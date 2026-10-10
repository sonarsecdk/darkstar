"""Opt-in local deployment tests. See docs/testing.md for environment variables."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
import uuid

from dotenv import dotenv_values
import mysql.connector
import pytest
import requests

from darkstar.core import db_helper as db


pytestmark = pytest.mark.integration
REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture()
def deployment(monkeypatch):
    if os.environ.get("RUN_DARKSTAR_INTEGRATION") != "1":
        pytest.skip("Set RUN_DARKSTAR_INTEGRATION=1 for local Docker integration tests")
    email = os.environ["DARKSTAR_TEST_EMAIL"]
    password = os.environ["DARKSTAR_TEST_PASSWORD"]
    base = os.environ.get("DARKSTAR_TEST_URL", "http://127.0.0.1:8080").rstrip("/")
    config = {**dotenv_values(REPO_ROOT / ".env"), **os.environ}
    registry = config["DB_NAME"]
    monkeypatch.setenv("DB_NAME", registry)
    organizations, users = [], []

    @contextmanager
    def database():
        connection = mysql.connector.connect(
            host=config.get("DARKSTAR_TEST_DB_HOST", "127.0.0.1"),
            port=int(config.get("DARKSTAR_TEST_DB_PORT", "3307")),
            user=config["DB_USER"], password=config["DB_PASSWORD"], database=registry,
        )
        try:
            yield connection
        finally:
            connection.close()

    def login(account):
        client = requests.Session()
        response = client.post(base + "/api/auth/login", json=account, timeout=30)
        assert response.status_code == 200, response.text
        assert not response.json().get("organization_required"), response.text
        return client

    admin = login({"email": email, "password": password})
    assert admin.get(base + "/api/me", timeout=30).json()["role"] == "platform_admin"

    def create(name):
        org_db = db.normalize_org_name(name)
        organizations.append(org_db)
        response = admin.post(base + "/api/admin/organizations", json={"name": name}, timeout=30)
        assert response.status_code == 201, response.text
        return response.json()["organization"]

    def user(org, role="tenant_admin"):
        account = {"email": f"{uuid.uuid4().hex}@example.test", "password": "Test!" + secrets.token_urlsafe(18) + "1aA"}
        response = admin.post(base + "/api/admin/users", json={**account, "org_db": org["org_db_name"], "role": role}, timeout=30)
        assert response.status_code == 200, response.text
        users.append(response.json()["user"]["id"])
        return account, login(account)

    try:
        yield {
            "base": base, "admin": admin, "account": {"email": email, "password": password},
            "database": database, "create": create, "user": user, "organizations": organizations,
        }
    finally:
        # Only this test's generated accounts/databases are removed.
        with database() as connection:
            cursor = connection.cursor()
            for user_id in users:
                cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
            for org_db in set(organizations):
                cursor.execute("DELETE FROM organizations WHERE org_db_name = %s", (org_db,))
            connection.commit()
            for org_db in set(organizations):
                cursor.execute(f"DROP DATABASE IF EXISTS `{org_db}`")
            cursor.close()
        admin.close()


def test_real_browser_creation_tenant_isolation_and_restart(deployment):
    from playwright.sync_api import expect, sync_playwright

    base, admin = deployment["base"], deployment["admin"]
    suffix = uuid.uuid4().hex[:10]
    organizations = [
        {"org_name": f"Integration {suffix} {label}", "org_db_name": f"org_integration_{suffix}_{label.lower()}"}
        for label in ("Alpha", "Beta")
    ]
    assert requests.post(base + "/api/admin/organizations", json={"name": "Unauthorized"}, timeout=30).status_code == 401

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            page.goto(base)
            page.locator("#emailInput").fill(deployment["account"]["email"])
            page.locator("#passwordInput").fill(deployment["account"]["password"])
            page.get_by_role("button", name="Sign In", exact=True).click()
            page.get_by_role("button", name="Oversight", exact=True).click()
            for organization in organizations:
                deployment["organizations"].append(organization["org_db_name"])
                page.get_by_role("button", name="New organization", exact=True).click()
                page.locator("#organizationNameInput").fill(organization["org_name"])
                page.get_by_role("button", name="Create organization", exact=True).click()
                expect(page.locator("#createOrganizationMessage")).to_contain_text("created", timeout=30000)
                expect(page.locator("#oversightRows")).to_contain_text(organization["org_name"])
                expect(page.locator(f'#tenantSwitchSelect option[value="{organization["org_db_name"]}"]')).to_have_text(organization["org_name"])
            output = REPO_ROOT / "test-results/playwright"
            output.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(output / "real-organizations.png"), full_page=True)
        finally:
            browser.close()

    for name in ("", "   ", "!!!"):
        assert admin.post(base + "/api/admin/organizations", json={"name": name}, timeout=30).status_code in (400, 422)
    for name in (organizations[0]["org_name"], organizations[0]["org_name"].upper().replace(" ", "-")):
        assert admin.post(base + "/api/admin/organizations", json={"name": name}, timeout=30).status_code == 409

    expected_tables = {re.search(r"CREATE TABLE IF NOT EXISTS (\w+)", sql).group(1) for sql in db.ORG_SCHEMA_STATEMENTS}
    with deployment["database"]() as connection:
        cursor = connection.cursor()
        for index, organization in enumerate(organizations, start=1):
            org_db = organization["org_db_name"]
            cursor.execute("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = %s", (org_db,))
            assert expected_tables <= {row[0] for row in cursor.fetchall()}
            # Synthetic findings are inserted directly; no scanner is started.
            cursor.execute(
                f"INSERT INTO `{org_db}`.vulnerability (id, title, host, tool, severity) VALUES (%s, %s, %s, %s, %s)",
                (900 + index, f"Tenant {index} synthetic finding", f"tenant{index}.invalid", "integration-test", "info"),
            )
        connection.commit()
        cursor.close()

    accounts, tenants = zip(*(deployment["user"](org) for org in organizations))
    for index, tenant in enumerate(tenants):
        own, other = organizations[index], organizations[1 - index]
        me = tenant.get(base + "/api/me", timeout=30).json()
        assert [org["org_db_name"] for org in me["organizations"]] == [own["org_db_name"]]
        findings = tenant.get(base + "/api/vulnerabilities", params={"org_db": other["org_db_name"]}, timeout=30).json()["items"]
        assert [item["title"] for item in findings] == [f"Tenant {index + 1} synthetic finding"]
        assert tenant.get(base + f"/api/vulnerabilities/{902 - index}", timeout=30).status_code == 404
        assert tenant.post(base + "/api/auth/select-organization", json={"org_db": other["org_db_name"]}, timeout=30).status_code == 403
        assert tenant.get(base + "/api/admin/organizations", timeout=30).status_code == 403
        assert tenant.post(base + "/api/admin/organizations", json={"name": "Forbidden"}, timeout=30).status_code == 403
        assert tenant.post(base + "/api/users", json={"email": accounts[1 - index]["email"], "password": "ForbiddenReset1!"}, timeout=30).status_code == 403
        assert requests.post(base + "/api/auth/login", json=accounts[1 - index], timeout=30).status_code == 200

    for role in ("security_analyst", "viewer"):
        _account, client = deployment["user"](organizations[0], role)
        assert client.post(base + "/api/admin/organizations", json={"name": "Forbidden"}, timeout=30).status_code == 403
        client.close()

    for index, organization in enumerate(organizations, start=1):
        response = admin.post(base + "/api/auth/select-organization", json={"org_db": organization["org_db_name"]}, timeout=30)
        assert response.status_code == 200, response.text
        assert response.json()["role"] == "platform_admin"
        assert admin.get(base + "/api/vulnerabilities", timeout=30).json()["items"][0]["title"] == f"Tenant {index} synthetic finding"

    subprocess.run(["docker", "compose", "restart", "mariadb", "darkstar-web", "darkstar-scanner"], cwd=REPO_ROOT, check=True, timeout=60)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            response = admin.get(base + "/api/admin/organizations", timeout=3)
            if response.status_code == 200:
                break
        except requests.RequestException:
            pass
        time.sleep(1)
    else:
        pytest.fail("Darkstar did not become ready after restart")
    assert {org["org_db_name"] for org in organizations} <= {org["org_db_name"] for org in response.json()["items"]}
    assert {org["org_db_name"] for org in organizations} <= {org["org_db_name"] for org in admin.get(base + "/api/me", timeout=30).json()["organizations"]}
    for index, tenant in enumerate(tenants, start=1):
        assert tenant.get(base + "/api/vulnerabilities", timeout=30).json()["items"][0]["title"] == f"Tenant {index} synthetic finding"
        tenant.close()


def test_concurrent_creation_has_one_winner(deployment):
    name = "Concurrent " + uuid.uuid4().hex[:10]
    deployment["organizations"].append(db.normalize_org_name(name))
    cookies = deployment["admin"].cookies.get_dict()

    def create():
        return requests.post(deployment["base"] + "/api/admin/organizations", cookies=cookies, json={"name": name}, timeout=30)

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _: create(), range(2)))
    assert sorted(response.status_code for response in responses) == [201, 409]


def test_failed_schema_is_removed_and_creation_can_be_retried(deployment, monkeypatch):
    name = "Provisioning failure " + uuid.uuid4().hex[:10]
    org_db = db.normalize_org_name(name)
    deployment["organizations"].append(org_db)
    monkeypatch.setattr(db, "DatabaseConnectionManager", deployment["database"])
    apply_schema = db._apply_org_schema

    def fail_after_first_table(cursor):
        cursor.execute(db.ORG_SCHEMA_STATEMENTS[0])
        raise mysql.connector.Error("Deliberate local schema failure")

    monkeypatch.setattr(db, "_apply_org_schema", fail_after_first_table)
    with pytest.raises(mysql.connector.Error, match="Deliberate local schema failure"):
        db.create_organization(name)

    with deployment["database"]() as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM organizations WHERE org_db_name = %s", (org_db,))
        assert cursor.fetchone()[0] == 0
        cursor.execute("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = %s", (org_db,))
        assert cursor.fetchone()[0] == 0
        cursor.close()
    monkeypatch.setattr(db, "_apply_org_schema", apply_schema)
    assert db.create_organization(name)["org_db_name"] == org_db
