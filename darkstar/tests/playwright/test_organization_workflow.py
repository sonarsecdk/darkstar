from pathlib import Path

import pytest

from darkstar.tests.playwright.test_dashboard_workflows import _install_dashboard_mocks, _json


pytestmark = pytest.mark.playwright


@pytest.fixture()
def organization_page(darkstar_server):
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        _install_dashboard_mocks(page, darkstar_server)
        state = {
            "role": "platform_admin",
            "org_db": "tenant_db",
            "organizations": [{"org_name": "Acme Security", "org_db_name": "tenant_db"}],
            "requests": [],
            "error": None,
            "hold": False,
        }

        def me(route):
            organization = next(org for org in state["organizations"] if org["org_db_name"] == state["org_db"])
            _json(route, {
                "authenticated": True, "role": state["role"], "organization": organization["org_name"],
                "org_db": state["org_db"], "organizations": state["organizations"],
            })

        def overview(route):
            _json(route, {
                "totals": {"organizations": len(state["organizations"])},
                "tenants": [{"organization": org["org_name"], "org_db": org["org_db_name"]} for org in state["organizations"]],
            })

        def finish_creation(route):
            if state["error"]:
                status, detail = state["error"]
                _json(route, {"detail": detail}, status=status)
                return
            organization = {"org_name": route.request.post_data_json["name"], "org_db_name": "org_new_tenant"}
            state["organizations"].append(organization)
            _json(route, {"ok": True, "organization": organization}, status=201)

        def create(route):
            state["requests"].append(route.request.post_data_json)
            if state["hold"]:
                state["pending_route"] = route
            else:
                finish_creation(route)

        def switch(route):
            state["org_db"] = route.request.post_data_json["org_db"]
            organization = next(org for org in state["organizations"] if org["org_db_name"] == state["org_db"])
            _json(route, {"ok": True, "organization": organization["org_name"], "org_db": state["org_db"], "role": state["role"]})

        page.route(f"{darkstar_server}/api/me", me)
        page.route(f"{darkstar_server}/api/admin/overview", overview)
        page.route(f"{darkstar_server}/api/admin/organizations", create)
        page.route(f"{darkstar_server}/api/auth/select-organization", switch)
        try:
            yield page, state, finish_creation, darkstar_server
        finally:
            browser.close()


def open_oversight(page, base_url):
    from playwright.sync_api import expect

    page.goto(base_url, wait_until="networkidle")
    page.get_by_role("button", name="Oversight", exact=True).click()
    expect(page.locator("#oversightRows")).to_contain_text("Acme Security")
    page.get_by_role("button", name="New organization", exact=True).click()


def test_creation_refreshes_list_and_selector_without_logging_in_again(organization_page):
    from playwright.sync_api import expect

    page, state, finish_creation, base_url = organization_page
    open_oversight(page, base_url)
    page.locator("#organizationNameInput").fill("   ")
    page.get_by_role("button", name="Create organization", exact=True).click()
    expect(page.locator("#createOrganizationMessage")).to_have_text("Organization name is required.")
    assert state["requests"] == []

    page.locator("#organizationNameInput").fill("  New Tenant  ")
    state["hold"] = True
    page.get_by_role("button", name="Create organization", exact=True).click()
    expect(page.locator("#createOrganizationBtn")).to_be_disabled()
    expect(page.locator("#cancelOrganizationBtn")).to_be_disabled()
    page.locator("#createOrganizationForm").dispatch_event("submit")
    assert state["requests"] == [{"name": "New Tenant"}]
    finish_creation(state["pending_route"])

    expect(page.locator("#createOrganizationMessage")).to_contain_text("New Tenant” created")
    expect(page.locator("#oversightRows")).to_contain_text("New Tenant")
    expect(page.locator("#tenantTotal")).to_have_text("2")
    expect(page.locator("#tenantSwitchSelect option")).to_have_text(["Acme Security", "New Tenant"])
    expect(page.locator("#tenantSwitchSelect")).to_have_value("tenant_db")
    expect(page.locator("#createOrganizationForm")).to_be_hidden()
    output_dir = Path("test-results/playwright")
    output_dir.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(output_dir / "organization-created.png"), full_page=True)
    page.locator("#tenantSwitchSelect").select_option("org_new_tenant")
    expect(page.locator("#tenantSwitchSelect")).to_have_value("org_new_tenant")
    expect(page.locator("#dashboard-tab")).to_have_class("tab-panel active")
    assert state["org_db"] == "org_new_tenant"


@pytest.mark.parametrize("error", [(409, "Organization already exists"), (503, "Organization provisioning failed")])
def test_server_error_keeps_form_available_for_correction(organization_page, error):
    from playwright.sync_api import expect

    page, state, _finish, base_url = organization_page
    open_oversight(page, base_url)
    state["error"] = error
    page.locator("#organizationNameInput").fill("Acme")
    page.get_by_role("button", name="Create organization", exact=True).click()
    expect(page.locator("#createOrganizationMessage")).to_have_text(error[1])
    expect(page.locator("#createOrganizationForm")).to_be_visible()
    expect(page.locator("#organizationNameInput")).to_have_value("Acme")
    expect(page.locator("#createOrganizationBtn")).to_be_enabled()
    expect(page.locator("#tenantSwitchSelect option")).to_have_count(1)
    state["error"] = None
    page.locator("#organizationNameInput").fill("Corrected Tenant")
    page.get_by_role("button", name="Create organization", exact=True).click()
    expect(page.locator("#oversightRows")).to_contain_text("Corrected Tenant")


@pytest.mark.parametrize("role", ["tenant_admin", "security_analyst", "viewer"])
def test_non_platform_roles_cannot_open_or_submit_creation_form(organization_page, role):
    from playwright.sync_api import expect

    page, state, _finish, base_url = organization_page
    state["role"] = role
    page.goto(base_url, wait_until="networkidle")
    expect(page.locator("#newOrganizationBtn")).to_be_hidden()
    expect(page.locator('[data-tab="oversight"]')).to_be_hidden()
    page.locator("#organizationNameInput").evaluate("element => element.value = 'Forbidden Tenant'")
    page.locator("#createOrganizationForm").dispatch_event("submit")
    assert state["requests"] == []
