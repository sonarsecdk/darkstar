"""Risk acceptance against MariaDB: opt in with DARKSTAR_TEST_DB_HOST/PASSWORD.

Use a disposable server. The fixture creates uniquely named organizations and
removes only those organizations when finished.
"""
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from darkstar.core import db_helper as db


@pytest.fixture()
def tenants(monkeypatch):
    host = os.environ.get("DARKSTAR_TEST_DB_HOST")
    password = os.environ.get("DARKSTAR_TEST_DB_PASSWORD")
    if not host or not password:
        pytest.skip("Set DARKSTAR_TEST_DB_HOST/PASSWORD to run MariaDB risk acceptance tests")
    for key, value in {"DB_HOST": host, "DB_USER": "root", "DB_PASSWORD": password, "DB_NAME": "feature_tests"}.items():
        monkeypatch.setenv(key, value)
    names = []
    try:
        for _ in range(2):
            org = db.create_organization("risk_test_" + uuid.uuid4().hex[:12])
            names.append(org["org_db_name"])
        yield names
    finally:
        for name in names:
            db.delete_organization(db.get_organization_id(name), active_org_db="feature_tests")


def execute(org, sql, params=(), fetch=False):
    with db.DatabaseConnectionManager() as conn:
        cursor = conn.cursor(dictionary=True)
        db._use_org_database(cursor, org)
        cursor.execute(sql, params)
        result = cursor.fetchall() if fetch else cursor.lastrowid
        conn.commit()
        cursor.close()
        return result


def network_finding(org, host="app.example.test", item="https://app.example.test/Admin", title="Test finding", cve="CVE-2026-1234"):
    return execute(org, """INSERT INTO vulnerability
        (host, affected_item, tool, title, cve, severity, priority_score)
        VALUES (%s, %s, 'TestScanner', %s, %s, 'high', 80)""", (host, item, title, cve))


def test_rescans_counts_exports_revocation_and_tenant_isolation(tenants):
    first, second = tenants
    finding_id = network_finding(first)
    network_finding(second)
    db.set_risk_acceptance(first, "network", finding_id, actor="analyst@example.test", reason="Compensating control <checked>")
    rescan_id = network_finding(first)
    assert db.get_vulnerability_detail(first, rescan_id)["risk_accepted"] == 1
    assert db.get_vulnerabilities_filtered(first)[1] == 0
    assert db.get_latest_vulnerabilities(first) == []
    assert db.get_grouped_vulnerabilities(first) == []
    assert db.get_vulnerability_stats(first)["total_vulnerabilities"] == 0
    assert db.get_scoring_overview(first)["summary"]["total"] == 0
    assert db.get_vulnerability_export_rows(first) == []
    assert db.get_vulnerability_stats(second)["total_vulnerabilities"] == 1
    items, total = db.get_vulnerabilities_filtered(first, include_accepted=True, dedupe=True)
    assert total == 1 and items[0]["duplicate_count"] == 2
    assert items[0]["risk_reason"] == "Compensating control <checked>"
    assert len(db.get_vulnerability_export_rows(first, include_accepted=True)) == 2
    assert db.get_scoring_overview(first, include_accepted=True)["summary"]["total"] == 2
    assert db.get_attack_surface_overview(first)["items"][0]["vulnerability_count"] == 0
    assert db.get_attack_surface_overview(first, include_accepted=True)["items"][0]["vulnerability_count"] == 2
    db.set_risk_acceptance(first, "network", rescan_id, actor="admin@example.test", revoke=True)
    assert db.get_vulnerability_stats(first)["total_vulnerabilities"] == 2
    audit = execute(first, "SELECT action FROM audit_log WHERE action LIKE 'risk.%' ORDER BY id", fetch=True)
    assert [row["action"] for row in audit] == ["risk.accepted", "risk.revoked"]


def test_acceptance_does_not_cross_assets_paths_or_finding_definitions(tenants):
    org = tenants[0]
    finding_id = network_finding(org)
    db.set_risk_acceptance(org, "network", finding_id, actor="analyst", reason="Mitigated")
    for changes in [dict(host="other.example.test"), dict(item="https://app.example.test/admin"),
                    dict(item="https://app.example.test:8443/Admin"), dict(title="Other finding"), dict(cve="CVE-2026-5678")]:
        new_id = network_finding(org, **changes)
        assert db.get_vulnerability_detail(org, new_id)["risk_accepted"] == 0
    assert db.get_vulnerabilities_filtered(org, dedupe=True)[1] == 5


def test_expiry_is_applied_without_a_background_job(tenants):
    org = tenants[0]
    finding_id = network_finding(org)
    db.set_risk_acceptance(org, "network", finding_id, actor="analyst", reason="Temporary",
                           expires_at=datetime.now(timezone.utc) + timedelta(days=1))
    assert db.get_vulnerability_stats(org)["total_vulnerabilities"] == 0
    execute(org, "UPDATE risk_acceptances SET expires_at = UTC_TIMESTAMP() - INTERVAL 1 SECOND")
    assert db.get_vulnerability_stats(org)["total_vulnerabilities"] == 1
    assert db.get_vulnerability_detail(org, finding_id)["risk_accepted"] == 0


def test_endpoint_acceptance_survives_inventory_refresh(tenants):
    org = tenants[0]
    finding = {"software_key": "test-package", "cve": "CVE-2026-1234", "source": "test", "severity": "high"}
    db.replace_endpoint_vulnerabilities(org, "agent-a", [finding])
    finding_id = db.list_endpoint_vulnerabilities(org)["items"][0]["id"]
    db.set_risk_acceptance(org, "endpoint", finding_id, actor="analyst", reason="Mitigated")
    db.replace_endpoint_vulnerabilities(org, "agent-a", [])
    db.replace_endpoint_vulnerabilities(org, "agent-a", [finding])
    db.replace_endpoint_vulnerabilities(org, "agent-b", [finding])
    items = db.list_endpoint_vulnerabilities(org)["items"]
    assert len(items) == 1 and items[0]["agent_id"] == "agent-b"
    assert db.get_endpoint_overview(org)["vulnerabilities"] == 1
    assert db.get_endpoint_overview(org, include_accepted=True)["vulnerabilities"] == 2
    assert db.get_endpoint_vulnerability(org, finding_id)["risk_accepted"] == 1
    assert len(db.list_endpoint_vulnerabilities(org, include_accepted=True)["items"]) == 2
    db.set_risk_acceptance(org, "endpoint", finding_id, actor="analyst", revoke=True)
    assert db.list_endpoint_vulnerabilities(org)["total"] == 2


@pytest.mark.parametrize("reason,expiry", [
    (" ", None), ("x" * 4001, None), ("test", datetime(2000, 1, 1)),
    ("test", datetime(2000, 1, 1, tzinfo=timezone.utc)),
])
def test_invalid_acceptance_is_rejected_before_writing(reason, expiry, mocker):
    connection = mocker.patch.object(db, "DatabaseConnectionManager")
    with pytest.raises(ValueError):
        db.set_risk_acceptance("tenant", "network", 1, actor="analyst", reason=reason, expires_at=expiry)
    connection.assert_not_called()


def test_missing_finding_or_stale_organization_cannot_create_acceptance(tenants):
    org = tenants[0]
    assert not db.set_risk_acceptance(org, "network", 9999, actor="analyst", reason="test")
    finding_id = network_finding(org)
    with pytest.raises(db.OrganizationConflictError):
        db.set_risk_acceptance(org, "network", finding_id, actor="analyst", reason="test", expected_org_id=-1)
    assert execute(org, "SELECT * FROM risk_acceptances", fetch=True) == []
