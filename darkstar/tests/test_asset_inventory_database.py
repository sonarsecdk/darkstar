"""Inventory persistence and approval boundaries on disposable MariaDB."""
import json
import os
import socket
import uuid

import pytest

from darkstar.core import asset_inventory as inventory, db_helper as db, scan_scope


@pytest.fixture
def tenants(monkeypatch):
    host = os.environ.get("DARKSTAR_TEST_DB_HOST")
    password = os.environ.get("DARKSTAR_TEST_DB_PASSWORD")
    if not host or not password:
        pytest.skip("Set DARKSTAR_TEST_DB_HOST/PASSWORD for MariaDB integration tests")
    for key, value in {"DB_HOST": host, "DB_USER": "root", "DB_PASSWORD": password, "DB_NAME": "feature_tests"}.items():
        monkeypatch.setenv(key, value)
    names = []
    try:
        for _ in range(2):
            names.append(db.create_organization("inventory_test_" + uuid.uuid4().hex[:12])["org_db_name"])
        yield names
    finally:
        for org in names:
            for scan in db.get_scan_history(org):
                db.update_scan_status(org, scan["id"], "stopped")
            db.delete_organization(db.get_organization_id(org), active_org_db="feature_tests")


def approve(org, targets, scanners=None):
    return inventory.approve_inventory_targets(org, targets, "platform@example.test", db.get_organization_id(org), scanners)


def discover(org, rows, node_id="node-a"):
    scan_id = inventory.create_discovery_scan(org, "Discover", "192.0.2.1", {"ports": [80]}, "platform", db.get_organization_id(org))
    inventory.save_discovery_results(org, scan_id, node_id, rows)
    db.update_scan_status(org, scan_id, "completed")
    return scan_id


def audit(org, action):
    with db.DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        db._use_org_database(cursor, org)
        cursor.execute("SELECT actor, metadata FROM audit_log WHERE action = %s", (action,))
        rows = cursor.fetchall()
        cursor.close()
    return rows


def test_pending_discovery_does_not_grant_scope_and_is_tenant_isolated(tenants):
    org, other = tenants
    rows = [{"target": "example.test", "addresses": ["192.0.2.1"], "services": [
        {"port": 443, "protocol": "tcp", "service": "https", "url": "https://example.test"},
    ]}]
    scan_id = discover(org, rows + rows)
    assert inventory.list_asset_inventory(org) == []
    assert db.get_allowed_scan_targets(org) == []
    pending = inventory.list_asset_inventory(org, include_pending=True)
    assert [row["target"] for row in pending] == ["192.0.2.1", "example.test"]
    assert not any(row["approved"] for row in pending)
    assert pending[0]["compatible_scanners"] == []  # DNS alone does not identify services.
    assert pending[1]["compatible_scanners"] == ["openvas", "zap", "nuclei"]
    assert pending[1]["source_node_id"] == "node-a"
    assert inventory.list_asset_inventory(other, include_pending=True) == []
    with pytest.raises(ValueError, match="does not exist"):
        inventory.save_discovery_results(other, scan_id, "node-a", rows)
    with pytest.raises(scan_scope.ScanScopeError):
        db.create_scan_record(org, "Not approved", "zap", "example.test")
    assert inventory.save_discovery_results(org, scan_id, "node-a", rows) == 0
    assert inventory.list_asset_inventory(org, include_pending=True) == pending
    assert len(audit(org, "asset.discovery_saved")) == 1
    assert '"scan_mode": "discovery"' in audit(org, "asset.discovery_queued")[0]["metadata"]


def test_domain_approval_requires_explicit_addresses_and_is_atomic(tenants, monkeypatch):
    org = tenants[0]
    monkeypatch.setattr(scan_scope.socket, "getaddrinfo", lambda *a, **kw: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 0, 0, 0)),
    ])
    approve(org, ["198.51.100.1"])
    with pytest.raises(scan_scope.ScanScopeError, match="unapproved IP"):
        approve(org, ["example.test", "192.0.2.1"])
    assert [row["target"] for row in db.get_allowed_scan_targets(org)] == ["198.51.100.1"]
    approve(org, ["example.test", "192.0.2.1", "2001:db8::1", "example.test"], ["zap"])
    assert len(db.get_allowed_scan_targets(org)) == 4
    assert len(audit(org, "asset.approved")) == 2
    assert {row["target"] for row in inventory.get_asset_scanner_rules(org)} == {"example.test", "192.0.2.1", "2001:db8::1"}
    monkeypatch.setattr(scan_scope.socket, "getaddrinfo", lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.1", 0))])
    with pytest.raises(scan_scope.ScanScopeError, match="203.0.113.1"):
        approve(org, ["example.test"])
    assert "203.0.113.1" not in {row["target"] for row in db.get_allowed_scan_targets(org)}


def test_network_only_services_do_not_suggest_web_scanners(tenants):
    org = tenants[0]
    discover(org, [{"target": "192.0.2.1", "addresses": ["192.0.2.1"],
                    "services": [{"port": 22, "protocol": "tcp", "service": "ssh"}]}])
    asset = inventory.list_asset_inventory(org, include_pending=True)[0]
    assert asset["compatible_scanners"] == ["openvas"]


def test_approval_and_scanner_settings_require_idle_current_organization(tenants):
    org = tenants[0]
    approve(org, ["192.0.2.1"])
    scan_id = db.create_scan_record(org, "Existing", "nuclei", "192.0.2.1")
    with pytest.raises(db.OrganizationConflictError, match="Stop active"):
        approve(org, ["192.0.2.2"])
    with pytest.raises(db.OrganizationConflictError, match="Stop active"):
        inventory.update_asset_scanners(org, "192.0.2.1", [], "platform", db.get_organization_id(org))
    db.update_scan_status(org, scan_id, "stopped")
    for action in [
        lambda: inventory.approve_inventory_targets(org, ["192.0.2.2"], "platform", -1),
        lambda: inventory.update_asset_scanners(org, "192.0.2.1", [], "platform", -1),
        lambda: inventory.create_discovery_scan(org, "Stale", "192.0.2.1", {}, "platform", -1),
    ]:
        with pytest.raises(db.OrganizationConflictError, match="no longer available"):
            action()
    assert inventory.get_asset_scanner_rules(org) == []
    assert len(db.get_allowed_scan_targets(org)) == 1


def test_cidr_visibility_scanner_rules_and_removed_approval(tenants):
    org = tenants[0]
    approve(org, ["192.0.2.0/24"])
    discover(org, [{"target": "192.0.2.1"}, {"target": "198.51.100.1"}])
    assert {row["target"] for row in inventory.list_asset_inventory(org)} == {"192.0.2.0/24", "192.0.2.1"}
    assert all(row["enabled_scanners"] is None for row in inventory.list_asset_inventory(org))
    org_id = db.get_organization_id(org)
    inventory.update_asset_scanners(org, "192.0.2.0/24", ["zap", "openvas"], "platform", org_id)
    inventory.update_asset_scanners(org, "192.0.2.1", ["zap"], "platform", org_id)
    assert next(row for row in inventory.list_asset_inventory(org) if row["target"] == "192.0.2.1")["enabled_scanners"] == ["zap"]
    inventory.update_asset_scanners(org, "192.0.2.1", [], "platform", org_id)
    assert next(row for row in inventory.list_asset_inventory(org) if row["target"] == "192.0.2.1")["enabled_scanners"] == []
    inventory.update_asset_scanners(org, "192.0.2.1", None, "platform", org_id)
    assert inventory.get_asset_scanner_rules(org) == [{"target": "192.0.2.0/24", "enabled_scanners": ["openvas", "zap"]}]
    db.replace_allowed_scan_targets(org, [], actor="platform", expected_org_id=org_id)
    assert inventory.list_asset_inventory(org) == []
    assert inventory.get_asset_scanner_rules(org) == []
    assert not any(row["approved"] for row in inventory.list_asset_inventory(org, include_pending=True))
    with pytest.raises(scan_scope.ScanScopeError, match="Approve this target"):
        inventory.update_asset_scanners(org, "192.0.2.1", ["zap"], "platform", org_id)


def test_failed_attempt_preserves_services_and_old_delivery_cannot_overwrite_newer(tenants):
    org = tenants[0]
    success = {"target": "192.0.2.1", "addresses": ["192.0.2.1"], "services": [{"port": 80, "url": "http://192.0.2.1"}]}
    first = discover(org, [success])
    before = inventory.list_asset_inventory(org, include_pending=True)[0]
    second = discover(org, [{"target": "192.0.2.1", "error": "Connection timed out"}], node_id="node-b")
    after = inventory.list_asset_inventory(org, include_pending=True)[0]
    assert after["services"] == before["services"]
    assert after["addresses"] == before["addresses"]
    assert after["discovered_at"] == before["discovered_at"]
    assert after["source_node_id"] == before["source_node_id"] == "node-a"
    assert audit(org, "asset.discovery_saved")[-1]["actor"] == "node-b"
    assert after["error"] == "Connection timed out" and after["last_scan_id"] == second
    assert inventory.save_discovery_results(org, first, "node-a", [success]) == 0
    assert inventory.list_asset_inventory(org, include_pending=True)[0] == after
    # A successful retry with no open services is authoritative, unlike a failed attempt.
    discover(org, [{"target": "192.0.2.1"}])
    latest = inventory.list_asset_inventory(org, include_pending=True)[0]
    assert latest["services"] == [] and latest["error"] is None


def test_dns_candidates_do_not_erase_existing_ip_service_observations(tenants):
    org = tenants[0]
    discover(org, [{"target": "192.0.2.1", "services": [{"port": 22, "service": "ssh"}]}])
    before = inventory.list_asset_inventory(org, include_pending=True)[0]
    discover(org, [{"target": "example.test", "addresses": ["192.0.2.1"]}])
    assert inventory.list_asset_inventory(org, include_pending=True)[0] == before


def test_domain_scanner_choices_include_observed_address_restrictions(tenants, monkeypatch):
    org = tenants[0]
    monkeypatch.setattr(scan_scope.socket, "getaddrinfo", lambda *a, **kw: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
    ])
    discover(org, [{"target": "example.test", "addresses": ["192.0.2.1"]}])
    approve(org, ["example.test", "192.0.2.1"])
    inventory.update_asset_scanners(org, "example.test", ["openvas", "zap"], "platform", db.get_organization_id(org))
    inventory.update_asset_scanners(org, "192.0.2.1", ["openvas"], "platform", db.get_organization_id(org))
    rows = inventory.list_asset_inventory(org)
    assert next(row for row in rows if row["target"] == "example.test")["enabled_scanners"] == ["openvas"]
    inventory.update_asset_scanners(org, "192.0.2.1", [], "platform", db.get_organization_id(org))
    rows = inventory.list_asset_inventory(org)
    assert next(row for row in rows if row["target"] == "example.test")["enabled_scanners"] == []


def test_url_refresh_preserves_other_ports_and_paths(tenants):
    org = tenants[0]
    previous = [{"port": 80, "url": "http://192.0.2.1/api"},
                {"port": 80, "url": "http://192.0.2.1/login"},
                {"port": 8443, "url": "https://192.0.2.1:8443/"}]
    discover(org, [{"target": "192.0.2.1", "services": previous}])
    url = "http://192.0.2.1/login"
    plan = {"seeds": [{"target": url, "host": "192.0.2.1", "kind": "url", "url": url,
                       "addresses": ["192.0.2.1"]}], "authorized_targets": ["192.0.2.1"], "port_mode": "full"}
    scan_id = inventory.create_discovery_scan(org, "One application", url, plan, "platform", db.get_organization_id(org))
    rows = [{"target": "192.0.2.1", "services": [{"port": 80, "service": "http", "url": url}]}]
    inventory.save_discovery_results(org, scan_id, "node-a", rows, plan=plan)
    after = inventory.list_asset_inventory(org, include_pending=True)[0]
    assert {service["url"] for service in after["services"]} == {service["url"] for service in previous}
    assert next(service for service in after["services"] if service["url"] == url)["service"] == "http"
    assert inventory.save_discovery_results(org, scan_id, "node-a", rows, plan=plan) == 0
    with pytest.raises(ValueError, match="outside the submitted probe scope"):
        inventory.save_discovery_results(org, scan_id, "node-a", [{"target": "192.0.2.1", "services": [{"port": 22}]}], plan=plan)
    assert inventory.list_asset_inventory(org, include_pending=True)[0] == after


def test_common_port_refresh_preserves_unprobed_services_until_full_refresh(tenants):
    org = tenants[0]
    discover(org, [{"target": "192.0.2.1", "services": [
        {"port": 22, "service": "ssh"}, {"port": 12345, "url": "http://192.0.2.1:12345/"},
    ]}])
    plan = {"seeds": [{"target": "192.0.2.1", "host": "192.0.2.1", "kind": "ip", "url": None,
                       "addresses": ["192.0.2.1"]}], "authorized_targets": ["192.0.2.1"], "port_mode": "common"}
    for mode, expected_ports in [("common", [12345]), ("full", [])]:
        plan["port_mode"] = mode
        scan_id = inventory.create_discovery_scan(org, mode, "192.0.2.1", plan, "platform", db.get_organization_id(org))
        inventory.save_discovery_results(org, scan_id, "node-a", [{"target": "192.0.2.1", "services": []}], plan=plan)
        actual = inventory.list_asset_inventory(org, include_pending=True)[0]
        assert [service["port"] for service in actual["services"]] == expected_ports


def test_failed_attempt_cannot_store_services_outside_its_probe_plan(tenants):
    org = tenants[0]
    plan = {"seeds": [{"target": "192.0.2.1", "host": "192.0.2.1", "kind": "ip", "url": None,
                       "addresses": ["192.0.2.1"]}], "authorized_targets": ["192.0.2.1"], "port_mode": "common"}
    scan_id = inventory.create_discovery_scan(org, "Common ports", "192.0.2.1", plan, "platform", db.get_organization_id(org))
    with pytest.raises(ValueError, match="outside the submitted probe scope"):
        inventory.save_discovery_results(org, scan_id, "node-a", [{
            "target": "192.0.2.1", "services": [{"port": 12345}], "error": "Incomplete result",
        }], plan=plan)
    assert inventory.list_asset_inventory(org, include_pending=True) == []


def test_large_discovery_and_approval_audits_fit_existing_text_column(tenants, monkeypatch):
    org = tenants[0]
    urls = ["http://192.0.2.1/" + str(index) + "a" * 250 for index in range(200)]
    plan = {"seeds": [{"target": url, "host": "192.0.2.1", "kind": "url", "url": url,
                       "addresses": ["192.0.2.1"]} for url in urls],
            "authorized_targets": ["192.0.2.1"], "port_mode": "full"}
    assert len(json.dumps(plan)) > 65535
    scan_id = inventory.create_discovery_scan(org, "Many applications", ",".join(urls), plan,
                                             "platform", db.get_organization_id(org))
    metadata = json.loads(audit(org, "asset.discovery_queued")[0]["metadata"])
    assert metadata["target_count"] == 200 and len(metadata["plan_sha256"]) == 64
    assert "plan" not in metadata
    db.update_scan_status(org, scan_id, "completed")
    monkeypatch.setattr(scan_scope.socket, "getaddrinfo", lambda *a, **kw: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
    ])
    approve(org, ["192.0.2.1"])
    domains = [f"{index:03d}" + "a" * 60 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 61 for index in range(300)]
    approve(org, domains)
    entries = audit(org, "asset.approved")
    assert all(len(row["metadata"].encode()) < 65535 for row in entries)
    assert {target for row in entries for target in json.loads(row["metadata"])["targets"]} == set(domains + ["192.0.2.1"])


def test_automatic_worker_result_roundtrip_keeps_discovery_context_and_does_not_approve(tenants, monkeypatch):
    """Use the real leased-job shape; a partial lease record cannot authorize results."""
    from fastapi.testclient import TestClient
    from darkstar import webapp

    org = tenants[0]
    plan = {"seeds": [{"target": "192.0.2.1", "host": "192.0.2.1", "kind": "ip",
                       "url": None, "addresses": ["192.0.2.1"]}],
            "authorized_targets": ["192.0.2.1"], "port_mode": "common"}
    scan_id = inventory.create_discovery_scan(org, "Discovery roundtrip", "192.0.2.1", plan,
                                             "platform", db.get_organization_id(org))
    node = db.create_scanner_node("inventory_test_" + uuid.uuid4().hex[:12], capabilities=["discovery"])
    web_node = db.create_scanner_node("inventory_test_" + uuid.uuid4().hex[:12], capabilities=["zap"])
    job_id = None
    try:
        payload = {"job_type": "discovery", "discovery": plan, "authorized_by": "platform"}
        job_id = db.enqueue_scanner_job(org, scan_id, "Discovery roundtrip", "discovery", "192.0.2.1",
                                       payload, scanner="discovery")
        assert db.get_scanner_job_for_scan(org, scan_id)["preferred_node_id"] is None
        assert db.claim_next_scanner_job(web_node["node_id"], capabilities=["zap"]) is None
        job = db.claim_next_scanner_job(node["node_id"], capabilities=["discovery"])
        assert job["id"] == job_id
        leased = db.extend_scanner_job_lease(job_id, node["node_id"])
        assert leased["scanner"] == "discovery" and leased["scan_mode"] == "discovery"
        assert leased["payload"] == payload
        assert db.extend_scanner_job_lease(job_id, "wrong-node") is None
        monkeypatch.setattr(webapp, "scheduler_started", True)
        monkeypatch.setattr(webapp, "list_organizations", list)
        with TestClient(webapp.app) as client:
            response = client.post(f"/api/scanner-workers/jobs/{job_id}/discovery-results",
                                   headers={"Authorization": "Bearer " + node["token"]},
                                   json={"items": [{"target": "192.0.2.1", "addresses": ["192.0.2.1"],
                                                    "services": [{"port": 443, "protocol": "tcp", "service": "https",
                                                                  "url": "https://192.0.2.1"}]}]})
        assert response.status_code == 200, response.text
        assert response.json()["saved"] == 1
        assert db.get_allowed_scan_targets(org) == []
        assert inventory.list_asset_inventory(org) == []
        pending = inventory.list_asset_inventory(org, include_pending=True)
        assert pending[0]["target"] == "192.0.2.1" and pending[0]["approved"] is False
        assert pending[0]["source_node_id"] == node["node_id"]
    finally:
        if job_id is not None:
            db.complete_scanner_job(job_id, node["node_id"], "stopped")
        db.revoke_scanner_node(node["node_id"])
        db.delete_revoked_scanner_node(node["node_id"])
        db.revoke_scanner_node(web_node["node_id"])
        db.delete_revoked_scanner_node(web_node["node_id"])
