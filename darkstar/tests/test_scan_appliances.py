"""Multi-appliance API validation before the atomic database write."""
from datetime import datetime
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from darkstar import webapp
from darkstar.core.scan_scope import ScanScopeError


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setattr(webapp, "scheduler_started", True)
    monkeypatch.setattr(webapp, "list_organizations", list)
    monkeypatch.setattr(webapp, "authenticate_api_key", lambda token: {
        "org_id": 7, "org_db_name": "tenant_db", "org_name": "Test", "role": token,
    })
    monkeypatch.setattr(webapp, "get_allowed_scan_targets", lambda org: [{"target": "192.0.2.1"}])
    monkeypatch.setattr(webapp, "get_asset_scanner_rules", lambda org: [])
    monkeypatch.setattr(webapp, "list_asset_inventory", lambda org: [])
    monkeypatch.setattr(webapp, "get_scan_history", lambda *a, **k: [])
    monkeypatch.setattr(webapp, "get_scanner_node_record", lambda node: {
        "node_id": node, "name": node, "capabilities": ["*"], "status": "online", "last_seen_at": datetime.utcnow(),
    })
    monkeypatch.setattr(webapp, "get_scanner_profiles", lambda node: {"items": [
        {"scanner": "openvas", "id": "network", "name": "Network scan"},
        {"scanner": "zap", "id": "default", "name": "Recon"},
    ]})
    with TestClient(webapp.app) as client:
        client.headers["Authorization"] = "Bearer platform_admin"
        yield client


@pytest.fixture
def payload():
    return {"targets": "192.0.2.1", "scan_name": "Review", "appliances": [
        {"node_id": "node-a", "selections": [{"scanner": "openvas", "profile_id": "network"}]},
        {"node_id": "node-b", "selections": [{"scanner": "zap", "profile_id": "default"}]},
    ]}


def test_start_routes_each_appliance_and_returns_all_runs(api, payload, monkeypatch):
    monkeypatch.setattr(webapp, "_scan_target_routes", lambda org, body: {
        "openvas": "192.0.2.1", "zap": "http://192.0.2.1:3000/",
    })
    rows = [{"scan_id": 41, "node_id": "node-a"}, {"scan_id": 42, "node_id": "node-b"}]
    create = Mock(return_value=rows)
    monkeypatch.setattr(webapp, "create_scan_batch", create)
    response = api.post("/api/scans/start", json=payload)
    assert response.status_code == 200, response.text
    assert response.json() == {"ok": True, "status": "queued", "scans": rows, "scan_ids": [41, 42]}
    org, plans = create.call_args.args
    assert org == "tenant_db"
    assert create.call_args.kwargs == {"expected_org_id": 7}
    assert [plan["node_id"] for plan in plans] == ["node-a", "node-b"]
    assert [plan["payload"]["selections"][0]["targets"] for plan in plans] == ["192.0.2.1", "http://192.0.2.1:3000/"]
    assert [plan["scan_name"] for plan in plans] == ["node-a: Review", "node-b: Review"]
    assert all("appliances" not in plan["payload"] for plan in plans)


@pytest.mark.parametrize("failure", ["offline", "unsupported", "missing-profile", "duplicate-node", "mixed-options", "empty-selection"])
def test_invalid_second_appliance_prevents_every_scan(api, payload, monkeypatch, failure):
    create = Mock()
    monkeypatch.setattr(webapp, "create_scan_batch", create)
    if failure in {"offline", "unsupported"}:
        get_node = webapp.get_scanner_node_record
        def node(node_id):
            result = get_node(node_id)
            if node_id == "node-b":
                result.update({"last_seen_at": None} if failure == "offline" else {"capabilities": ["openvas"]})
            return result
        monkeypatch.setattr(webapp, "get_scanner_node_record", node)
    elif failure == "missing-profile":
        payload["appliances"][1]["selections"][0]["profile_id"] = "removed"
    elif failure == "duplicate-node":
        payload["appliances"][1]["node_id"] = "node-a"
    elif failure == "mixed-options":
        payload["mode"] = 2
    else:
        payload["appliances"][1]["selections"] = []
    assert api.post("/api/scans/start", json=payload).status_code in {400, 422}
    create.assert_not_called()


def test_same_scanner_can_run_on_two_appliances(api, payload, monkeypatch):
    payload["appliances"][1]["selections"] = payload["appliances"][0]["selections"]
    create = Mock(return_value=[{"scan_id": 1}, {"scan_id": 2}])
    monkeypatch.setattr(webapp, "create_scan_batch", create)
    assert api.post("/api/scans/start", json=payload).status_code == 200
    assert len(create.call_args.args[1]) == 2


@pytest.mark.parametrize("selection", [{"mode": 2}, {"scanner": "openvas"}])
def test_legacy_requests_cannot_pin_unsupported_work_to_zap_appliance(api, monkeypatch, selection):
    monkeypatch.setattr(webapp, "get_scanner_node_record", lambda node: {"capabilities": ["zap"]})
    create = Mock()
    monkeypatch.setattr(webapp, "create_scan_record", create)
    response = api.post("/api/scans/start", json={"targets": "192.0.2.1", "preferred_node_id": "node-b", **selection})
    assert response.status_code == 400
    assert "does not support" in response.json()["detail"]
    create.assert_not_called()


@pytest.mark.parametrize("role,allowed", [("viewer", False), ("security_analyst", False), ("tenant_admin", True), ("platform_admin", True)])
@pytest.mark.parametrize("path", ["/api/scans/start", "/api/schedules"])
def test_appliance_batches_keep_existing_admin_permissions(api, payload, monkeypatch, role, allowed, path):
    monkeypatch.setattr(webapp, "create_scan_batch", Mock(return_value=[{"scan_id": 1}]))
    monkeypatch.setattr(webapp, "create_scan_schedule_batch", Mock(return_value=[{"schedule_id": 1}]))
    response = api.post(path, json=payload, headers={"Authorization": "Bearer " + role})
    assert response.status_code == (200 if allowed else 403), response.text


def test_schedule_saves_all_appliances_with_shared_timing(api, payload, monkeypatch):
    payload.update(interval_minutes=60, start_at="2026-12-01T12:00:00", end_at="2026-12-03T12:00:00")
    rows = [{"schedule_id": 11}, {"schedule_id": 12}]
    create = Mock(return_value=rows)
    monkeypatch.setattr(webapp, "create_scan_schedule_batch", create)
    monkeypatch.setattr(webapp, "_active_scan_conflict", Mock(side_effect=AssertionError("Future schedule must not conflict with an active run")))
    response = api.post("/api/schedules", json=payload)
    assert response.status_code == 200, response.text
    assert response.json()["schedule_ids"] == [11, 12]
    org, plans, settings = create.call_args.args
    assert len(plans) == 2 and org == "tenant_db"
    assert settings["interval_minutes"] == 60
    assert settings["start_at"] == payload["start_at"]
    assert create.call_args.kwargs["expected_org_id"] == 7


@pytest.mark.parametrize("error,status", [(webapp.OrganizationConflictError("changed"), 409), (ScanScopeError("unapproved"), 403), (ValueError("unavailable"), 400)])
@pytest.mark.parametrize("path,helper", [("/api/scans/start", "create_scan_batch"), ("/api/schedules", "create_scan_schedule_batch")])
def test_transaction_revalidation_errors_reach_client(api, payload, monkeypatch, error, status, path, helper):
    monkeypatch.setattr(webapp, helper, Mock(side_effect=error))
    assert api.post(path, json=payload).status_code == status
