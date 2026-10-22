import pytest
from fastapi.testclient import TestClient
from darkstar import webapp

pytestmark = pytest.mark.smoke


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(webapp, "list_organizations", list)
    monkeypatch.setattr(webapp, "scheduler_started", True)
    monkeypatch.setattr(webapp, "authenticate_api_key", lambda token: {
        "id": 12, "org_id": 7, "org_db_name": "tenant_a", "org_name": "Tenant A", "role": token,
    } if token in webapp.ROLE_RANK else None)
    with TestClient(webapp.app) as client:
        yield client


@pytest.mark.parametrize("prefix,kind", [("/api/vulnerabilities", "network"), ("/api/endpoints/vulnerabilities", "endpoint")])
@pytest.mark.parametrize("role", [None, "viewer", "security_analyst", "tenant_admin", "platform_admin"])
@pytest.mark.parametrize("method", ["POST", "DELETE"])
def test_risk_writes_enforce_roles_and_current_tenant(client, mocker, prefix, kind, role, method):
    write = mocker.patch.object(webapp, "set_risk_acceptance", return_value=True)
    response = client.request(method, f"{prefix}/42/risk-acceptance",
                              headers={"Authorization": f"Bearer {role}"} if role else {},
                              json={"reason": "Mitigated"} if method == "POST" else None)
    allowed = role in {"security_analyst", "tenant_admin", "platform_admin"}
    assert response.status_code == (200 if allowed else 403 if role else 401)
    if allowed:
        write.assert_called_once_with("tenant_a", kind, 42, actor="api_key:12", reason="Mitigated" if method == "POST" else None,
                                      expires_at=None, revoke=method == "DELETE", expected_org_id=7)
    else:
        write.assert_not_called()


@pytest.mark.parametrize("error,status", [(ValueError("Invalid expiry"), 400), (webapp.OrganizationConflictError("Organization changed"), 409)])
def test_risk_write_errors_are_reported(client, mocker, error, status):
    mocker.patch.object(webapp, "set_risk_acceptance", side_effect=error)
    response = client.post("/api/vulnerabilities/1/risk-acceptance", headers={"Authorization": "Bearer tenant_admin"}, json={"reason": "test"})
    assert response.status_code == status


@pytest.mark.parametrize("include", [False, True])
@pytest.mark.parametrize("path,helper", [
    ("/api/stats", "get_vulnerability_stats"),
    ("/api/vulnerabilities", "get_latest_vulnerabilities"),
    ("/api/endpoints/overview", "get_endpoint_overview"),
    ("/api/endpoints/vulnerabilities", "list_endpoint_vulnerabilities"),
    ("/api/scoring/overview", "get_scoring_overview"),
    ("/api/vulnerabilities/grouped", "get_grouped_vulnerabilities"),
    ("/api/exports/vulnerabilities.csv", "get_vulnerability_export_rows"),
    ("/api/exports/vulnerabilities.xlsx", "get_vulnerability_export_rows"),
    ("/api/exports/vulnerabilities.html", "get_vulnerability_export_rows"),
    ("/api/exports/vulnerabilities.pdf", "get_vulnerability_export_rows"),
    ("/api/exports/attack-surface.csv", "_attack_surface_export_rows"),
    ("/api/exports/attack-surface.xlsx", "_attack_surface_export_rows"),
    ("/api/exports/attack-surface.html", "_attack_surface_export_rows"),
])
def test_accepted_risks_are_explicitly_opted_into(client, mocker, include, path, helper):
    query = mocker.patch.object(webapp, helper, return_value=[])
    response = client.get(path + ("?include_accepted=true" if include else ""), headers={"Authorization": "Bearer viewer"})
    assert response.status_code == 200
    assert query.call_args.kwargs["include_accepted"] is include
