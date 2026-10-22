"""A theme is a personal preference, regardless of organization or role."""
import base64
import json

import pytest
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner

from darkstar import webapp

pytestmark = pytest.mark.smoke


@pytest.fixture()
def theme_client(monkeypatch):
    monkeypatch.setattr(webapp, "list_organizations", list)
    monkeypatch.setattr(webapp, "scheduler_started", True)
    monkeypatch.setattr(webapp, "authenticate_api_key", lambda token: None)
    with TestClient(webapp.app) as client:
        yield client


def sign_in(client, **session):
    middleware = next(item for item in webapp.app.user_middleware if item.cls.__name__ == "SessionMiddleware")
    signer = TimestampSigner(str(middleware.kwargs["secret_key"]))
    cookie = signer.sign(base64.b64encode(json.dumps(session).encode())).decode()
    client.cookies.set("session", cookie)


@pytest.mark.parametrize("role", ["viewer", "security_analyst", "tenant_admin", "platform_admin"])
def test_theme_update_uses_session_user_for_every_role(theme_client, monkeypatch, role):
    writes = []

    def update(user_id, theme):
        writes.append((user_id, theme))
        return {"id": user_id, "theme": theme}

    monkeypatch.setattr(webapp, "update_user_theme", update)
    sign_in(theme_client, user_id=12, org_db="tenant_a", role=role)
    result = theme_client.patch("/api/me/theme", json={"theme": "midnight", "user_id": 99, "org_db": "tenant_b"})
    assert result.status_code == 200
    assert result.json() == {"theme": "midnight"}
    assert writes == [(12, "midnight")]


@pytest.mark.parametrize("theme", ["darkstar", "midnight", "daylight", "aurora", "sandstone"])
def test_known_themes_can_be_saved(theme_client, monkeypatch, theme):
    monkeypatch.setattr(webapp, "update_user_theme", lambda user_id, value: {"theme": value})
    sign_in(theme_client, user_id=12, org_db="tenant_a", role="viewer")
    assert theme_client.patch("/api/me/theme", json={"theme": theme}).json() == {"theme": theme}


@pytest.mark.parametrize("theme", ["", "unknown", "DAYLIGHT", "../custom.css", '<script>alert(1)</script>', None, 42])
def test_invalid_themes_do_not_write(theme_client, monkeypatch, theme):
    def unexpected_write(*args):
        pytest.fail("An invalid theme reached the database")

    monkeypatch.setattr(webapp, "update_user_theme", unexpected_write)
    sign_in(theme_client, user_id=12, org_db="tenant_a", role="viewer")
    assert theme_client.patch("/api/me/theme", json={"theme": theme}).status_code == 422


@pytest.mark.parametrize("session,status", [({}, 401), ({"org_db": "tenant_a", "role": "platform_admin"}, 403), ({"pending_mfa": {"user_id": 12}}, 401)])
def test_theme_requires_a_completed_personal_login(theme_client, monkeypatch, session, status):
    def unexpected_write(*args):
        pytest.fail("An unauthenticated request reached the database")

    monkeypatch.setattr(webapp, "update_user_theme", unexpected_write)
    sign_in(theme_client, **session)
    assert theme_client.patch("/api/me/theme", json={"theme": "daylight"}).status_code == status


def test_api_key_does_not_identify_a_personal_account(theme_client, monkeypatch):
    monkeypatch.setattr(webapp, "authenticate_api_key", lambda token: {"org_db_name": "tenant_a", "role": "platform_admin"})
    response = theme_client.patch("/api/me/theme", headers={"Authorization": "Bearer test-key"}, json={"theme": "daylight"})
    assert response.status_code == 403


def test_deleted_account_cannot_save_theme(theme_client, monkeypatch):
    monkeypatch.setattr(webapp, "update_user_theme", lambda *args: {})
    sign_in(theme_client, user_id=12, org_db="tenant_a", role="viewer")
    assert theme_client.patch("/api/me/theme", json={"theme": "daylight"}).status_code == 401


@pytest.mark.parametrize("path", ["/", "/documentation"])
def test_theme_is_rendered_before_javascript(theme_client, monkeypatch, path):
    monkeypatch.setattr(webapp, "get_user_by_id", lambda user_id: {"id": user_id, "theme": "sandstone"})
    sign_in(theme_client, user_id=12, org_db="tenant_a", role="viewer")
    response = theme_client.get(path)
    assert response.status_code == 200
    assert '<html lang="en" data-theme="sandstone">' in response.text
    assert '/static/css/themes.css' in response.text


@pytest.mark.parametrize("user", [None, {}, {"theme": "removed-theme"}, {"theme": '\" onload=\"alert(1)'}])
def test_missing_or_obsolete_preferences_fall_back(theme_client, monkeypatch, user):
    monkeypatch.setattr(webapp, "get_user_by_id", lambda user_id: user)
    sign_in(theme_client, user_id=12, org_db="tenant_a", role="viewer")
    assert '<html lang="en" data-theme="darkstar">' in theme_client.get("/").text
