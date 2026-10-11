from contextlib import nullcontext
from types import SimpleNamespace

import mysql.connector
import pytest

from darkstar import webapp
from darkstar.core import db_helper as db


pytestmark = pytest.mark.unit


@pytest.fixture()
def organization_database(mocker, monkeypatch):
    monkeypatch.setenv("DB_NAME", "darkstar")
    monkeypatch.setenv("PLATFORM_ADMIN_ORG", "platform_admin")
    organization = {"id": 7, "org_name": "Acme", "org_db_name": "org_acme", "role": "tenant_admin"}
    replies = [{"org_db_name": "org_acme"}, {"acquired": 1}, organization, None, None, {"SCHEMA_NAME": "org_acme"}, None]
    cursor = mocker.Mock()
    cursor.fetchone.side_effect = lambda: replies.pop(0)
    connection = mocker.Mock()
    connection.cursor.return_value = cursor
    mocker.patch.object(db, "DatabaseConnectionManager", return_value=nullcontext(connection))
    return cursor, connection, replies


def test_delete_removes_only_tenant_records_and_keeps_users(organization_database):
    cursor, connection, _replies = organization_database

    result = db.delete_organization(7, active_org_db="org_home")

    assert result["org_name"] == "Acme"
    writes = [call.args for call in cursor.execute.call_args_list if call.args[0].startswith(("DROP", "DELETE", "UPDATE"))]
    assert writes == [
        ("DROP DATABASE IF EXISTS `org_acme`",),
        ("DELETE FROM api_keys WHERE org_db_name = %s", ("org_acme",)),
        ("DELETE FROM organization_memberships WHERE org_db_name = %s", ("org_acme",)),
        ("DELETE FROM scanner_jobs WHERE org_db_name = %s", ("org_acme",)),
        ("DELETE FROM organizations WHERE id = %s", (7,)),
    ]
    connection.commit.assert_called_once()
    cursor.close.assert_called_once()


@pytest.mark.parametrize("recreated", [False, True])
def test_missing_or_recreated_organization_is_not_deleted(organization_database, recreated):
    cursor, connection, replies = organization_database
    if recreated:
        replies[2] = {**replies[2], "id": 8}
    else:
        replies[0] = None

    assert db.delete_organization(7, active_org_db="org_home") is None
    assert not any(call.args[0].startswith(("DROP", "DELETE")) for call in cursor.execute.call_args_list)
    connection.commit.assert_not_called()


@pytest.mark.parametrize("reason", ["platform_role", "platform_name", "registry", "active", "platform_member", "queue", "scan", "lock"])
def test_unsafe_deletion_is_rejected_before_writes(organization_database, reason):
    cursor, connection, replies = organization_database
    active_org_db = "org_home"
    if reason == "platform_role":
        replies[2]["role"] = "platform_admin"
    elif reason in {"platform_name", "registry"}:
        org_db = "org_platform_admin" if reason == "platform_name" else "darkstar"
        replies[0]["org_db_name"] = org_db
        replies[2]["org_db_name"] = org_db
    elif reason == "active":
        active_org_db = "org_acme"
    elif reason == "lock":
        replies[1] = {"acquired": 0}
    else:
        replies[{"platform_member": 3, "queue": 4, "scan": 6}[reason]] = {"id": 1}

    with pytest.raises(db.OrganizationConflictError):
        db.delete_organization(7, active_org_db=active_org_db)

    assert not any(call.args[0].startswith(("DROP", "DELETE")) for call in cursor.execute.call_args_list)
    connection.commit.assert_not_called()


def test_invalid_database_identifier_is_never_interpolated(organization_database):
    cursor, _connection, replies = organization_database
    replies[0]["org_db_name"] = "org_acme`; DROP DATABASE darkstar; --"
    with pytest.raises(ValueError, match="identifier"):
        db.delete_organization(7, active_org_db="org_home")
    assert cursor.execute.call_count == 1


@pytest.mark.parametrize("failure", ["DROP DATABASE", "DELETE FROM api_keys"])
def test_database_failure_does_not_publish_success(organization_database, failure):
    cursor, connection, _replies = organization_database

    def execute(statement, *_args):
        if statement.startswith(failure):
            raise mysql.connector.Error("Deliberate failure")

    cursor.execute.side_effect = execute
    with pytest.raises(mysql.connector.Error, match="Deliberate failure"):
        db.delete_organization(7, active_org_db="org_home")
    connection.rollback.assert_called_once()
    connection.commit.assert_not_called()
    assert not any(call.args[0].startswith("DELETE FROM organizations") for call in cursor.execute.call_args_list)


def test_deletion_can_retry_cleanup_after_database_was_dropped(organization_database):
    cursor, connection, replies = organization_database
    replies[5] = None
    assert db.delete_organization(7, active_org_db="org_home")["id"] == 7
    assert not any("`org_acme`.scans" in call.args[0] for call in cursor.execute.call_args_list)
    connection.commit.assert_called_once()


@pytest.mark.parametrize("operation", ["scan", "queue", "schema", "membership", "api_key"])
def test_deleted_organization_cannot_receive_new_records(organization_database, mocker, operation):
    cursor, connection, replies = organization_database
    replies[:] = [{"acquired": 1}, None]
    mocker.patch.object(db, "_ensure_organizations_registry")
    if operation == "schema":
        db.ensure_org_database_schema("org_acme")
    else:
        with pytest.raises(ValueError, match="no longer exists"):
            if operation == "scan":
                db.create_scan_record("org_acme", "Test scan", "nuclei", "example.invalid")
            elif operation == "queue":
                db.enqueue_scanner_job("org_acme", 1, "Test scan", "nuclei", "example.invalid", {})
            elif operation == "membership":
                db.create_or_update_user("user@example.test", "Password1!", "User", "org_acme", "viewer", restrict_to_org=False)
            else:
                db.create_api_key("org_acme", "Test key")
    assert all(call.args[0].startswith("SELECT") for call in cursor.execute.call_args_list)
    connection.commit.assert_not_called()


@pytest.mark.parametrize("stored_id,current_id", [(7, None), (7, 8), (None, 7)])
def test_deleted_recreated_and_old_sessions_require_login(mocker, stored_id, current_id):
    mocker.patch.object(webapp, "get_organization_id", return_value=current_id)
    request = SimpleNamespace(session={"org_db": "org_acme", "org_id": stored_id}, state=SimpleNamespace())
    with pytest.raises(webapp.HTTPException) as exc:
        webapp._get_org_db(request)
    assert exc.value.status_code == 401
    assert request.session == {}


def test_current_session_is_checked_once_per_request(mocker):
    lookup = mocker.patch.object(webapp, "get_organization_id", return_value=7)
    request = SimpleNamespace(session={"org_db": "org_acme", "org_id": 7}, state=SimpleNamespace())
    assert webapp._get_org_db(request) == "org_acme"
    assert webapp._get_org_db(request) == "org_acme"
    lookup.assert_called_once_with("org_acme")
