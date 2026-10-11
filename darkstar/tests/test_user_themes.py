from unittest.mock import MagicMock

import pytest

from darkstar.core import db_helper

pytestmark = pytest.mark.unit


def test_theme_update_changes_only_the_selected_account(monkeypatch):
    connection = MagicMock()
    manager = MagicMock()
    manager.__enter__.return_value = connection
    monkeypatch.setattr(db_helper, "DatabaseConnectionManager", lambda: manager)
    monkeypatch.setattr(db_helper, "_ensure_organizations_registry", lambda cursor: None)
    monkeypatch.setattr(db_helper, "get_user_by_id", lambda user_id: {"id": user_id, "theme": "daylight"})
    assert db_helper.update_user_theme(12, "daylight") == {"id": 12, "theme": "daylight"}
    connection.cursor.return_value.execute.assert_called_once_with(
        "UPDATE users SET theme = %s WHERE id = %s", ("daylight", 12)
    )
    connection.commit.assert_called_once()


def test_public_user_includes_theme_without_secrets():
    user = db_helper._public_user({"id": 12, "theme": "aurora", "password_hash": "secret", "mfa_secret": "secret"})
    assert user["theme"] == "aurora"
    assert "password_hash" not in user
    assert "mfa_secret" not in user
    assert db_helper._public_user({"id": 12})["theme"] == "darkstar"
