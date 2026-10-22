"""Approved target persistence and tenant boundaries on disposable MariaDB."""
import os
import uuid

import pytest

from darkstar.core import db_helper as db
from darkstar.core.scan_scope import ScanScopeError


@pytest.fixture
def tenants(monkeypatch):
    host = os.environ.get('DARKSTAR_TEST_DB_HOST')
    password = os.environ.get('DARKSTAR_TEST_DB_PASSWORD')
    if not host or not password:
        pytest.skip('Set DARKSTAR_TEST_DB_HOST/PASSWORD for MariaDB integration tests')
    for key, value in {'DB_HOST': host, 'DB_USER': 'root', 'DB_PASSWORD': password, 'DB_NAME': 'feature_tests'}.items():
        monkeypatch.setenv(key, value)
    names = []
    try:
        for _ in range(2):
            names.append(db.create_organization('scope_test_' + uuid.uuid4().hex[:12])['org_db_name'])
        yield names
    finally:
        for org in names:
            for scan in db.get_scan_history(org):
                db.update_scan_status(org, scan['id'], 'stopped')
            db.delete_organization(db.get_organization_id(org), active_org_db='feature_tests')


def approve(org, targets):
    return db.replace_allowed_scan_targets(org, targets, actor='platform@example.test', expected_org_id=db.get_organization_id(org))


def test_empty_scope_tenant_isolation_and_audit(tenants):
    first, second = tenants
    with pytest.raises(ScanScopeError, match='No scan targets are approved'):
        db.create_scan_record(first, 'Blocked', 'nuclei', '192.0.2.1')
    approvals = approve(first, ['192.0.2.1', 'EXAMPLE.test.', '192.0.2.1'])
    assert [row['target'] for row in approvals] == ['192.0.2.1', 'example.test']
    assert all(row['approved_by'] == 'platform@example.test' and row['approved_at'] for row in approvals)
    assert db.get_allowed_scan_targets(second) == []
    with pytest.raises(ScanScopeError):
        db.create_scan_record(second, 'Other tenant', 'nuclei', '192.0.2.1')
    with db.DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        db._use_org_database(cursor, first)
        cursor.execute("SELECT actor, metadata FROM audit_log WHERE action = 'scan_scope.updated'")
        audit = cursor.fetchone()
        cursor.close()
    assert audit['actor'] == 'platform@example.test'
    assert '192.0.2.1' in audit['metadata']


def test_active_scans_block_scope_changes_until_stopped(tenants):
    org = tenants[0]
    approve(org, ['192.0.2.0/24'])
    scan_id = db.create_scan_record(org, 'Approved', 'nuclei', '192.0.2.1')
    with pytest.raises(db.OrganizationConflictError, match='Stop active'):
        approve(org, [])
    assert db.get_allowed_scan_targets(org)[0]['target'] == '192.0.2.0/24'
    db.update_scan_status(org, scan_id, 'stopped')
    assert approve(org, []) == []
    with pytest.raises(ScanScopeError):
        db.create_scan_record(org, 'Blocked again', 'nuclei', '192.0.2.1')


def test_invalid_or_stale_updates_preserve_approvals(tenants):
    org = tenants[0]
    approve(org, ['192.0.2.1'])
    with pytest.raises(ScanScopeError):
        approve(org, ['192.0.2.2', 'https://example.test'])
    with pytest.raises(db.OrganizationConflictError):
        db.replace_allowed_scan_targets(org, [], actor='platform', expected_org_id=-1)
    assert [row['target'] for row in db.get_allowed_scan_targets(org)] == ['192.0.2.1']
