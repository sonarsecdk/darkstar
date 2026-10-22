"""Authorization and execution checks for approved scan targets."""
import socket
from unittest.mock import Mock

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from darkstar import webapp
from darkstar.core import scan_scope


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setattr(webapp, 'scheduler_started', True)
    monkeypatch.setattr(webapp, 'list_organizations', list)
    monkeypatch.setattr(webapp, 'authenticate_api_key', lambda token: {'id': 9, 'org_id': 7, 'org_db_name': 'tenant_db', 'org_name': 'Test', 'role': token} if token in webapp.ROLE_RANK else None)
    monkeypatch.setattr(webapp, 'get_allowed_scan_targets', lambda org: [{'target': value} for value in ['example.test', '192.0.2.1']])
    monkeypatch.setattr(scan_scope.socket, 'getaddrinfo', lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.1', 0))])
    with TestClient(webapp.app) as client:
        yield client


@pytest.mark.parametrize('role,status', [('', 401), ('viewer', 403), ('security_analyst', 403), ('tenant_admin', 403), ('platform_admin', 200)])
def test_only_platform_admin_can_change_approvals(api, monkeypatch, role, status):
    update = Mock(return_value=[{'target': '192.0.2.1'}])
    monkeypatch.setattr(webapp, 'replace_allowed_scan_targets', update)
    response = api.put('/api/scan-scope', headers={'Authorization': 'Bearer ' + role}, json={'targets': ['192.0.2.1']})
    assert response.status_code == status
    if status == 200:
        assert update.call_args.args == ('tenant_db', ['192.0.2.1'])
        assert update.call_args.kwargs['expected_org_id'] == 7
    else:
        update.assert_not_called()


@pytest.mark.parametrize('role', ['viewer', 'security_analyst', 'tenant_admin', 'platform_admin'])
def test_members_can_read_scope(api, role):
    response = api.get('/api/scan-scope', headers={'Authorization': 'Bearer ' + role})
    assert response.status_code == 200
    assert response.json()['items'][0]['target'] == 'example.test'


@pytest.mark.parametrize('path', ['/api/scans/start', '/api/schedules'])
@pytest.mark.parametrize('targets', ['outside.test', '192.0.2.2', 'https://sub.example.test', '192.0.2.0/24'])
def test_manual_and_scheduled_scans_reject_unapproved_targets(api, monkeypatch, path, targets):
    create = Mock()
    monkeypatch.setattr(webapp, 'create_scan_record', create)
    monkeypatch.setattr(webapp, 'create_scan_schedule', create)
    response = api.post(path, headers={'Authorization': 'Bearer security_analyst'}, json={'targets': targets, 'scanner': 'nuclei'})
    assert response.status_code == 403
    create.assert_not_called()


def test_changed_dns_blocks_previously_queued_job(api, monkeypatch):
    monkeypatch.setattr(webapp, 'authenticate_scanner_node', lambda token: {'node_id': 'node-a', 'capabilities': ['*']})
    monkeypatch.setattr(webapp, 'claim_next_scanner_job', lambda *a, **k: {'id': 42, 'org_db_name': 'tenant_db', 'targets': 'example.test'})
    monkeypatch.setattr(scan_scope.socket, 'getaddrinfo', lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.2', 0))])
    complete = Mock()
    monkeypatch.setattr(webapp, 'complete_scanner_job', complete)
    response = api.post('/api/scanner-workers/jobs/claim', headers={'Authorization': 'Bearer worker-token'}, json={})
    assert response.status_code == 200
    assert response.json()['job'] is None
    assert complete.call_args.args[:3] == (42, 'node-a', 'failed')
    assert 'unapproved IP 192.0.2.2' in complete.call_args.args[3]


def test_empty_scope_blocks_existing_scheduled_targets(api, monkeypatch):
    monkeypatch.setattr(webapp, 'get_allowed_scan_targets', lambda org: [])
    with pytest.raises(HTTPException, match='No scan targets are approved'):
        webapp._queue_scan('tenant_db', webapp.ScanStartRequest(targets='192.0.2.1', scanner='nuclei'))


def test_stale_organization_and_active_scan_conflicts_are_visible(api, monkeypatch):
    monkeypatch.setattr(webapp, 'replace_allowed_scan_targets', Mock(side_effect=webapp.OrganizationConflictError('Stop active scans')))
    response = api.put('/api/scan-scope', headers={'Authorization': 'Bearer platform_admin'}, json={'targets': []})
    assert response.status_code == 409
    assert response.json()['detail'] == 'Stop active scans'
