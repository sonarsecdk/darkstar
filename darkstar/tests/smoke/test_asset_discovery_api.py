"""Discovery authorization stays separate from customer scan approval."""
from datetime import datetime, timedelta
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from darkstar import webapp


PLAN = {'seeds': [{'target': '192.0.2.1', 'host': '192.0.2.1', 'kind': 'ip',
                   'addresses': ['192.0.2.1'], 'url': None}],
        'authorized_targets': ['192.0.2.1'], 'port_mode': 'common'}


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setattr(webapp, 'scheduler_started', True)
    monkeypatch.setattr(webapp, 'list_organizations', list)
    monkeypatch.setattr(webapp, 'authenticate_api_key', lambda token: {
        'id': 1, 'org_id': 7, 'org_db_name': 'tenant_db', 'org_name': 'Tenant', 'role': token,
    } if token in webapp.ROLE_RANK else None)
    monkeypatch.setattr(webapp, 'list_asset_inventory', lambda org, include_pending=False: [
        {'target': '192.0.2.1', 'approved': True},
        *([{'target': '192.0.2.2', 'approved': False}] if include_pending else []),
    ])
    monkeypatch.setattr(webapp, 'get_scan_history', lambda *a, **k: [
        {'id': 1, 'scan_mode': 'discovery', 'targets': '192.0.2.2'},
        {'id': 2, 'scan_mode': 'zap', 'targets': '192.0.2.1'},
    ])
    monkeypatch.setattr(webapp, 'get_scanner_node_record', lambda node: {
        'node_id': node, 'capabilities': ['discovery', 'zap'], 'status': 'online',
        'last_seen_at': datetime.utcnow(),
    })
    monkeypatch.setattr(webapp, 'list_available_scanner_nodes', lambda: [{
        'node_id': 'node-discovery', 'capabilities': ['discovery'], 'status': 'online',
        'last_seen_at': datetime.utcnow(),
    }])
    monkeypatch.setattr(webapp, 'prepare_discovery', Mock(return_value=PLAN))
    monkeypatch.setattr(webapp, 'create_discovery_scan', Mock(return_value=9))
    monkeypatch.setattr(webapp, 'enqueue_scanner_job', Mock(return_value=11))
    monkeypatch.setattr(webapp, 'insert_scan_log', Mock())
    monkeypatch.setattr(webapp, 'replace_allowed_scan_targets', Mock())
    monkeypatch.setattr(webapp, 'approve_inventory_targets', Mock())
    monkeypatch.setattr(webapp, 'update_asset_scanners', Mock())
    with TestClient(webapp.app) as client:
        yield client


@pytest.mark.parametrize('role,status', [('', 401), ('viewer', 403), ('security_analyst', 403),
                                         ('tenant_admin', 403), ('platform_admin', 200)])
def test_only_platform_can_start_preapproval_discovery(api, role, status):
    response = api.post('/api/discoveries', headers={'Authorization': 'Bearer ' + role},
                        json={'targets': '192.0.2.1', 'port_mode': 'common'})
    assert response.status_code == status
    webapp.replace_allowed_scan_targets.assert_not_called()
    if status == 200:
        assert response.json()['scan_id'] == 9
        assert webapp.create_discovery_scan.call_args.args[0] == 'tenant_db'
        job = webapp.enqueue_scanner_job.call_args
        assert job.args[5]['job_type'] == 'discovery'
        assert job.args[5]['discovery'] == PLAN
        assert job.kwargs.get('preferred_node_id') is None
    else:
        webapp.prepare_discovery.assert_not_called()
        webapp.enqueue_scanner_job.assert_not_called()


def test_discovery_does_not_pin_a_worker_from_an_old_client(api):
    response = api.post('/api/discoveries', headers={'Authorization': 'Bearer platform_admin'},
                        json={'targets': '192.0.2.1', 'preferred_node_id': 'some-old-selection'})
    assert response.status_code == 200
    assert webapp.enqueue_scanner_job.call_args.kwargs.get('preferred_node_id') is None


@pytest.mark.parametrize('changes', [
    {'capabilities': ['zap']}, {'status': 'offline'}, {'revoked_at': 'today'},
    {'last_seen_at': datetime.utcnow() - timedelta(minutes=4)}, {'last_seen_at': None},
])
def test_discovery_requires_an_online_capable_worker(api, monkeypatch, changes):
    node = {'node_id': 'node-1', 'capabilities': ['discovery'], 'status': 'online',
            'last_seen_at': datetime.utcnow(), **changes}
    monkeypatch.setattr(webapp, 'list_available_scanner_nodes', lambda: [node])
    headers = {'Authorization': 'Bearer platform_admin'}
    assert api.get('/api/discoveries', headers=headers).json()['available'] is False
    response = api.post('/api/discoveries', headers=headers, json={'targets': '192.0.2.1'})
    assert response.status_code == 503
    webapp.enqueue_scanner_job.assert_not_called()


def test_appliance_tags_require_online_capability_and_installed_profile(api, monkeypatch):
    def node(identifier, capabilities, **extra):
        return {'node_id': identifier, 'name': identifier, 'capabilities': capabilities,
                'status': 'online', 'last_seen_at': datetime.utcnow(), **extra}
    monkeypatch.setattr(webapp, 'list_asset_inventory', lambda *a, **k: [{
        'target': '192.0.2.1', 'approved': True, 'compatible_scanners': ['openvas', 'zap', 'nuclei'],
    }])
    monkeypatch.setattr(webapp, 'list_available_scanner_nodes', lambda: [
        node('network', ['openvas']), node('web', ['zap']), node('no-policy', ['openvas']),
        node('wrong-capability', ['discovery']), node('stale', ['zap'], last_seen_at=datetime.utcnow() - timedelta(minutes=4)),
        node('revoked', ['zap'], revoked_at='today'), node('variant', ['scanner:nucleinetwork']),
    ])
    profiles = {'network': ['openvas', 'zap'], 'web': ['zap'], 'no-policy': [],
                'wrong-capability': ['zap'], 'variant': ['nucleinetwork']}
    monkeypatch.setattr(webapp, 'get_scanner_profiles', lambda node: {'items': [{'scanner': scanner} for scanner in profiles[node]]})
    response = api.get('/api/asset-inventory', headers={'Authorization': 'Bearer platform_admin'})
    assert response.status_code == 200
    assert response.json()['scanner_appliances'] == {
        'openvas': [{'node_id': 'network', 'name': 'network'}],
        'zap': [{'node_id': 'web', 'name': 'web'}],
        'nuclei': [{'node_id': 'variant', 'name': 'variant'}],
    }


@pytest.mark.parametrize('role', ['viewer', 'security_analyst', 'tenant_admin', 'platform_admin'])
def test_inventory_hides_pending_from_customer_roles(api, role):
    response = api.get('/api/asset-inventory?org_db=someone_else', headers={'Authorization': 'Bearer ' + role})
    assert response.status_code == 200
    assert response.json()['pending_count'] == (1 if role == 'platform_admin' else 0)


@pytest.mark.parametrize('role', ['viewer', 'security_analyst', 'tenant_admin'])
def test_customers_cannot_approve_or_change_engine_permissions(api, role):
    headers = {'Authorization': 'Bearer ' + role}
    assert api.post('/api/asset-inventory/approve', headers=headers,
                    json={'targets': ['192.0.2.1']}).status_code == 403
    assert api.put('/api/asset-inventory/scanners', headers=headers,
                   json={'target': '192.0.2.1', 'enabled_scanners': ['zap']}).status_code == 403
    webapp.approve_inventory_targets.assert_not_called()
    webapp.update_asset_scanners.assert_not_called()


def test_platform_approval_preserves_org_identity_and_engine_choices(api):
    response = api.post('/api/asset-inventory/approve', headers={'Authorization': 'Bearer platform_admin'},
                        json={'targets': ['192.0.2.1'], 'enabled_scanners': ['openvas', 'zap']})
    assert response.status_code == 200
    call = webapp.approve_inventory_targets.call_args
    assert call.args == ('tenant_db', ['192.0.2.1'])
    assert call.kwargs['expected_org_id'] == 7
    assert call.kwargs['enabled_scanners'] == ['openvas', 'zap']


def test_normal_scan_api_cannot_be_used_to_start_discovery(api):
    response = api.post('/api/scans/start', headers={'Authorization': 'Bearer tenant_admin'},
                        json={'targets': '192.0.2.2', 'scanner': 'discovery', 'job_type': 'discovery'})
    assert response.status_code == 400
    webapp.enqueue_scanner_job.assert_not_called()


def test_customer_scan_history_excludes_discovery(api):
    response = api.get('/api/scans', headers={'Authorization': 'Bearer tenant_admin'})
    assert [item['id'] for item in response.json()['items']] == [2]
    assert api.get('/api/discoveries', headers={'Authorization': 'Bearer tenant_admin'}).status_code == 403


def test_customer_cannot_read_or_stop_discovery_by_id(api, monkeypatch):
    monkeypatch.setattr(webapp, 'get_scan_record', lambda *a: {'id': 1, 'scan_mode': 'discovery', 'status': 'running'})
    headers = {'Authorization': 'Bearer tenant_admin'}
    for path in ['/api/scans/1', '/api/scans/1/logs']:
        assert api.get(path, headers=headers).status_code == 403
    assert api.post('/api/scans/1/stop', headers=headers).status_code == 403


def worker_auth(monkeypatch, job):
    monkeypatch.setattr(webapp, 'authenticate_scanner_node', lambda token: {'node_id': 'node-zap', 'capabilities': ['discovery']})
    monkeypatch.setattr(webapp, 'extend_scanner_job_lease', lambda *a, **k: job)
    monkeypatch.setattr(webapp, 'save_discovery_results', Mock(return_value=1))


def test_worker_results_require_owned_discovery_job_and_original_hosts(api, monkeypatch):
    job = {'id': 11, 'scan_id': 9, 'org_db_name': 'tenant_db', 'scanner': 'discovery', 'scan_mode': 'discovery',
           'status': 'running', 'payload': {'job_type': 'discovery', 'discovery': PLAN}}
    worker_auth(monkeypatch, job)
    headers = {'Authorization': 'Bearer worker'}
    response = api.post('/api/scanner-workers/jobs/11/discovery-results', headers=headers,
                        json={'items': [{'target': '198.51.100.1', 'addresses': [], 'services': []}]})
    assert response.status_code == 400
    webapp.save_discovery_results.assert_not_called()
    response = api.post('/api/scanner-workers/jobs/11/discovery-results', headers=headers,
                        json={'items': [{'target': '192.0.2.1', 'addresses': ['192.0.2.1'], 'services': []}]})
    assert response.status_code == 200
    assert webapp.save_discovery_results.call_args.args[:3] == ('tenant_db', 9, 'node-zap')
    job['status'] = 'stopping'
    assert api.post('/api/scanner-workers/jobs/11/discovery-results', headers=headers,
                    json={'items': []}).json()['stop_requested'] is True


def test_failed_queue_does_not_leave_discovery_queued(api, monkeypatch):
    monkeypatch.setattr(webapp, 'enqueue_scanner_job', Mock(side_effect=ValueError('Organization no longer exists')))
    update = Mock()
    monkeypatch.setattr(webapp, 'update_scan_status', update)
    response = api.post('/api/discoveries', headers={'Authorization': 'Bearer platform_admin'},
                        json={'targets': '192.0.2.1', 'preferred_node_id': 'node-zap'})
    assert response.status_code == 400
    assert update.call_args.args == ('tenant_db', 9, 'failed')


@pytest.mark.parametrize('item', [
    {'target': [], 'addresses': [], 'services': []},
    {'target': '192.0.2.1', 'addresses': [], 'services': None},
    {'target': '192.0.2.1', 'addresses': [], 'services': [{}]},
    {'target': '192.0.2.1', 'addresses': ['192.0.2.1'] * 257, 'services': []},
])
def test_malformed_worker_results_are_rejected_before_persistence(api, monkeypatch, item):
    worker_auth(monkeypatch, None)
    response = api.post('/api/scanner-workers/jobs/11/discovery-results',
                        headers={'Authorization': 'Bearer worker'}, json={'items': [item]})
    assert response.status_code == 422
    webapp.save_discovery_results.assert_not_called()


def test_discovered_zap_urls_are_queued_without_changing_approved_asset(api, monkeypatch):
    monkeypatch.setattr(webapp, 'get_allowed_scan_targets', lambda org: [{'target': '192.0.2.1'}])
    monkeypatch.setattr(webapp, 'get_asset_scanner_rules', lambda org: [{'target': '192.0.2.1', 'enabled_scanners': ['zap']}])
    monkeypatch.setattr(webapp, 'list_asset_inventory', lambda org: [
        {'target': '192.0.2.1', 'approved': True, 'services': [{'url': 'http://192.0.2.1:3000/'}]},
    ])
    monkeypatch.setattr(webapp, 'get_scan_history', lambda *a, **k: [])
    monkeypatch.setattr(webapp, 'get_scanner_profiles', lambda node: {'items': [{'scanner': 'zap', 'id': 'default', 'name': 'Recon'}]})
    monkeypatch.setattr(webapp, 'create_scan_record', Mock(return_value=17))
    monkeypatch.setattr(webapp, 'create_scan_components', Mock())
    response = api.post('/api/scans/start', headers={'Authorization': 'Bearer tenant_admin'}, json={
        'targets': '192.0.2.1', 'selections': [{'scanner': 'zap', 'profile_id': 'default'}], 'preferred_node_id': 'node-zap',
    })
    assert response.status_code == 200
    queued = webapp.enqueue_scanner_job.call_args.kwargs
    assert queued['targets'] == '192.0.2.1'
    assert queued['payload']['selections'][0]['targets'] == 'http://192.0.2.1:3000/'
    webapp.replace_allowed_scan_targets.assert_not_called()


@pytest.mark.parametrize('path', ['/api/scans/start', '/api/schedules'])
def test_disabled_engine_is_rejected_for_manual_and_scheduled_work(api, monkeypatch, path):
    monkeypatch.setattr(webapp, 'get_allowed_scan_targets', lambda org: [{'target': '192.0.2.1'}])
    monkeypatch.setattr(webapp, 'get_asset_scanner_rules', lambda org: [{'target': '192.0.2.1', 'enabled_scanners': []}])
    response = api.post(path, headers={'Authorization': 'Bearer tenant_admin'},
                        json={'targets': '192.0.2.1', 'scanner': 'openvas'})
    assert response.status_code == 403
    assert 'not enabled' in response.json()['detail']
    webapp.enqueue_scanner_job.assert_not_called()


def test_claim_rechecks_asset_engine_access(api, monkeypatch):
    job = {'id': 7, 'org_db_name': 'tenant_db', 'targets': '192.0.2.1', 'scanner': 'zap',
           'payload': {'scanner': 'zap', 'targets': 'http://192.0.2.1:3000/'}}
    monkeypatch.setattr(webapp, 'authenticate_scanner_node', lambda token: {'node_id': 'node-zap', 'capabilities': ['zap']})
    monkeypatch.setattr(webapp, 'claim_next_scanner_job', lambda *a, **k: job)
    monkeypatch.setattr(webapp, 'get_allowed_scan_targets', lambda org: [{'target': '192.0.2.1'}])
    monkeypatch.setattr(webapp, 'get_asset_scanner_rules', lambda org: [{'target': '192.0.2.1', 'enabled_scanners': []}])
    complete = Mock()
    monkeypatch.setattr(webapp, 'complete_scanner_job', complete)
    response = api.post('/api/scanner-workers/jobs/claim', headers={'Authorization': 'Bearer worker'}, json={})
    assert response.status_code == 200 and response.json()['job'] is None
    assert complete.call_args.args[:3] == (7, 'node-zap', 'failed')
