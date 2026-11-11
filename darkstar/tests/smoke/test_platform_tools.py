"""Administrative tools enforce permissions for sessions and API keys."""
import base64
import json

import pytest
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner
from starlette.websockets import WebSocketDisconnect

from darkstar import webapp


READ_PATHS = [
    '/documentation', '/docs', '/redoc', '/openapi.json',
    '/api/endpoints/overview', '/api/endpoints/enrollment-tokens',
    '/api/endpoints/agents', '/api/endpoints/agents/agent-a',
    '/api/endpoints/network-map', '/api/endpoints/software',
    '/api/endpoints/vulnerabilities', '/api/endpoints/vulnerabilities/1',
    '/api/scanner-nodes', '/api/integrations/m365/settings', '/api/integrations/m365/secure-score',
]
SCAN_ROUTES = [
    ('GET', '/api/scanner-nodes/available', None),
    ('GET', '/api/scanner-nodes/node-a/profiles', None),
    ('GET', '/api/schedules', None),
    ('POST', '/api/scans/start', {'targets': '192.0.2.1', 'scanner': 'openvas'}),
    ('POST', '/api/scans/1/stop', {}),
    ('POST', '/api/schedules', {'targets': '192.0.2.1', 'scanner': 'openvas'}),
    ('PATCH', '/api/schedules/1', {'enabled': False}),
    ('DELETE', '/api/schedules/1', None), ('POST', '/api/schedules/1/run', {}),
]
WRITE_ROUTES = [
    ('POST', '/api/scanner-nodes', {'name': 'Test scanner'}),
    ('DELETE', '/api/scanner-nodes/node-a', None),
    ('DELETE', '/api/scanner-nodes/node-a/record', None),
    ('POST', '/api/endpoints/enrollment-tokens', {'name': 'Test token'}),
    ('DELETE', '/api/endpoints/enrollment-tokens/1', None),
    ('POST', '/api/endpoints/agents/agent-a/revoke', {}),
    ('DELETE', '/api/endpoints/agents/agent-a', None),
    ('POST', '/api/endpoints/vulnerabilities/recalculate', {}),
    ('POST', '/api/endpoints/vulnerabilities/1/risk-acceptance', {'reason': 'Mitigated'}),
    ('DELETE', '/api/endpoints/vulnerabilities/1/risk-acceptance', None),
    ('PATCH', '/api/integrations/m365/settings', {'enabled': False}),
    ('POST', '/api/integrations/m365/secure-score/sync', {}),
]


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(webapp, 'scheduler_started', True)
    monkeypatch.setattr(webapp, 'list_organizations', list)
    monkeypatch.setattr(webapp, 'get_organization_id', lambda org: 7)
    monkeypatch.setattr(webapp, 'authenticate_api_key', lambda token: {
        'org_id': 7, 'org_db_name': 'tenant_a', 'org_name': 'Tenant A', 'role': token,
    } if token in webapp.ROLE_RANK else None)
    with TestClient(webapp.app) as client:
        yield client


def authenticate(client, role, method, org_db='tenant_a'):
    if role is None:
        return {}
    if method == 'api_key':
        return {'Authorization': f'Bearer {role}'}
    middleware = next(item for item in webapp.app.user_middleware if item.cls.__name__ == 'SessionMiddleware')
    signer = TimestampSigner(str(middleware.kwargs['secret_key']))
    session = {'org_db': org_db, 'org_id': 7, 'role': role}
    client.cookies.set('session', signer.sign(base64.b64encode(json.dumps(session).encode())).decode())
    return {}


@pytest.mark.parametrize('auth_method', ['session', 'api_key'])
@pytest.mark.parametrize('role', [None, 'viewer', 'security_analyst', 'tenant_admin'])
@pytest.mark.parametrize('method,path,body', [('GET', path, None) for path in READ_PATHS] + WRITE_ROUTES)
def test_platform_tools_reject_non_platform_roles(client, role, auth_method, method, path, body):
    response = client.request(method, path, headers=authenticate(client, role, auth_method), json=body)
    assert response.status_code == (401 if role is None else 403), response.text


@pytest.mark.parametrize('auth_method', ['session', 'api_key'])
@pytest.mark.parametrize('role', [None, 'viewer', 'security_analyst'])
@pytest.mark.parametrize('method,path,body', SCAN_ROUTES)
def test_scan_controls_require_tenant_admin(client, role, auth_method, method, path, body):
    response = client.request(method, path, headers=authenticate(client, role, auth_method), json=body)
    assert response.status_code == (401 if role is None else 403), response.text


@pytest.mark.parametrize('auth_method', ['session', 'api_key'])
@pytest.mark.parametrize('role', ['tenant_admin', 'platform_admin'])
@pytest.mark.parametrize('org_db', ['tenant_a', 'tenant_b'])
def test_scan_controls_use_authenticated_organization(client, monkeypatch, role, auth_method, org_db):
    monkeypatch.setattr(webapp, 'authenticate_api_key', lambda token: {
        'org_id': 7, 'org_db_name': org_db, 'role': role,
    })
    headers = authenticate(client, role, auth_method, org_db)
    calls = []
    monkeypatch.setattr(webapp, '_queue_scan', lambda org, body, **kw: calls.append(org) or 42)
    monkeypatch.setattr(webapp, 'get_scan_schedules', lambda org: [{'organization': org}])
    monkeypatch.setattr(webapp, 'get_scan_record', lambda org, scan_id: calls.append(org))
    monkeypatch.setattr(webapp, 'get_scan_schedule', lambda org, scan_id: calls.append(org))
    monkeypatch.setattr(webapp, 'set_scan_schedule_enabled', lambda org, *args: calls.append(org) or False)
    monkeypatch.setattr(webapp, 'delete_scan_schedule', lambda org, *args: calls.append(org) or False)
    response = client.post('/api/scans/start', headers=headers, json={'targets': '192.0.2.1', 'scanner': 'nuclei'})
    assert response.status_code == 200
    assert client.get('/api/schedules', headers=headers).json()['items'] == [{'organization': org_db}]
    for method, path, body in [
        ('POST', '/api/scans/99/stop', {}), ('POST', '/api/schedules/99/run', {}),
        ('PATCH', '/api/schedules/99', {'enabled': True}), ('DELETE', '/api/schedules/99', None),
    ]:
        assert client.request(method, path, headers=headers, json=body).status_code == 404
    assert calls == [org_db] * 5


@pytest.mark.parametrize('auth_method', ['session', 'api_key'])
def test_tenant_admin_can_read_scanner_catalog(client, monkeypatch, auth_method):
    headers = authenticate(client, 'tenant_admin', auth_method)
    monkeypatch.setattr(webapp, 'list_available_scanner_nodes', lambda: [{'node_id': 'node-a', 'name': 'Scanner'}])
    monkeypatch.setattr(webapp, 'get_scanner_node_record', lambda node: {'capabilities': ['*']})
    profiles = [{'scanner': 'openvas', 'id': 'full-fast', 'name': 'Full and fast'}]
    monkeypatch.setattr(webapp, 'get_scanner_profiles', lambda node: {'items': profiles, 'updated_at': None})
    assert client.get('/api/scanner-nodes/available', headers=headers).status_code == 200
    assert client.get('/api/scanner-nodes/node-a/profiles', headers=headers).json()['items'] == profiles


@pytest.mark.parametrize('auth_method', ['session', 'api_key'])
def test_platform_admin_can_use_each_area(client, monkeypatch, auth_method):
    headers = authenticate(client, 'platform_admin', auth_method)
    monkeypatch.setattr(webapp, 'get_endpoint_overview', lambda *a, **kw: {'agents': 1})
    monkeypatch.setattr(webapp, 'get_m365_graph_settings', lambda org: {'enabled': False})
    monkeypatch.setattr(webapp, '_queue_scan', lambda *a, **kw: 42)
    assert client.get('/api/endpoints/overview', headers=headers).json() == {'agents': 1}
    assert client.get('/api/integrations/m365/settings', headers=headers).status_code == 200
    assert client.get('/documentation', headers=headers).status_code == 200
    assert client.get('/docs', headers=headers).status_code == 200
    assert client.get('/redoc', headers=headers).status_code == 200
    schema = client.get('/openapi.json', headers=headers)
    assert schema.status_code == 200 and '/api/scans/start' in schema.json()['paths']
    response = client.post('/api/scans/start', headers=headers, json={'targets': '192.0.2.1', 'scanner': 'openvas'})
    assert response.status_code == 200 and response.json()['scan_id'] == 42


@pytest.mark.parametrize('auth_method', ['session', 'api_key'])
@pytest.mark.parametrize('role', [None, 'viewer', 'security_analyst'])
@pytest.mark.parametrize('path', ['/api/scans/1', '/api/scans/1/logs'])
def test_scan_debug_requires_tenant_admin(client, role, auth_method, path):
    response = client.get(path, headers=authenticate(client, role, auth_method))
    assert response.status_code == (401 if role is None else 403), response.text


@pytest.mark.parametrize('auth_method', ['session', 'api_key'])
@pytest.mark.parametrize('role', [None, 'viewer', 'security_analyst'])
def test_debug_stream_requires_tenant_admin(client, role, auth_method):
    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect('/ws/scan/1', headers=authenticate(client, role, auth_method)):
            pytest.fail('Non-admin connected to the debug stream')
    assert error.value.code == 1008


@pytest.mark.parametrize('auth_method', ['session', 'api_key'])
@pytest.mark.parametrize('role', ['tenant_admin', 'platform_admin'])
def test_admins_can_read_their_tenant_scan_debug(client, monkeypatch, role, auth_method):
    headers = authenticate(client, role, auth_method)
    scan = {'id': 1, 'scan_mode': 'quick'}
    logs = [{'message': 'Scan completed'}]

    def scan_record(org_db, scan_id):
        assert org_db == 'tenant_a'
        return scan if scan_id == 1 else None

    def scan_logs(org_db, scan_id, limit):
        assert (org_db, scan_id) == ('tenant_a', 1)
        return logs

    monkeypatch.setattr(webapp, 'get_scan_record', scan_record)
    monkeypatch.setattr(webapp, 'get_scan_logs', scan_logs)
    monkeypatch.setattr(webapp, 'get_scanner_job_for_scan', lambda org, scan_id: None)
    response = client.get('/api/scans/1', headers=headers)
    assert response.status_code == 200 and response.json()['logs'] == logs
    assert client.get('/api/scans/1/logs', headers=headers).json() == {'items': logs}
    assert client.get('/api/scans/2', headers=headers).status_code == 404
    with client.websocket_connect('/ws/scan/1', headers=headers) as socket:
        socket.send_text('ping')
    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect('/ws/scan/2', headers=headers):
            pytest.fail('Connected to a scan outside the current tenant')
    assert error.value.code == 1008


@pytest.mark.parametrize('auth_method', ['session', 'api_key'])
@pytest.mark.parametrize('role', ['viewer', 'security_analyst', 'tenant_admin', 'platform_admin'])
def test_scan_history_remains_readable(client, monkeypatch, role, auth_method):
    def scan_history(org_db, limit):
        assert org_db == 'tenant_a'
        return [{'id': 1, 'status': 'failed', 'error_message': 'Scanner execution output'}]

    monkeypatch.setattr(webapp, 'get_scan_history', scan_history)
    response = client.get('/api/scans', headers=authenticate(client, role, auth_method))
    assert response.status_code == 200 and response.json()['items'][0]['id'] == 1
    scan = response.json()['items'][0]
    assert scan['status'] == 'failed'
    if role in ['tenant_admin', 'platform_admin']:
        assert scan['error_message'] == 'Scanner execution output'
    else:
        assert 'error_message' not in scan
