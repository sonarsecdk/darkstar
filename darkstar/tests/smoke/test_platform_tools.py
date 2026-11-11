"""Platform tools reject tenant sessions and API keys before reading or writing data."""
import base64
import json

import pytest
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner

from darkstar import webapp


READ_PATHS = [
    '/documentation', '/docs', '/redoc', '/openapi.json',
    '/api/endpoints/overview', '/api/endpoints/enrollment-tokens',
    '/api/endpoints/agents', '/api/endpoints/agents/agent-a',
    '/api/endpoints/network-map', '/api/endpoints/software',
    '/api/endpoints/vulnerabilities', '/api/endpoints/vulnerabilities/1',
    '/api/scanner-nodes', '/api/scanner-nodes/available', '/api/scanner-nodes/node-a/profiles',
    '/api/schedules', '/api/integrations/m365/settings', '/api/integrations/m365/secure-score',
]
WRITE_ROUTES = [
    ('POST', '/api/scans/start', {'targets': '192.0.2.1', 'scanner': 'openvas'}),
    ('POST', '/api/scans/1/stop', {}),
    ('POST', '/api/schedules', {'targets': '192.0.2.1', 'scanner': 'openvas'}),
    ('PATCH', '/api/schedules/1', {'enabled': False}),
    ('DELETE', '/api/schedules/1', None), ('POST', '/api/schedules/1/run', {}),
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


def authenticate(client, role, method):
    if role is None:
        return {}
    if method == 'api_key':
        return {'Authorization': f'Bearer {role}'}
    middleware = next(item for item in webapp.app.user_middleware if item.cls.__name__ == 'SessionMiddleware')
    signer = TimestampSigner(str(middleware.kwargs['secret_key']))
    session = {'org_db': 'tenant_a', 'org_id': 7, 'role': role}
    client.cookies.set('session', signer.sign(base64.b64encode(json.dumps(session).encode())).decode())
    return {}


@pytest.mark.parametrize('auth_method', ['session', 'api_key'])
@pytest.mark.parametrize('role', [None, 'viewer', 'security_analyst', 'tenant_admin'])
@pytest.mark.parametrize('method,path,body', [('GET', path, None) for path in READ_PATHS] + WRITE_ROUTES)
def test_platform_tools_reject_non_platform_roles(client, role, auth_method, method, path, body):
    response = client.request(method, path, headers=authenticate(client, role, auth_method), json=body)
    assert response.status_code == (401 if role is None else 403), response.text


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
