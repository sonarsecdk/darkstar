"""Profile discovery, queue validation, and combined scan execution without scanning."""
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from unittest.mock import Mock

import pytest
import requests
from fastapi import HTTPException
from fastapi.testclient import TestClient

from darkstar import scanner_profiles as profiles, scanner_worker, webapp
from scanners.external_vuln import ZAPScanner


CATALOG = [
    {"scanner": "openvas", "id": "config-network", "name": "Network scan"},
    {"scanner": "zap", "id": "default", "name": "Recon"},
]
SELECTIONS = [{"scanner": item["scanner"], "profile_id": item["id"]} for item in CATALOG]


@pytest.fixture
def catalog(monkeypatch):
    monkeypatch.setattr(webapp, "get_allowed_scan_targets", lambda org: [{"target": "192.0.2.1"}])
    monkeypatch.setattr(webapp, "get_scanner_node_record", lambda node: {"node_id": node, "capabilities": ["*"]})
    monkeypatch.setattr(webapp, "get_scanner_profiles", lambda node: {"items": CATALOG, "updated_at": "2026-10-22T12:00:00"})


def test_profiles_are_discovered_from_installed_files_and_openvas(monkeypatch, tmp_path):
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "sample.yaml").write_text("id: sample")
    outside = tmp_path / "outside.yaml"
    outside.write_text("id: outside")
    (templates / "escape.yaml").symlink_to(outside)
    policies = tmp_path / "policies"
    policies.mkdir()
    (policies / "custom.policy").write_text('<configuration><policy>Custom &amp; test</policy></configuration>')
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(templates))
    monkeypatch.setenv("ZAP_POLICY_DIR", str(policies))
    monkeypatch.setattr(profiles.shutil, "which", lambda binary: "/bin/" + binary if binary in {"nuclei", "zap.sh"} else None)
    response = Mock()
    response.json.return_value = [{"id": "config-network", "name": "Network scan"}]
    monkeypatch.setattr(profiles.requests, "get", lambda *a, **k: response)
    items = profiles.discover_scanner_profiles()
    assert {item["id"] for item in items if item["scanner"] == "nuclei"} == {"default", "sample.yaml"}
    assert {item["id"] for item in items if item["scanner"] == "zap"} == {"default", "custom.policy"}
    assert CATALOG[0] in items
    with pytest.raises(ValueError):
        profiles.profile_file(templates, "escape.yaml", {".yaml"})
    with pytest.raises(ValueError):
        profiles.profile_file(templates, "../outside.yaml", {".yaml"})


def test_unavailable_openvas_does_not_advertise_profiles(monkeypatch):
    monkeypatch.setattr(profiles.shutil, "which", lambda binary: None)
    monkeypatch.setattr(profiles.requests, "get", Mock(side_effect=requests.ConnectionError()))
    assert profiles.discover_scanner_profiles() == []


def test_large_installed_catalog_keeps_openvas_profiles():
    templates = [{"scanner": "nuclei", "id": f"http/template-{i}.yaml", "name": f"Template {i}"} for i in range(100000)]
    catalog = webapp.ScannerCatalogRequest(items=templates + CATALOG)
    assert len(catalog.items) == 100002
    assert catalog.items[-2].scanner == "openvas"
    assert catalog.items[-2].id == "config-network"


def test_catalog_failure_does_not_block_claims_and_retries_later(monkeypatch):
    worker = scanner_worker.ScannerWorker("http://orchestrator.test", "test-token", "test", ["*"])
    discover = Mock(return_value=CATALOG)
    monkeypatch.setattr(scanner_worker, "discover_scanner_profiles", discover)
    clock = Mock(return_value=1000)
    monkeypatch.setattr(scanner_worker.time, "monotonic", clock)
    monkeypatch.setattr(scanner_worker.time, "sleep", lambda seconds: None)
    worker.heartbeat = Mock()
    worker._api = Mock(side_effect=requests.HTTPError("Catalog rejected"))
    def claim():
        worker.stop_event.set()
        return None
    worker.claim = Mock(side_effect=claim)
    worker.run_forever()
    worker.claim.assert_called_once()
    worker._api.assert_called_once()
    clock.return_value = 1299
    worker.report_profiles()
    assert discover.call_count == 1
    clock.return_value = 1300
    worker._api.side_effect = None
    worker.report_profiles()
    assert discover.call_count == 2


@pytest.mark.parametrize("changes,message", [
    ({"preferred_node_id": None}, "Choose an appliance"),
    ({"mode": 2}, "Choose one"),
    ({"scanner": "zap"}, "Choose one"),
    ({"selections": [SELECTIONS[0], SELECTIONS[0]]}, "one profile per scanner"),
    ({"selections": [{"scanner": "openvas", "profile_id": "removed"}]}, "not installed"),
    ({"selections": [{"scanner": "unknown", "profile_id": "default"}]}, "Unsupported scanner"),
])
def test_selection_validation(catalog, changes, message):
    body = dict(targets="192.0.2.1", preferred_node_id="node-a", selections=SELECTIONS)
    body.update(changes)
    with pytest.raises(HTTPException, match=message):
        webapp._validate_scan_payload(webapp.ScanStartRequest(**body))


def test_selected_scanners_must_all_be_allowed_by_node_capabilities(catalog, monkeypatch):
    monkeypatch.setattr(webapp, "get_scanner_node_record", lambda node: {"capabilities": ["scanner:openvas"]})
    with pytest.raises(HTTPException, match="does not support zap"):
        webapp._validate_scan_payload(webapp.ScanStartRequest(targets="192.0.2.1", preferred_node_id="node-a", selections=SELECTIONS))


@pytest.fixture
def api(catalog, monkeypatch):
    monkeypatch.setattr(webapp, "scheduler_started", True)
    monkeypatch.setattr(webapp, "list_organizations", list)
    monkeypatch.setattr(webapp, "authenticate_api_key", lambda token: {"org_id": 7, "org_db_name": "tenant_db", "org_name": "Test", "role": token} if token in {"viewer", "security_analyst", "platform_admin"} else None)
    with TestClient(webapp.app) as client:
        yield client


def test_catalog_search_and_access(api):
    assert api.get('/api/scanner-nodes/node-a/profiles').status_code == 401
    assert api.get('/api/scanner-nodes/node-a/profiles', headers={"Authorization": "Bearer viewer"}).status_code == 403
    response = api.get('/api/scanner-nodes/node-a/profiles?scanner=openvas&search=network&limit=1', headers={"Authorization": "Bearer security_analyst"})
    assert response.status_code == 200
    assert response.json()["items"] == [CATALOG[0]]
    assert response.json()["scanners"] == ["openvas", "zap"]


def test_queue_keeps_individual_profiles_and_names(catalog, monkeypatch):
    monkeypatch.setattr(webapp, "get_scan_history", lambda *a, **k: [])
    monkeypatch.setattr(webapp, "create_scan_record", Mock(return_value=42))
    components = Mock()
    enqueue = Mock()
    monkeypatch.setattr(webapp, "create_scan_components", components)
    monkeypatch.setattr(webapp, "enqueue_scanner_job", enqueue)
    monkeypatch.setattr(webapp, "insert_scan_log", Mock())
    body = webapp.ScanStartRequest(targets="192.0.2.1", preferred_node_id="node-a", selections=SELECTIONS)
    assert webapp._queue_scan("tenant_db", body) == 42
    payload = enqueue.call_args.kwargs["payload"]
    assert payload["mode"] is None and payload["scanner"] is None
    assert payload["selections"] == [dict(item, profile_name=profile["name"]) for item, profile in zip(SELECTIONS, CATALOG)]
    components.assert_called_once_with("tenant_db", 42, payload["selections"])
    assert enqueue.call_args.kwargs["preferred_node_id"] == "node-a"


def worker_fixture(monkeypatch):
    worker = scanner_worker.ScannerWorker("http://test", "token", "node-a", ["*"])
    worker.send_logs = Mock(return_value=False)
    worker.complete = Mock()
    worker.component_status = Mock(return_value=False)
    monkeypatch.setattr(scanner_worker, "discover_scanner_profiles", lambda: CATALOG)
    return worker


def test_worker_continues_after_first_scanner_failure(monkeypatch):
    worker = worker_fixture(monkeypatch)
    worker._run_process = Mock(side_effect=[("failed", "OpenVAS unavailable"), ("completed", None)])
    job = {"id": 42, "org_db_name": "tenant_db", "targets": "192.0.2.1", "payload": {"selections": SELECTIONS}}
    worker.active_threads[42] = object()
    worker.run_job(job)
    assert [call.args[0]["payload"]["scanner"] for call in worker._run_process.call_args_list] == ["openvas", "zap"]
    assert worker._run_process.call_args_list[0].args[0]["payload"]["profile_id"] == "config-network"
    worker.complete.assert_called_once_with(42, "failed", "Failed scanners: openvas")
    assert 42 not in worker.active_threads


def test_worker_stops_remaining_scanners(monkeypatch):
    worker = worker_fixture(monkeypatch)
    worker._run_process = Mock(return_value=("stopped", "Scan stopped by user"))
    worker.run_job({"id": 42, "payload": {"selections": SELECTIONS}})
    worker._run_process.assert_called_once()
    worker.component_status.assert_any_call(42, "zap", "stopped", "Scan stopped by user")
    worker.complete.assert_called_once_with(42, "stopped", "Scan stopped by user")


def test_missing_profile_fails_component_without_using_a_default(monkeypatch):
    worker = worker_fixture(monkeypatch)
    monkeypatch.setattr(scanner_worker, "discover_scanner_profiles", lambda: [CATALOG[1]])
    worker._run_process = Mock(return_value=("completed", None))
    worker.run_job({"id": 42, "payload": {"selections": SELECTIONS}})
    worker._run_process.assert_called_once()
    assert worker._run_process.call_args.args[0]["payload"]["scanner"] == "zap"
    worker.component_status.assert_any_call(42, "openvas", "failed", "Selected profile is no longer installed on this appliance")


def test_profile_is_passed_as_one_command_argument(monkeypatch):
    worker = worker_fixture(monkeypatch)
    command = worker.build_command({"targets": "192.0.2.1", "org_db_name": "tenant_db", "payload": {"scanner": "zap", "profile_id": "A & B.policy"}})
    assert command[command.index('--profile') + 1] == "A & B.policy"


def test_zap_recon_never_starts_active_scan(monkeypatch):
    scanner = ZAPScanner("https://example.test/?a=1&b=2", "org")
    calls = []
    def api(path):
        calls.append(path)
        if '/spider/action/' in path: return {"scan": "1"}
        if '/status/' in path: return {"status": "100"}
        if 'recordsToScan' in path: return {"recordsToScan": "0"}
        return {"alerts": []}
    scanner._zap_api = api
    assert scanner._scan_target(scanner.targets[0]) == []
    assert not any('/ascan/' in path for path in calls)
    assert parse_qs(urlsplit(calls[0]).query)['url'] == [scanner.targets[0]]


@pytest.mark.parametrize("assigned_name", ["custom2", "A & B"])
def test_zap_imports_and_executes_selected_active_policy(monkeypatch, tmp_path, assigned_name):
    (tmp_path / 'custom.policy').write_text('<configuration><policy>A &amp; B</policy></configuration>')
    monkeypatch.setenv('ZAP_POLICY_DIR', str(tmp_path))
    scanner = ZAPScanner('https://example.test', 'org', profile='custom.policy')
    scanner._start_daemon = Mock(return_value=True)
    scanner._stop_daemon = Mock()
    calls = []
    imported = False
    def api(path):
        nonlocal imported
        calls.append(path)
        if 'scanPolicyNames' in path:
            return {"scanPolicyNames": ['custom', assigned_name] if imported else ['custom']}
        if 'importScanPolicy' in path:
            import xml.etree.ElementTree as ET
            copy = Path(parse_qs(urlsplit(path).query)['path'][0])
            assert copy.stem.startswith('darkstar-')
            assert ET.parse(copy).getroot().findtext('policy') == copy.stem
            imported = True
            return {"Result": "OK"}
        if '/action/scan/' in path: return {"scan": "1"}
        if '/status/' in path: return {"status": "100"}
        if 'recordsToScan' in path: return {"recordsToScan": "0"}
        return {"alerts": []}
    scanner._zap_api = api
    scanner.run()
    active = next(path for path in calls if '/ascan/action/scan/' in path)
    assert parse_qs(urlsplit(active).query)['scanPolicyName'] == [assigned_name]
    assert any('importScanPolicy' in path for path in calls)
    scanner._stop_daemon.assert_called_once()
    assert (tmp_path / "custom.policy").read_text() == '<configuration><policy>A &amp; B</policy></configuration>'


def test_nuclei_executes_only_selected_template(monkeypatch, tmp_path):
    from scanners import nuclei
    template = tmp_path / 'chosen.yaml'
    template.write_text('id: chosen')
    targets = tmp_path / 'targets.txt'
    targets.write_text('192.0.2.1\n')
    monkeypatch.setenv('NUCLEI_TEMPLATES_DIR', str(tmp_path))
    monkeypatch.setattr(nuclei, '_select_nuclei_templates_dir', lambda configured: str(tmp_path))
    monkeypatch.setattr(nuclei, '_update_nuclei_templates_if_due', lambda directory: None)
    process = Mock()
    process.stdout.readline.return_value = ''
    process.poll.return_value = 0
    process.wait.return_value = 0
    popen = Mock(return_value=process)
    monkeypatch.setattr(nuclei.subprocess, 'Popen', popen)
    scanner = nuclei.NucleiScanner(str(targets), 'org', profile='chosen.yaml')
    scanner.scan_nuclei()
    command = popen.call_args.args[0]
    assert command[command.index('-t') + 1] == str(template)


@pytest.mark.asyncio
async def test_openvas_passes_selected_config_id(mocker):
    from openvas.openvas_connector import OpenVASAPIClient
    client = OpenVASAPIClient(base_url='http://test-openvas:8008')
    client._client = mocker.AsyncMock()
    client._client.post.return_value = Mock()
    await client.create_task('Selected policy', 'target-1', config_id='config-network')
    client._client.post.assert_awaited_once_with('/tasks', json={'name': 'Selected policy', 'target_id': 'target-1', 'config_id': 'config-network'})


def test_openvas_catalog_lists_all_configurations(mocker):
    from openvas_api import api
    gmp = Mock()
    gmp.get_scan_configs.return_value = '<get_configs_response status="200"><config id="one"><name>Network</name></config><config id="two"><name>Custom</name></config></get_configs_response>'
    assert api.scan_configs(gmp) == [{'id': 'one', 'name': 'Network'}, {'id': 'two', 'name': 'Custom'}]
    gmp.get_scan_configs.assert_called_once_with(filter_string='rows=-1')


def test_enqueue_failure_does_not_leave_scan_queued(catalog, monkeypatch):
    monkeypatch.setattr(webapp, 'get_scan_history', lambda *a, **k: [])
    monkeypatch.setattr(webapp, 'create_scan_record', Mock(return_value=42))
    monkeypatch.setattr(webapp, 'create_scan_components', Mock())
    monkeypatch.setattr(webapp, 'enqueue_scanner_job', Mock(side_effect=ValueError('Node unavailable')))
    status = Mock()
    monkeypatch.setattr(webapp, 'update_scan_status', status)
    body = webapp.ScanStartRequest(targets='192.0.2.1', preferred_node_id='node-a', selections=SELECTIONS)
    with pytest.raises(HTTPException, match='Node unavailable'):
        webapp._queue_scan('tenant_db', body)
    status.assert_called_once_with('tenant_db', 42, 'failed', error_message='Node unavailable')


def test_worker_cannot_update_another_nodes_component(api, monkeypatch):
    monkeypatch.setattr(webapp, 'authenticate_scanner_node', lambda token: {'node_id': 'node-a'} if token == 'worker-token' else None)
    monkeypatch.setattr(webapp, 'extend_scanner_job_lease', Mock(return_value=None))
    update = Mock()
    monkeypatch.setattr(webapp, 'update_scan_component', update)
    response = api.post('/api/scanner-workers/jobs/42/components/zap', headers={'Authorization': 'Bearer worker-token'}, json={'status': 'completed'})
    assert response.status_code == 404
    update.assert_not_called()
    assert api.post('/api/scanner-workers/profiles', json={'items': CATALOG}).status_code == 401


def test_zap_cleans_up_only_the_imported_policy(monkeypatch):
    scanner = ZAPScanner('https://example.test', 'org')
    scanner.policy_name = 'custom2'
    scanner._zap_api = Mock(return_value={'Result': 'OK'})
    import urllib.request
    monkeypatch.setattr(urllib.request, 'urlopen', Mock())
    monkeypatch.setattr('scanners.external_vuln.time.sleep', lambda seconds: None)
    scanner._stop_daemon()
    path = scanner._zap_api.call_args.args[0]
    assert 'removeScanPolicy' in path
    assert parse_qs(urlsplit(path).query)['scanPolicyName'] == ['custom2']
    assert scanner.policy_name is None


def test_zap_does_not_guess_an_imported_policy_name():
    scanner = ZAPScanner('https://example.test', 'org')
    scanner.profile = 'custom.policy'
    # Name discovery failure must not silently select the engine's default.
    scanner._zap_api = Mock(return_value={'code': 'error'})
    from unittest.mock import patch
    with patch('scanners.external_vuln.profile_file', return_value=Path('/tmp/custom.policy')):
        with pytest.raises(RuntimeError, match='could not list'):
            scanner._load_policy()
    assert scanner.policy_name is None
