import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from darkstar.scanner_worker import ScannerWorker


@pytest.mark.parametrize('stopping', [False, True])
def test_discovery_upload_and_cancel_between_process_and_upload(monkeypatch, stopping):
    worker = ScannerWorker('http://orchestrator.test', 'token', 'worker', ['discovery'])
    job = {'id': 1, 'targets': '192.0.2.1', 'org_db_name': 'tenant_db',
           'payload': {'job_type': 'discovery', 'discovery': {'seeds': []}}}
    rows = [{'target': '192.0.2.1', 'addresses': ['192.0.2.1'], 'services': [], 'error': None}]
    def run(job, command):
        assert command[1:3] == ['-m', 'darkstar.asset_discovery']
        path = Path(command[command.index('--input') + 1])
        assert json.loads(path.read_text()) == job['payload']['discovery']
        Path(command[command.index('--output') + 1]).write_text(json.dumps(rows))
        return 'completed', None
    monkeypatch.setattr(worker, '_run_process', run)
    monkeypatch.setattr(worker, '_api', Mock(return_value={'stop_requested': stopping}))
    status, error = worker._run_discovery(job)
    assert status == ('stopped' if stopping else 'completed')
    worker._api.assert_called_once_with('POST', '/api/scanner-workers/jobs/1/discovery-results', json={'items': rows})


def test_combined_scan_uses_engine_specific_targets(monkeypatch):
    worker = ScannerWorker('http://orchestrator.test', 'token', 'worker', ['zap'])
    monkeypatch.setattr('darkstar.scanner_worker.discover_scanner_profiles', lambda: [{'scanner': 'zap', 'id': 'default'}])
    worker.send_logs = Mock(return_value=False)
    worker.component_status = Mock(return_value=False)
    worker.complete = Mock()
    worker._run_process = Mock(return_value=('completed', None))
    worker.run_job({'id': 3, 'targets': '192.0.2.1', 'org_db_name': 'tenant_db', 'payload': {
        'targets': '192.0.2.1', 'selections': [{'scanner': 'zap', 'profile_id': 'default', 'targets': 'http://192.0.2.1:3000/'}],
    }})
    assert worker._run_process.call_args.args[0]['payload']['targets'] == 'http://192.0.2.1:3000/'
