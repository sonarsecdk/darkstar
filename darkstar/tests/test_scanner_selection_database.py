"""Combined scans against a disposable MariaDB server, with no scanner execution."""
import json
import os
import uuid

import pytest

from darkstar.core import db_helper as db


@pytest.fixture
def database(monkeypatch):
    host = os.environ.get('DARKSTAR_TEST_DB_HOST')
    password = os.environ.get('DARKSTAR_TEST_DB_PASSWORD')
    if not host or not password:
        pytest.skip('Set DARKSTAR_TEST_DB_HOST/PASSWORD for MariaDB integration tests')
    for key, value in {'DB_HOST': host, 'DB_USER': 'root', 'DB_PASSWORD': password, 'DB_NAME': 'feature_tests'}.items():
        monkeypatch.setenv(key, value)
    names = []
    node = None
    try:
        for _ in range(2):
            names.append(db.create_organization('selection_test_' + uuid.uuid4().hex[:12])['org_db_name'])
        node = db.create_scanner_node('selection-test-' + uuid.uuid4().hex[:10], capabilities=['openvas', 'zap'])
        yield names, node
    finally:
        for org in names:
            for scan in db.get_scan_history(org):
                job = db.get_scanner_job_for_scan(org, scan['id'])
                if job and job.get('locked_by_node_id'):
                    db.complete_scanner_job(job['id'], job['locked_by_node_id'], 'stopped')
                elif job:
                    db.cancel_queued_scanner_job(org, scan['id'])
                db.update_scan_status(org, scan['id'], 'stopped')
            db.delete_organization(db.get_organization_id(org), active_org_db='feature_tests')
        if node:
            db.revoke_scanner_node(node['node_id'])
            db.delete_revoked_scanner_node(node['node_id'])


SELECTIONS = [
    {'scanner': 'openvas', 'profile_id': 'config-network', 'profile_name': 'Network scan'},
    {'scanner': 'zap', 'profile_id': 'default', 'profile_name': 'Recon'},
]


def test_profiles_queue_component_statuses_and_tenant_isolation(database):
    (org, other), node = database
    catalog = [{'scanner': item['scanner'], 'id': item['profile_id'], 'name': item['profile_name']} for item in SELECTIONS]
    db.update_scanner_profiles(node['node_id'], catalog)
    assert db.get_scanner_profiles(node['node_id'])['items'] == catalog
    assert db.get_scanner_profiles(node['node_id'])['updated_at']
    scan_id = db.create_scan_record(org, 'Combined', 'selection', '192.0.2.1')
    db.create_scan_components(org, scan_id, SELECTIONS)
    job_id = db.enqueue_scanner_job(org, scan_id, 'Combined', 'selection', '192.0.2.1', {'selections': SELECTIONS}, scanner='openvas', preferred_node_id=node['node_id'])
    job = db.claim_next_scanner_job(node['node_id'], ['openvas', 'zap'])
    assert job['id'] == job_id
    assert job['payload']['selections'] == SELECTIONS
    assert not db.get_scan_components(other, scan_id)
    assert db.update_scan_component(org, scan_id, 'openvas', 'running')
    assert db.update_scan_component(org, scan_id, 'openvas', 'failed', 'Unavailable')
    assert db.update_scan_component(org, scan_id, 'zap', 'running')
    assert db.update_scan_component(org, scan_id, 'zap', 'completed')
    db.complete_scanner_job(job_id, node['node_id'], 'failed', 'Failed scanners: openvas')
    components = db.get_scan_components(org, scan_id)
    assert [(item['scanner'], item['status']) for item in components] == [('openvas', 'failed'), ('zap', 'completed')]
    assert all(item['started_at'] and item['finished_at'] for item in components)
    assert db.get_scan_record(org, scan_id)['status'] == 'failed'


def test_schedules_keep_selections_and_queued_cancel_stops_components(database):
    (org, _), node = database
    schedule_id = db.create_scan_schedule(org, 'Recurring combined', '192.0.2.1', 'selection', None, 60, preferred_node_id=node['node_id'], selections=SELECTIONS)
    assert json.loads(db.get_scan_schedule(org, schedule_id)['selections_json']) == SELECTIONS
    assert json.loads(db.get_scan_schedules(org)[0]['selections_json']) == SELECTIONS
    with db.DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        db._use_org_database(cursor, org)
        cursor.execute('UPDATE scan_schedules SET next_run_at = UTC_TIMESTAMP() - INTERVAL 1 SECOND WHERE id = %s', (schedule_id,))
        connection.commit()
        cursor.close()
    assert json.loads(db.get_due_scan_schedules(org)[0]['selections_json']) == SELECTIONS
    scan_id = db.create_scan_record(org, 'Combined', 'selection', '192.0.2.1')
    db.create_scan_components(org, scan_id, SELECTIONS)
    db.enqueue_scanner_job(org, scan_id, 'Combined', 'selection', '192.0.2.1', {'selections': SELECTIONS}, scanner='openvas', preferred_node_id=node['node_id'])
    assert db.cancel_queued_scanner_job(org, scan_id)
    assert {item['status'] for item in db.get_scan_components(org, scan_id)} == {'stopped'}
