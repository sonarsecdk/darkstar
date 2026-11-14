"""Multi-appliance transactions against disposable MariaDB, without executing scanners."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
import json
import os
import socket
import threading
import uuid

import mysql.connector
import pytest

from darkstar.core import asset_inventory, db_helper as db, scan_scope


@pytest.fixture
def database(monkeypatch):
    host = os.environ.get("DARKSTAR_TEST_DB_HOST")
    password = os.environ.get("DARKSTAR_TEST_DB_PASSWORD")
    if not host or not password:
        pytest.skip("Set DARKSTAR_TEST_DB_HOST/PASSWORD for MariaDB integration tests")
    for key, value in {"DB_HOST": host, "DB_USER": "root", "DB_PASSWORD": password, "DB_NAME": "feature_tests"}.items():
        monkeypatch.setenv(key, value)
    org = db.create_organization("batch_test_" + uuid.uuid4().hex[:12])["org_db_name"]
    org_id = db.get_organization_id(org)
    nodes = []
    try:
        db.replace_allowed_scan_targets(org, ["192.0.2.0/24"], actor="platform-test", expected_org_id=org_id)
        for name in ("Network appliance", "Web appliance"):
            nodes.append(db.create_scanner_node(name, capabilities=["openvas", "zap"]))
        yield org, org_id, nodes
    finally:
        for scan in db.get_scan_history(org):
            job = db.get_scanner_job_for_scan(org, scan["id"])
            if job and job.get("locked_by_node_id"):
                db.complete_scanner_job(job["id"], job["locked_by_node_id"], "stopped")
            elif job:
                db.cancel_queued_scanner_job(org, scan["id"])
            db.update_scan_status(org, scan["id"], "stopped")
        db.delete_organization(org_id, active_org_db="feature_tests")
        for node in nodes:
            db.revoke_scanner_node(node["node_id"])
            db.delete_revoked_scanner_node(node["node_id"])


def plans_for(nodes, scanners=("openvas", "zap")):
    plans = []
    for node, scanner in zip(nodes, scanners):
        selections = [{"scanner": scanner, "profile_id": "default", "profile_name": "Default policy",
                       "targets": "https://192.0.2.1:8443/admin" if scanner == "zap" else "192.0.2.1"}]
        plans.append({"node_id": node["node_id"], "node_name": node["name"],
                      "scan_name": node["name"] + ": test", "targets": "192.0.2.1", "scanner": scanner,
                      "scan_mode": "selection", "components": selections,
                      "payload": {"targets": "192.0.2.1", "mode": None, "scanner": None,
                                  "preferred_node_id": node["node_id"], "selections": selections}})
    return plans


def counts(org):
    with db.DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM scanner_jobs WHERE org_db_name = %s", (org,))
        result = {"jobs": cursor.fetchone()[0]}
        db._use_org_database(cursor, org)
        for table in ("scans", "scan_components", "scan_logs", "scan_schedules"):
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            result[table] = cursor.fetchone()[0]
        cursor.close()
    return result


def test_appliances_have_independent_jobs_targets_and_stop_status(database):
    org, org_id, nodes = database
    plans = plans_for(nodes)
    rows = db.create_scan_batch(org, plans, expected_org_id=org_id)
    assert len({row["scan_id"] for row in rows}) == 2
    assert counts(org) == {"jobs": 2, "scans": 2, "scan_components": 2, "scan_logs": 2, "scan_schedules": 0}
    for row, plan in zip(rows, plans):
        scan = db.get_scan_record(org, row["scan_id"])
        job = db.get_scanner_job_for_scan(org, row["scan_id"])
        assert scan["scan_name"] == row["scan_name"] == plan["scan_name"]
        assert scan["status"] == job["status"] == row["status"] == "queued"
        assert job["preferred_node_id"] == row["node_id"] == plan["node_id"]
        assert job["targets"] == "192.0.2.1"
        assert job["payload"]["selections"] == plan["components"]
        assert db.get_scan_components(org, row["scan_id"])[0]["profile_id"] == "default"

    first = db.claim_next_scanner_job(nodes[0]["node_id"], ["openvas", "zap"])
    second = db.claim_next_scanner_job(nodes[1]["node_id"], ["openvas", "zap"])
    assert [first["scan_id"], second["scan_id"]] == [row["scan_id"] for row in rows]
    db.request_scanner_job_stop(org, first["scan_id"])
    db.complete_scanner_job(first["id"], nodes[0]["node_id"], "completed")
    assert db.get_scan_record(org, first["scan_id"])["status"] == "stopped"
    assert db.get_scan_record(org, second["scan_id"])["status"] == "running"
    db.update_scan_component(org, second["scan_id"], "zap", "completed")
    db.complete_scanner_job(second["id"], nodes[1]["node_id"], "completed")
    assert db.get_scan_record(org, second["scan_id"])["status"] == "completed"


def test_same_scanner_on_two_appliances_is_allowed_but_active_duplicate_is_not(database):
    org, org_id, nodes = database
    plans = plans_for(nodes, ("openvas", "openvas"))
    rows = db.create_scan_batch(org, plans, expected_org_id=org_id)
    assert [db.get_scan_components(org, row["scan_id"])[0]["scanner"] for row in rows] == ["openvas", "openvas"]
    with pytest.raises(db.OrganizationConflictError, match="identical scan"):
        db.create_scan_batch(org, list(reversed(plans)), expected_org_id=org_id)
    assert counts(org)["scans"] == 2
    for row in rows:
        db.cancel_queued_scanner_job(org, row["scan_id"])
    assert len(db.create_scan_batch(org, plans, expected_org_id=org_id)) == 2


@pytest.mark.parametrize("change", ["unapproved", "resolved_unapproved", "engine_restricted", "revoked", "unsupported"])
def test_changed_second_selection_rejects_the_whole_batch(database, change):
    org, org_id, nodes = database
    plans = plans_for(nodes)
    if change == "unapproved":
        plans[1]["targets"] = "198.51.100.1"
    elif change == "resolved_unapproved":
        plans[1]["payload"]["selections"][0]["targets"] = "https://198.51.100.1:8443/"
    elif change == "engine_restricted":
        asset_inventory.update_asset_scanners(org, "192.0.2.0/24", ["openvas"], "platform-test", org_id)
    elif change == "revoked":
        db.revoke_scanner_node(nodes[1]["node_id"])
    else:
        db.heartbeat_scanner_node(nodes[1]["node_id"], capabilities=["openvas"])
    with pytest.raises(ValueError):
        db.create_scan_batch(org, plans, expected_org_id=org_id)
    with pytest.raises(ValueError):
        db.create_scan_schedule_batch(org, plans, {"interval_minutes": 60}, expected_org_id=org_id)
    assert not any(counts(org).values())


def test_changed_dns_address_is_rechecked_before_either_scan_is_queued(database, monkeypatch):
    org, org_id, nodes = database
    db.replace_allowed_scan_targets(org, ["192.0.2.0/24", "app.example.test"],
                                    actor="platform-test", expected_org_id=org_id)
    monkeypatch.setattr(scan_scope.socket, "getaddrinfo", lambda *args, **kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.51.100.1", 0)),
    ])
    plans = plans_for(nodes)
    plans[1]["targets"] = "app.example.test"
    plans[1]["payload"]["selections"][0]["targets"] = "https://app.example.test:8443/admin"
    with pytest.raises(scan_scope.ScanScopeError, match="198.51.100.1"):
        db.create_scan_batch(org, plans, expected_org_id=org_id)
    assert not any(counts(org).values())


def test_existing_second_appliance_scan_does_not_queue_the_first_appliance(database):
    org, org_id, nodes = database
    plans = plans_for(nodes)
    existing = db.create_scan_batch(org, plans[1:], expected_org_id=org_id)
    with pytest.raises(db.OrganizationConflictError, match=f"scan {existing[0]['scan_id']}"):
        db.create_scan_batch(org, plans, expected_org_id=org_id)
    assert counts(org)["scans"] == counts(org)["jobs"] == 1


def test_stale_tenant_cannot_launch_or_create_schedules(database):
    org, _, nodes = database
    plans = plans_for(nodes)
    with pytest.raises(db.OrganizationConflictError, match="no longer available"):
        db.create_scan_batch(org, plans, expected_org_id=-1)
    with pytest.raises(db.OrganizationConflictError, match="no longer available"):
        db.create_scan_schedule_batch(org, plans, {"interval_minutes": 60}, expected_org_id=-1)
    assert not any(counts(org).values())


def test_second_insert_failure_rolls_back_all_tables_and_uncommitted_jobs_are_invisible(database, monkeypatch):
    org, org_id, nodes = database
    plans = plans_for(nodes)
    plans[1]["scan_name"] = "Reject this child"
    with db.DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        cursor_type = type(cursor)
        db._use_org_database(cursor, org)
        cursor.execute("""CREATE TRIGGER reject_second_scan BEFORE INSERT ON scans FOR EACH ROW
                          BEGIN IF NEW.scan_name = 'Reject this child' THEN
                              SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Second scan rejected';
                          END IF; END""")
        cursor.close()
    original_execute = cursor_type.execute
    observed = []

    def execute(cursor, operation, *args, **kwargs):
        result = original_execute(cursor, operation, *args, **kwargs)
        if isinstance(operation, bytes):
            operation = operation.decode()
        if operation.lstrip().startswith("INSERT INTO `feature_tests`.scanner_jobs"):
            # Another connection, like a worker, sees none of this transaction yet.
            observed.append(counts(org))
        return result

    with monkeypatch.context() as patch:
        patch.setattr(cursor_type, "execute", execute)
        with pytest.raises(mysql.connector.Error, match="Second scan rejected"):
            db.create_scan_batch(org, plans, expected_org_id=org_id)
    assert len(observed) == 1
    assert not any(observed[0].values())
    assert not any(counts(org).values())


def test_concurrent_identical_batches_create_only_one_pair(database):
    org, org_id, nodes = database
    plans = plans_for(nodes)
    ready = threading.Barrier(2)

    def launch():
        ready.wait(timeout=10)
        try:
            return db.create_scan_batch(org, plans, expected_org_id=org_id)
        except ValueError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: launch(), range(2)))
    assert sum(isinstance(result, list) for result in results) == 1
    assert any(isinstance(result, str) and "identical scan" in result for result in results)
    assert counts(org)["jobs"] == counts(org)["scans"] == 2


def test_schedules_keep_host_targets_and_profiles_with_identical_first_run(database):
    org, org_id, nodes = database
    plans = plans_for(nodes)
    start = (datetime.utcnow() + timedelta(days=1)).replace(microsecond=0)
    rows = db.create_scan_schedule_batch(org, plans, {"interval_minutes": 60, "start_at": start.isoformat(),
                                                   "bruteforce": True, "bruteforce_timeout": 450}, expected_org_id=org_id)
    assert len({row["schedule_id"] for row in rows}) == 2
    for row, plan in zip(rows, plans):
        schedule = db.get_scan_schedule(org, row["schedule_id"])
        assert schedule["preferred_node_id"] == plan["node_id"]
        assert schedule["targets"] == "192.0.2.1"
        assert schedule["scan_mode"] == "selection" and schedule["scanner"] is None
        assert schedule["next_run_at"] == schedule["start_at"] == start
        assert schedule["bruteforce"] and schedule["bruteforce_timeout"] == 450
        assert json.loads(schedule["selections_json"]) == [{"scanner": plan["scanner"], "profile_id": "default"}]
    assert counts(org) == {"jobs": 0, "scans": 0, "scan_components": 0, "scan_logs": 0, "scan_schedules": 2}


def test_schedule_batch_rolls_back_if_second_insert_fails(database):
    org, org_id, nodes = database
    plans = plans_for(nodes)
    plans[1]["scan_name"] = "Reject this child"
    with db.DatabaseConnectionManager() as connection:
        cursor = connection.cursor()
        db._use_org_database(cursor, org)
        cursor.execute("""CREATE TRIGGER reject_second_schedule BEFORE INSERT ON scan_schedules FOR EACH ROW
                          BEGIN IF NEW.scan_name = 'Reject this child' THEN
                              SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Second schedule rejected';
                          END IF; END""")
        cursor.close()
    with pytest.raises(mysql.connector.Error, match="Second schedule rejected"):
        db.create_scan_schedule_batch(org, plans, {"interval_minutes": 60}, expected_org_id=org_id)
    assert not any(counts(org).values())
