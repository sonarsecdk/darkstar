"""Discovery observations and per-asset settings, separate from scan approval."""
from datetime import datetime
import hashlib
import ipaddress
import json
from urllib.parse import urlsplit

from . import db_helper as db
from .scan_scope import ScanScope, ScanScopeError, normalize_scope_entry, target_host


SCANNER_FAMILIES = {"openvas", "zap", "nuclei"}


def _scanner_names(scanners):
    if scanners is None:
        return None
    if not isinstance(scanners, list) or any(name not in SCANNER_FAMILIES for name in scanners):
        raise ValueError("Scanners must be openvas, zap, or nuclei")
    return sorted(set(scanners))


def _lock_tenant(cursor, org, expected_org_id=None, *, idle=False):
    organization = db._lock_organization(cursor, db.normalize_org_name(org))
    if not organization or (expected_org_id is not None and organization["id"] != expected_org_id):
        raise db.OrganizationConflictError("Organization is no longer available")
    db._use_org_database(cursor, org)
    if idle:
        cursor.execute("SELECT id FROM scans WHERE status IN ('queued', 'running', 'stopping') LIMIT 1")
        if cursor.fetchone():
            raise db.OrganizationConflictError("Stop active and queued scans before changing allowed targets or scanners")


def _audit(cursor, actor, action, metadata, *, scan_id=None):
    cursor.execute(
        """INSERT INTO audit_log (actor, action, entity_type, entity_id, metadata, created_at)
           VALUES (%s, %s, 'asset_inventory', %s, %s, %s)""",
        (actor, action, str(scan_id) if scan_id is not None else None, json.dumps(metadata), datetime.utcnow()),
    )


def _approved(scope, target):
    return target in scope.entries or scope.allows(target)


def _read_approvals(cursor):
    cursor.execute("SELECT target, approved_by, approved_at FROM allowed_scan_targets ORDER BY target")
    return cursor.fetchall() or []


def _read_rules(cursor, scope):
    cursor.execute("SELECT target, scanners_json FROM asset_scanner_settings ORDER BY target")
    return [{"target": row["target"], "enabled_scanners": json.loads(row["scanners_json"])}
            for row in cursor.fetchall() or [] if _approved(scope, row["target"])]


def get_asset_scanner_rules(org):
    """Return explicit scanner restrictions that still belong to approved scope."""
    with db.DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        db._use_org_database(cursor, org)
        scope = ScanScope([row["target"] for row in _read_approvals(cursor)])
        rules = _read_rules(cursor, scope)
        cursor.close()
    return rules


def list_asset_inventory(org, include_pending=False):
    """Combine observed hosts and approvals without turning observations into grants."""
    with db.DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        db._use_org_database(cursor, org)
        approvals = _read_approvals(cursor)
        scope = ScanScope([row["target"] for row in approvals])
        rules = _read_rules(cursor, scope)
        cursor.execute("SELECT * FROM asset_inventory ORDER BY target")
        observations = {row["target"]: row for row in cursor.fetchall() or []}
        cursor.close()

    approval_scopes = [(approval, ScanScope([approval["target"]])) for approval in approvals]
    rule_scopes = [(rule, ScanScope([rule["target"]])) for rule in rules]
    result = []
    for target in sorted(set(observations) | set(scope.entries)):
        approved = _approved(scope, target)
        if not approved and not include_pending:
            continue
        observation = observations.get(target, {})
        approval = next((row for row in approvals if row["target"] == target), None)
        if approval is None:
            approval = next((row for row, approved_scope in approval_scopes if approved_scope.allows(target)), {})
        addresses = json.loads(observation.get("addresses_json") or "[]")
        services = json.loads(observation.get("services_json") or "[]")
        compatible = [] if target.startswith("*.") or "/" in target else ["openvas"]
        if any(service.get("url") for service in services):
            compatible.extend(["zap", "nuclei"])
        matching_rules = [set(rule["enabled_scanners"]) for rule, rule_scope in rule_scopes
                          if any(_approved(rule_scope, host) for host in [target, *addresses])]
        result.append({
            "target": target, "approved": approved,
            "approved_by": approval.get("approved_by"), "approved_at": approval.get("approved_at"),
            "addresses": addresses,
            "services": services, "compatible_scanners": compatible,
            "enabled_scanners": sorted(set.intersection(*matching_rules)) if matching_rules else None,
            **{key: observation.get(key) for key in (
                "discovered_at", "last_attempt_at", "source_node_id", "error", "last_scan_id",
            )},
        })
    return result


def _normalize_observation(row):
    target = normalize_scope_entry(row["target"])
    if target.startswith("*.") or "/" in target:
        raise ValueError("Discovery observations must identify an individual IP or domain")
    addresses = sorted({str(ipaddress.ip_address(address)) for address in row.get("addresses", [])})
    services = {}
    for item in row.get("services", []):
        port = item["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("Invalid service port")
        if item.get("protocol", "tcp") != "tcp":
            raise ValueError("Only TCP service observations are supported")
        url = item.get("url") or None
        if url:
            parsed = urlsplit(url)
            if parsed.scheme not in {"http", "https"} or parsed.username is not None or parsed.password is not None:
                raise ValueError("Invalid web service URL")
            host = target_host(url)
            host = host if isinstance(host, str) else str(host.network_address)
            if host not in {target, *addresses} or (parsed.port or (443 if parsed.scheme == "https" else 80)) != port:
                raise ValueError("Service URL must match the observed host and port")
        service = str(item.get("service") or "unknown")[:128]
        services[(port, url or "")] = {"port": port, "protocol": "tcp", "service": service, "url": url}
    error = str(row["error"])[:4000] if row.get("error") else None
    return {"target": target, "addresses": addresses, "services": [services[key] for key in sorted(services)], "error": error}


def _refresh_services(target, previous, services, plan):
    """Replace only observations covered by this job's immutable probe plan."""
    if plan is None:
        return services
    seeds = [seed for seed in plan["seeds"] if seed["host"] == target]
    if not seeds:
        raise ValueError("Discovery result is outside the submitted target scope")
    whole_host = any(not seed.get("url") for seed in seeds)
    common_ports = set()
    if whole_host and plan["port_mode"] == "common":
        # Keep the probe list authoritative in the engine, without an import cycle.
        from ..asset_discovery import COMMON_PORTS
        common_ports = {int(port) for port in COMMON_PORTS.split(",")}
    urls = {seed["url"] for seed in seeds if seed.get("url")}
    url_ports = {urlsplit(url).port or (443 if urlsplit(url).scheme == "https" else 80) for url in urls}

    def covered(service):
        return (whole_host and (plan["port_mode"] == "full" or service["port"] in common_ports)
                or service.get("url") in urls
                or not service.get("url") and service["port"] in url_ports)

    if any(not covered(service) for service in services):
        raise ValueError("Discovery service is outside the submitted probe scope")
    merged = {(service["port"], service.get("url") or ""): service for service in previous if not covered(service)}
    merged.update({(service["port"], service.get("url") or ""): service for service in services})
    return [merged[key] for key in sorted(merged)]


def save_discovery_results(org, scan_id, node_id, rows, *, plan=None):
    """Upsert results; retries are harmless and failed attempts retain known services."""
    observations = {row["target"]: row for row in map(_normalize_observation, rows)}
    candidates = set()
    for row in list(observations.values()):
        for address in row["addresses"]:
            if address not in observations:
                candidates.add(address)
                observations[address] = {"target": address, "addresses": [address], "services": [], "error": None}
    saved = []
    now = datetime.utcnow()
    with db.DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _lock_tenant(cursor, org)
        cursor.execute("SELECT scan_mode FROM scans WHERE id = %s", (scan_id,))
        scan = cursor.fetchone()
        if not scan or scan["scan_mode"] != "discovery":
            raise ValueError("Discovery scan does not exist in this organization")
        for target, row in observations.items():
            cursor.execute("SELECT * FROM asset_inventory WHERE target = %s", (target,))
            previous = cursor.fetchone()
            if previous and (target in candidates or previous["last_scan_id"] > scan_id):
                continue
            addresses = row["addresses"]
            services = row["services"]
            source_node_id = node_id
            discovered_at = None if row["error"] else now
            if target not in candidates:
                prior_services = json.loads(previous["services_json"]) if previous and not row["error"] else []
                services = _refresh_services(target, prior_services, services, plan)
            if previous and row["error"]:
                # Preserve the last successful observation, marking this attempt stale.
                services = json.loads(previous["services_json"])
                addresses = addresses or json.loads(previous["addresses_json"])
                discovered_at = previous["discovered_at"]
                source_node_id = previous["source_node_id"]
            addresses_json, services_json = json.dumps(addresses), json.dumps(services)
            if previous and previous["last_scan_id"] == scan_id and all(previous[key] == value for key, value in {
                "source_node_id": source_node_id, "addresses_json": addresses_json,
                "services_json": services_json, "error": row["error"],
            }.items()):
                continue
            cursor.execute(
                """INSERT INTO asset_inventory
                   (target, addresses_json, services_json, discovered_at, last_attempt_at, source_node_id, error, last_scan_id)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                   ON DUPLICATE KEY UPDATE addresses_json = VALUES(addresses_json), services_json = VALUES(services_json),
                   discovered_at = VALUES(discovered_at), last_attempt_at = VALUES(last_attempt_at),
                   source_node_id = VALUES(source_node_id), error = VALUES(error), last_scan_id = VALUES(last_scan_id)""",
                (target, addresses_json, services_json, discovered_at, now, source_node_id, row["error"], scan_id),
            )
            saved.append(target)
        if saved:
            _audit(cursor, node_id, "asset.discovery_saved", {"scan_id": scan_id, "count": len(saved)}, scan_id=scan_id)
        connection.commit()
        cursor.close()
    return len(saved)


def _write_scanners(cursor, target, scanners, actor):
    if scanners is None:
        cursor.execute("DELETE FROM asset_scanner_settings WHERE target = %s", (target,))
    else:
        cursor.execute(
            """INSERT INTO asset_scanner_settings (target, scanners_json, updated_by, updated_at)
               VALUES (%s, %s, %s, %s) ON DUPLICATE KEY UPDATE scanners_json = VALUES(scanners_json),
               updated_by = VALUES(updated_by), updated_at = VALUES(updated_at)""",
            (target, json.dumps(scanners), actor, datetime.utcnow()),
        )


def approve_inventory_targets(org, targets, actor, expected_org_id, enabled_scanners=None):
    """Add approvals atomically; domains require separately approved current DNS IPs."""
    targets = sorted({normalize_scope_entry(target) for target in targets})
    if not targets:
        raise ValueError("Select at least one target to approve")
    scanners = _scanner_names(enabled_scanners)
    with db.DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _lock_tenant(cursor, org, expected_org_id, idle=True)
        previous = _read_approvals(cursor)
        scope = ScanScope([row["target"] for row in previous] + targets)
        for target in targets:
            if not target.startswith("*."):
                scope.require([target])
        now = datetime.utcnow()
        for target in targets:
            cursor.execute(
                "INSERT IGNORE INTO allowed_scan_targets (target, approved_by, approved_at) VALUES (%s, %s, %s)",
                (target, actor, now),
            )
            if scanners is not None:
                _write_scanners(cursor, target, scanners, actor)
        # Keep each audit entry within the existing TEXT column's byte limit.
        for offset in range(0, len(targets), 100):
            _audit(cursor, actor, "asset.approved", {"targets": targets[offset:offset + 100], "enabled_scanners": scanners})
        connection.commit()
        cursor.close()
    return list_asset_inventory(org, include_pending=True)


def update_asset_scanners(org, target, scanners, actor, expected_org_id):
    target = normalize_scope_entry(target)
    scanners = _scanner_names(scanners)
    with db.DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _lock_tenant(cursor, org, expected_org_id, idle=True)
        scope = ScanScope([row["target"] for row in _read_approvals(cursor)])
        if not _approved(scope, target):
            raise ScanScopeError("Approve this target before choosing its scanners")
        _write_scanners(cursor, target, scanners, actor)
        _audit(cursor, actor, "asset.scanners_updated", {"target": target, "enabled_scanners": scanners})
        connection.commit()
        cursor.close()
    return get_asset_scanner_rules(org)


def create_discovery_scan(org, name, targets, plan, actor, expected_org_id):
    """Record an explicitly authorized discovery plan without granting scan scope."""
    with db.DatabaseConnectionManager() as connection:
        cursor = connection.cursor(dictionary=True)
        _lock_tenant(cursor, org, expected_org_id)
        cursor.execute(
            """INSERT INTO scans (scan_name, scan_mode, targets, status, created_at)
               VALUES (%s, 'discovery', %s, 'queued', %s)""",
            (name, targets, datetime.utcnow()),
        )
        scan_id = int(cursor.lastrowid)
        # The queue retains the full plan; its digest links this bounded audit entry.
        plan_digest = hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        _audit(cursor, actor, "asset.discovery_queued", {
            "scan_mode": "discovery", "port_mode": plan.get("port_mode"),
            "target_count": len(plan.get("seeds", [])), "plan_sha256": plan_digest,
        }, scan_id=scan_id)
        connection.commit()
        cursor.close()
    return scan_id
