import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest


pytestmark = pytest.mark.playwright


VULNERABILITIES = [
    {
        "id": 1,
        "priority_score": 97,
        "severity": "critical",
        "title": "SQL Injection",
        "host": "app.example.com",
        "tool": "nuclei",
        "cve": "CVE-2026-1111",
        "has_public_exploit": True,
        "kev": True,
        "confidence": 95,
        "summary": "Unsanitized input reaches a database query.",
        "impact": "Remote data exposure is possible.",
        "solution": "Use parameterized queries and retest.",
        "references": "https://owasp.org/www-community/attacks/SQL_Injection",
        "pocs": "GET /search?q='",
    },
    {
        "id": 2,
        "priority_score": 88,
        "severity": "high",
        "title": "Reflected XSS",
        "host": "portal.example.com",
        "tool": "zap",
        "cve": "",
        "has_public_exploit": False,
        "kev": False,
        "confidence": 80,
        "summary": "A reflected parameter is rendered without escaping.",
        "impact": "An attacker can execute JavaScript in a user session.",
        "solution": "Escape output and add a content security policy.",
    },
]


def _json(route, payload, status=200):
    route.fulfill(
        status=status,
        content_type="application/json",
        body=json.dumps(payload),
    )


def _install_dashboard_mocks(page, base_url, role="tenant_admin", theme="darkstar"):
    state = {
        "scan_requests": [],
        "schedule_requests": [],
        "queued_scans": [],
        "notification_updates": [],
        "notification_tests": 0,
        "unexpected": [],
    }

    page.add_init_script(
        """
        window.WebSocket = function(url) {
            this.url = url;
            this.readyState = 1;
            setTimeout(() => {
                if (this.onopen) this.onopen({});
            }, 0);
        };
        window.WebSocket.OPEN = 1;
        window.WebSocket.CLOSED = 3;
        window.WebSocket.prototype.send = function() {};
        window.WebSocket.prototype.close = function() {
            this.readyState = 3;
            if (this.onclose) this.onclose({});
        };
        """
    )

    def root_handler(route):
        response = route.fetch()
        html = response.text()
        html = html.replace('data-authenticated="false"', 'data-authenticated="true"')
        html = html.replace(
            'data-organization=""',
            'data-organization="Acme Security"',
        )
        html = html.replace('data-org-db=""', 'data-org-db="tenant_db"')
        html = html.replace('data-role=""', f'data-role="{role}"')
        route.fulfill(response=response, body=html)

    def filtered_vulnerabilities(query):
        items = VULNERABILITIES
        severity = (query.get("severity") or [""])[0]
        host = (query.get("host") or [""])[0]
        tool = (query.get("tool") or [""])[0]
        if severity:
            items = [item for item in items if item["severity"] == severity]
        if host:
            items = [item for item in items if item["host"] == host]
        if tool:
            items = [item for item in items if item["tool"] == tool]
        return {
            "items": items,
            "total": len(items),
            "limit": int((query.get("limit") or ["50"])[0]),
            "offset": int((query.get("offset") or ["0"])[0]),
        }

    def scans_payload():
        items = [
            {
                "id": 101,
                "scan_name": "Nightly Web",
                "scan_mode": "2",
                "status": "completed",
                "targets": "app.example.com",
                "created_at": "2026-05-14T08:00:00Z",
                "started_at": "2026-05-14T08:00:10Z",
                "finished_at": "2026-05-14T08:01:00Z",
            },
            {
                "id": 102,
                "scan_name": "Queued Perimeter",
                "scan_mode": "4",
                "status": "queued",
                "targets": "example.com",
                "created_at": "2026-05-14T09:00:00Z",
            },
        ]
        items = list(reversed(state["queued_scans"])) + items
        return {"items": items}

    def api_handler(route):
        request = route.request
        parsed = urlparse(request.url)
        path = parsed.path
        query = parse_qs(parsed.query)
        method = request.method.upper()

        if path in {"/api/admin/auth/policy", "/api/admin/organizations", "/api/admin/users", "/api/scanner-nodes"}:
            _json(route, {"items": []})
            return
        if path == "/api/me":
            _json(
                route,
                {
                    "authenticated": True,
                    "organization": "Acme Security",
                    "org_db": "tenant_db",
                    "role": role,
                    "user": {"email": "analyst@example.org", "theme": theme},
                    "auth_method": "session",
                    "organizations": [
                        {"org_name": "Acme Security", "org_db_name": "tenant_db", "role": "tenant_admin"}
                    ],
                },
            )
            return
        if path == "/api/stats":
            _json(
                route,
                {
                    "total_vulnerabilities": 2,
                    "running_scans": 1,
                    "total_scans": 2 + len(state["scan_requests"]),
                    "scheduled_scans": 1,
                    "severity_breakdown": {"critical": 1, "high": 1, "medium": 0, "low": 0},
                },
            )
            return
        if path == "/api/scans" and method == "GET":
            _json(route, scans_payload())
            return
        if path.startswith("/api/scans/") and path.endswith("/logs"):
            _json(
                route,
                {"items": [{"message": "Queued for scanner workers", "log_level": "info", "created_at": "2026-05-14T10:00:00Z"}]},
            )
            return
        if path == "/api/scans/start" and method == "POST":
            payload = request.post_data_json or {}
            state["scan_requests"].append(payload)
            runs = []
            for appliance in payload.get("appliances") or [{"node_id": payload.get("preferred_node_id")}]:
                scan_id = 777 + len(state["queued_scans"])
                name = payload.get("scan_name") or "Playwright queued scan"
                state["queued_scans"].append({"id": scan_id, "scan_name": name,
                    "scan_mode": "selected" if payload.get("appliances") else str(payload.get("mode") or payload.get("scanner") or ""),
                    "status": "queued", "targets": payload.get("targets", ""), "created_at": "2026-05-14T10:00:00Z"})
                runs.append({"scan_id": scan_id, "scan_name": name, "node_id": appliance["node_id"],
                             "node_name": "Office scanner" if appliance["node_id"] == "node-1" else "Web scanner", "status": "queued"})
            _json(route, {"ok": True, "scan_id": runs[0]["scan_id"], "scans": runs,
                          "scan_ids": [run["scan_id"] for run in runs], "status": "queued"})
            return
        if path == "/api/vulnerabilities" and method == "GET":
            _json(route, {"items": VULNERABILITIES})
            return
        if path == "/api/vulnerabilities/filtered":
            _json(route, filtered_vulnerabilities(query))
            return
        if path == "/api/vulnerabilities/grouped":
            _json(
                route,
                {"items": [{"group_key": "app.example.com", "count": 2, "max_priority": 97, "hosts": "app.example.com"}]},
            )
            return
        if path.startswith("/api/vulnerabilities/"):
            vulnerability_id = int(path.rsplit("/", 1)[1])
            item = next((vuln for vuln in VULNERABILITIES if vuln["id"] == vulnerability_id), None)
            _json(route, item or {"detail": "not found"}, status=200 if item else 404)
            return
        if path == "/api/filters/hosts":
            _json(route, {"items": ["app.example.com", "portal.example.com"]})
            return
        if path == "/api/filters/tools":
            _json(route, {"items": ["nuclei", "zap"]})
            return
        if path == "/api/attack-surface":
            _json(
                route,
                {
                    "summary": {
                        "asset_count": 2,
                        "exposed_ports": 3,
                        "critical_assets": 1,
                        "exploitable_assets": 1,
                        "port_services": {"https": 2, "ssh": 1},
                    },
                    "items": [
                        {
                            "host": "app.example.com",
                            "urls": ["https://app.example.com"],
                            "ips": ["203.0.113.10"],
                            "ports": [{"port": 443, "service": "https"}, {"port": 22, "service": "ssh"}],
                            "vulnerability_count": 2,
                            "max_severity": "critical",
                            "sources": ["bbot", "nuclei"],
                            "tags": ["in-scope"],
                        }
                    ],
                    "total": 1,
                    "limit": int((query.get("limit") or ["50"])[0]),
                    "offset": int((query.get("offset") or ["0"])[0]),
                },
            )
            return
        if path == "/api/recon/subdomains":
            _json(
                route,
                {
                    "items": [
                        {
                            "target": "app.example.com",
                            "preferred_target": "https://app.example.com",
                            "parent_domain": "example.com",
                            "urls": ["https://app.example.com"],
                            "ips": ["203.0.113.10"],
                            "sources": ["bbot"],
                            "tags": ["in-scope"],
                            "last_seen": "2026-05-14T10:00:00Z",
                        },
                        {
                            "target": "portal.example.com",
                            "preferred_target": "https://portal.example.com",
                            "parent_domain": "example.com",
                            "urls": ["https://portal.example.com"],
                            "ips": ["203.0.113.11"],
                            "sources": ["bbot"],
                            "tags": ["auth"],
                            "last_seen": "2026-05-14T10:00:00Z",
                        },
                    ],
                    "domains": ["example.com"],
                    "total": 2,
                    "limit": int((query.get("limit") or ["25"])[0]),
                    "offset": int((query.get("offset") or ["0"])[0]),
                },
            )
            return
        if path == "/api/scanner-nodes/node-1/profiles":
            profiles = [
                {"scanner": "openvas", "id": "network-policy", "name": "Network scan"},
                {"scanner": "zap", "id": "default", "name": "Recon"},
                {"scanner": "zap", "id": "custom.policy", "name": "Active: Custom"},
            ]
            scanner = (query.get("scanner") or [""])[0]
            search = (query.get("search") or [""])[0].lower()
            items = [item for item in profiles if (not scanner or scanner == item["scanner"]) and search in item["name"].lower()]
            _json(route, {"items": items, "total": len(items), "scanners": ["openvas", "zap"], "updated_at": "2026-10-22T12:00:00"})
            return
        if path in {"/api/asset-inventory", "/api/discoveries"}:
            _json(route, {"detail": "Not available in this legacy fixture"}, status=404)
            return
        if path == "/api/scan-scope" and method == "GET":
            _json(route, {"items": [{"target": "192.0.2.0/24", "approved_by": "platform@example.test"}]})
            return
        if path == "/api/scanner-nodes/available":
            _json(
                route,
                {"items": [{"node_id": "node-1", "name": "Office scanner", "status": "online", "last_seen_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(), "running_jobs": 0, "max_parallel_jobs": 2}]},
            )
            return
        if path == "/api/schedules" and method == "GET":
            _json(
                route,
                {
                    "items": [
                        {
                            "id": 11,
                            "scan_name": "Weekly perimeter",
                            "scan_mode": "2",
                            "targets": "example.com",
                            "interval_minutes": 10080,
                            "enabled": True,
                            "next_run_at": "2026-05-21T08:00:00Z",
                        }
                    ]
                },
            )
            return
        if path == "/api/schedules" and method == "POST":
            payload = request.post_data_json or {}
            state["schedule_requests"].append(payload)
            schedules = [{"schedule_id": 12 + index, "node_id": item["node_id"],
                          "node_name": "Office scanner" if item["node_id"] == "node-1" else "Web scanner",
                          "scan_name": payload.get("scan_name") or "Recurring scan"}
                         for index, item in enumerate(payload.get("appliances", []))]
            _json(route, {"ok": True, "schedules": schedules, "schedule_ids": [item["schedule_id"] for item in schedules]})
            return
        if path == "/api/notifications/settings" and method == "GET":
            _json(
                route,
                {
                    "enabled": False,
                    "recipients": "ops@example.org",
                    "min_severity": "high",
                    "notify_on_success": True,
                    "notify_on_failure": True,
                },
            )
            return
        if path == "/api/notifications/settings" and method == "PATCH":
            payload = request.post_data_json or {}
            state["notification_updates"].append(payload)
            _json(route, {"ok": True, **payload})
            return
        if path == "/api/notifications/test" and method == "POST":
            state["notification_tests"] += 1
            _json(route, {"ok": True})
            return
        if path == "/api/auth/mfa/settings":
            _json(route, {"enabled": False, "required": False, "org_required": False})
            return
        if path == "/api/auth/sso/settings":
            _json(
                route,
                {
                    "enabled": False,
                    "required": False,
                    "issuer": "",
                    "client_id": "",
                    "client_secret_configured": False,
                    "allowed_domain": "",
                },
            )
            return
        if path == "/api/api-keys":
            _json(route, {"items": [{"id": 5, "name": "CI readout", "key_prefix": "ds_live_", "role": "security_analyst"}]})
            return
        if path == "/api/users":
            _json(
                route,
                {
                    "items": [
                        {
                            "id": 7,
                            "email": "analyst@example.org",
                            "display_name": "Security Analyst",
                            "role": "tenant_admin",
                            "mfa_enabled": False,
                        }
                    ]
                },
            )
            return

        state["unexpected"].append((method, path))
        _json(route, {"detail": f"Unexpected test API route: {method} {path}"}, status=404)

    page.route(f"{base_url}/", root_handler)
    page.route(f"{base_url}/api/**", api_handler)
    return state


def test_dashboard_vulnerabilities_and_scan_center_workflow(darkstar_server):
    sync_api = pytest.importorskip("playwright.sync_api")
    expect = sync_api.expect
    output_dir = Path("test-results/playwright")
    output_dir.mkdir(parents=True, exist_ok=True)

    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page(viewport={"width": 1440, "height": 1200})
            mock_state = _install_dashboard_mocks(page, darkstar_server, role="platform_admin")
            page.goto(f"{darkstar_server}/", wait_until="networkidle")

            expect(page.locator("#mainDashboard")).to_be_visible()
            expect(page.locator("#statTotal")).to_have_text("2")
            expect(page.locator("#scanRows")).to_contain_text("Nightly Web")

            page.locator('[data-tab="vulns"]').click()
            expect(page.locator("#vulnRows")).to_contain_text("SQL Injection")
            page.locator("#filterSeverity").select_option("high")
            expect(page.locator("#vulnRows")).to_contain_text("Reflected XSS")
            expect(page.locator("#resultCount")).to_contain_text("1 total vulnerabilities")
            page.locator(".vulnerability-detail-link", has_text="Reflected XSS").click()
            expect(page.locator("#detailOverlay")).to_be_visible()
            expect(page.locator("#detailTitle")).to_have_text("Reflected XSS")
            expect(page.locator("#detailBody")).to_contain_text("Escape output")

            page.locator("#detailCloseBtn").click()
            page.locator('[data-tab="scan"]').click()
            expect(page.locator("#scheduleRows")).to_contain_text("Weekly perimeter")
            page.locator("#targetsInput").fill("app.example.com, portal.example.com")
            page.locator("#scanNameInput").fill("Playwright normal scan")
            page.locator('.scan-appliance-choice[value="node-1"]').check()
            openvas = page.locator('.scanner-engine').filter(has=page.locator('input[value="openvas"]'))
            openvas.locator('.scanner-choice').check()
            openvas.locator('select').select_option('network-policy')
            page.locator('#launchScanBtn').click()
            expect(page.locator('#scan-tab.active')).to_be_visible()
            expect(page.locator('#scanLaunchResults')).to_contain_text('Run #777')
            page.locator('#scanLaunchResults .open-debug-scan-btn').click()
            expect(page.locator('#debugOutput')).to_contain_text('Queued for scanner workers')

            assert mock_state["scan_requests"][-1] == {
                "targets": "app.example.com, portal.example.com",
                "appliances": [{"node_id": "node-1", "selections": [{"scanner": "openvas", "profile_id": "network-policy"}]}],
                "scan_name": "Playwright normal scan",
                "bruteforce": False,
                "bruteforce_timeout": 300,
            }
            assert mock_state["unexpected"] == []
            page.screenshot(path=str(output_dir / "dashboard-workflow.png"), full_page=True)
        finally:
            browser.close()


def test_attack_surface_subdomains_can_be_queued_without_running_scans(darkstar_server):
    sync_api = pytest.importorskip("playwright.sync_api")
    expect = sync_api.expect
    output_dir = Path("test-results/playwright")
    output_dir.mkdir(parents=True, exist_ok=True)

    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page(viewport={"width": 1280, "height": 1100})
            mock_state = _install_dashboard_mocks(page, darkstar_server, role="platform_admin")
            page.goto(f"{darkstar_server}/", wait_until="networkidle")

            page.locator('[data-tab="surface"]').click()
            expect(page.locator("#attackSurfaceRows")).to_contain_text("app.example.com")
            expect(page.locator("#bbotSubdomainRows")).to_contain_text("portal.example.com")
            page.locator(".subdomain-target-checkbox").first.check()
            page.locator("#scanSelectedSubdomainsBtn").click()
            expect(page.locator("#debug-tab.active")).to_be_visible()
            expect(page.locator("#bbotSubdomainMessage")).to_contain_text("Scan 777 started for 1 target(s).")

            assert mock_state["scan_requests"][-1]["targets"] == "https://app.example.com"
            assert mock_state["scan_requests"][-1]["mode"] == 2
            assert mock_state["scan_requests"][-1]["scanner"] is None
            assert mock_state["unexpected"] == []
            page.screenshot(path=str(output_dir / "attack-surface-workflow.png"), full_page=True)
        finally:
            browser.close()


def test_settings_notifications_can_be_configured(darkstar_server):
    sync_api = pytest.importorskip("playwright.sync_api")
    expect = sync_api.expect
    output_dir = Path("test-results/playwright")
    output_dir.mkdir(parents=True, exist_ok=True)

    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page(viewport={"width": 1280, "height": 1100})
            mock_state = _install_dashboard_mocks(page, darkstar_server)
            page.goto(f"{darkstar_server}/", wait_until="networkidle")

            page.locator('[data-tab="settings"]').click()
            expect(page.locator("#recipientList")).to_contain_text("ops@example.org")
            page.locator("#notificationEnabledInput").check()
            page.locator("#recipientEmailInput").fill("security@example.org")
            page.locator("#addRecipientBtn").click()
            expect(page.locator("#recipientList")).to_contain_text("security@example.org")
            page.locator("#notificationSeverityInput").select_option("critical")
            page.locator("#notifyFailureInput").uncheck()
            page.get_by_role("button", name="Save Notifications").click()
            expect(page.locator("#notificationMessage")).to_have_text("Notification settings saved.")
            page.get_by_role("button", name="Send Test").click()
            expect(page.locator("#notificationMessage")).to_have_text("Test notification sent or skipped if SMTP is not configured.")

            assert mock_state["notification_updates"][-1] == {
                "enabled": True,
                "recipients": "ops@example.org, security@example.org",
                "min_severity": "critical",
                "notify_on_success": True,
                "notify_on_failure": False,
            }
            assert mock_state["notification_tests"] == 1
            assert mock_state["unexpected"] == []
            page.screenshot(path=str(output_dir / "settings-notifications-workflow.png"), full_page=True)
        finally:
            browser.close()


def test_risk_acceptance_filter_and_revocation(darkstar_server):
    sync_api = pytest.importorskip("playwright.sync_api")
    expect = sync_api.expect
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page(viewport={"width": 1440, "height": 1100})
            original = _install_dashboard_mocks(page, darkstar_server)
            finding = dict(VULNERABILITIES[0], risk_accepted=False)
            writes = []

            def risk_routes(route):
                path = urlparse(route.request.url).path
                include = parse_qs(urlparse(route.request.url).query).get("include_accepted") == ["true"]
                visible = include or not finding["risk_accepted"]
                if path == "/api/vulnerabilities/1/risk-acceptance":
                    writes.append((route.request.method, route.request.post_data_json))
                    accepted = route.request.method == "POST"
                    finding.update(risk_accepted=accepted)
                    if accepted:
                        finding.update(risk_reason=route.request.post_data_json["reason"], risk_accepted_by="analyst@example.test", risk_accepted_at="2026-10-22T12:00:00")
                    _json(route, {"ok": True})
                elif path == "/api/vulnerabilities/1":
                    _json(route, finding)
                elif path == "/api/vulnerabilities/filtered":
                    _json(route, {"items": [finding] if visible else [], "total": int(visible)})
                elif path == "/api/stats":
                    _json(route, {"total_vulnerabilities": int(visible), "severity_breakdown": {"critical": int(visible)}})
                else:
                    route.fallback()

            page.route(f"{darkstar_server}/api/**", risk_routes)
            page.goto(darkstar_server, wait_until="networkidle")
            expect(page.locator("#statTotal")).to_have_text("1")
            page.locator('[data-tab="vulns"]').click()
            page.locator(".vulnerability-detail-link").first.click()
            page.locator("#riskReasonInput").fill("Temporary mitigation <script>never execute</script>")
            page.get_by_role("button", name="Accept risk", exact=True).click()
            expect(page.get_by_role("button", name="Revoke acceptance")).to_be_visible()
            expect(page.locator("#detailBody")).to_contain_text("<script>never execute</script>")
            expect(page.locator("#detailBody script")).to_have_count(0)
            expect(page.locator("#statTotal")).to_have_text("0")
            page.locator("#detailCloseBtn").click()
            expect(page.locator("#vulnRows")).to_contain_text("No vulnerabilities")
            page.locator("#vulns-tab .include-accepted-risks").check()
            expect(page.locator("#vulnRows")).to_contain_text("Risk accepted")
            expect(page.locator("#statTotal")).to_have_text("1")
            expect(page.locator("#htmlReportExportBtn")).to_have_attribute("href", "/api/exports/vulnerabilities.html?include_accepted=true")
            page.locator(".vulnerability-detail-link").first.click()
            page.get_by_role("button", name="Revoke acceptance").click()
            expect(page.get_by_role("button", name="Accept risk", exact=True)).to_be_visible()
            assert [method for method, _ in writes] == ["POST", "DELETE"]
            assert writes[0][1]["expires_at"] is None
            assert original["unexpected"] == []
        finally:
            browser.close()


@pytest.mark.parametrize('viewport,theme', [({'width': 1440, 'height': 1100}, 'midnight'), ({'width': 390, 'height': 844}, 'daylight')])
def test_scan_center_keeps_profiles_across_appliances_and_schedules(darkstar_server, viewport, theme):
    sync_api = pytest.importorskip('playwright.sync_api')
    expect = sync_api.expect
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page(viewport=viewport)
            state = _install_dashboard_mocks(page, darkstar_server, role="platform_admin", theme=theme)
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.route('**/api/scanner-nodes/available', lambda route: _json(route, {'items': [
                {'node_id': node, 'name': name, 'status': 'online', 'last_seen_at': datetime.now(timezone.utc).replace(tzinfo=None).isoformat()}
                for node, name in [('node-1', 'Office scanner'), ('node-2', 'Web scanner')]]
            }))
            page.route('**/api/scanner-nodes/node-2/profiles?*', lambda route: _json(route, {
                'scanners': ['zap'], 'total': 2, 'items': [{'scanner': 'zap', 'id': 'default', 'name': 'Recon'},
                                                        {'scanner': 'zap', 'id': 'active', 'name': 'Active: Full'}],
            }))
            page.goto(darkstar_server, wait_until='networkidle')
            page.locator('[data-tab="scan"]').click()
            page.locator('#targetsInput').fill('192.0.2.1')
            office = page.locator('.scanner-appliance-card[data-node-id="node-1"]')
            web = page.locator('.scanner-appliance-card[data-node-id="node-2"]')
            office.locator('.scan-appliance-choice').check()
            openvas = office.locator('.scanner-engine').filter(has=page.locator('input[value="openvas"]'))
            openvas.locator('.scanner-choice').check()
            openvas.locator('select').select_option('network-policy')
            web.locator('.scan-appliance-choice').check()
            zap = web.locator('.scanner-engine').filter(has=page.locator('input[value="zap"]'))
            zap.locator('.scanner-choice').check()
            zap.locator('select').select_option('default')
            web.locator('.scan-appliance-choice').uncheck()
            expect(openvas.locator('select')).to_have_value('network-policy')
            web.locator('.scan-appliance-choice').check()
            expect(zap.locator('select')).to_have_value('default')
            page.locator('[data-tab="dashboard"]').click()
            page.locator('[data-tab="scan"]').click()
            expect(openvas.locator('select')).to_have_value('network-policy')
            expect(zap.locator('select')).to_have_value('default')
            expect(page.locator('#modeInput, #scannerInput, #applianceInput')).to_have_count(0)
            expect(page.locator('#scanLaunchSummaryText')).to_have_text('1 target · 2 appliances · Run now')
            expect(page.locator('#scanLaunchPlan')).to_contain_text('OpenVAS / Network scan')
            expect(page.locator('#scanLaunchPlan')).to_contain_text('OWASP ZAP / Recon')
            page.evaluate('(theme) => document.documentElement.dataset.theme = theme', theme)
            page.locator('#scannerApplianceChoices').scroll_into_view_if_needed()
            Path('test-results/playwright').mkdir(parents=True, exist_ok=True)
            page.screenshot(path=f'test-results/playwright/multi-appliance-{viewport["width"]}.png', full_page=True)
            assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
            page.locator('#launchScanBtn').click()
            expect(page.locator('#scan-tab.active')).to_be_visible()
            expect(page.locator('#scanLaunchResults li')).to_have_count(2)
            expect(page.locator('#scanLaunchResults')).to_contain_text('Run #777')
            expect(page.locator('#scanLaunchResults')).to_contain_text('Run #778')
            expect(page.locator('#scanLaunchResults .open-debug-scan-btn')).to_have_count(2)
            expect(page.locator('#scanLaunchResults .stop-scan-btn')).to_have_count(2)
            appliances = [
                {'node_id': 'node-1', 'selections': [{'scanner': 'openvas', 'profile_id': 'network-policy'}]},
                {'node_id': 'node-2', 'selections': [{'scanner': 'zap', 'profile_id': 'default'}]},
            ]
            assert state['scan_requests'][-1] == {'targets': '192.0.2.1', 'appliances': appliances,
                                                'scan_name': None, 'bruteforce': False, 'bruteforce_timeout': 300}
            state['queued_scans'][0]['status'] = 'failed'
            state['queued_scans'][1]['status'] = 'running'
            page.evaluate('refreshDashboard()')
            expect(page.locator('#scanLaunchResults li').nth(0)).to_contain_text('failed')
            expect(page.locator('#scanLaunchResults li').nth(1)).to_contain_text('running')
            expect(page.locator('#scanLaunchResults .stop-scan-btn')).to_have_count(1)
            page.screenshot(path=f'test-results/playwright/multi-appliance-results-{viewport["width"]}.png', full_page=True)
            page.locator('#recurringScanInput').check()
            page.locator('#launchScanBtn').click()
            expect(page.locator('#scanMessage')).to_contain_text('2 recurring schedules created.')
            expect(page.locator('#scanLaunchResults li')).to_have_count(2)
            assert state['schedule_requests'][-1]['appliances'] == appliances
            assert state['schedule_requests'][-1]['interval_minutes'] == 1440
            assert not {'mode', 'scanner', 'selections', 'preferred_node_id'} & state['schedule_requests'][-1].keys()
            assert state['unexpected'] == []
            assert errors == []
        finally:
            browser.close()


@pytest.mark.parametrize('role', ['tenant_admin', 'platform_admin'])
def test_scan_scope_settings_can_only_be_saved_by_platform_admin(darkstar_server, role):
    sync_api = pytest.importorskip('playwright.sync_api')
    expect = sync_api.expect
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page(viewport={'width': 1440, 'height': 1100})
            state = _install_dashboard_mocks(page, darkstar_server)
            page.route('**/api/me', lambda route: _json(route, {'authenticated': True, 'organization': 'Test', 'org_db': 'tenant_db', 'role': role, 'user': {'id': 1, 'theme': 'darkstar'}}))
            page.route('**/api/scanner-nodes', lambda route: _json(route, {'items': []}))
            page.route('**/api/admin/auth/policy', lambda route: _json(route, {}))
            page.route('**/api/admin/organizations', lambda route: _json(route, {'items': []}))
            page.route('**/api/admin/users', lambda route: _json(route, {'items': []}))
            writes = []
            def scope(route):
                if route.request.method == 'PUT':
                    writes.append(route.request.post_data_json)
                _json(route, {'items': [{'target': target} for target in (writes[-1]['targets'] if writes else ['192.0.2.0/24'])]})
            page.route('**/api/scan-scope', scope)
            page.goto(darkstar_server, wait_until='networkidle')
            page.locator('[data-tab="settings"]').click()
            expect(page.locator('#allowedTargetsInput')).to_have_value('192.0.2.0/24')
            if role == 'platform_admin':
                expect(page.locator('#saveScanScopeBtn')).to_be_enabled()
                page.locator('#allowedTargetsInput').fill('example.test\n192.0.2.1')
                page.locator('#saveScanScopeBtn').click()
                expect(page.locator('#scanScopeMessage')).to_have_text('Allowed scan targets saved.')
                assert writes == [{'targets': ['example.test', '192.0.2.1']}]
            else:
                expect(page.locator('#allowedTargetsInput')).not_to_be_editable()
                expect(page.locator('#saveScanScopeBtn')).to_be_disabled()
                assert writes == []
            assert state['unexpected'] == []
        finally:
            browser.close()


@pytest.mark.parametrize('pending_operation', ['load', 'save', 'save_error'])
def test_scan_scope_ignores_previous_tenant_requests(darkstar_server, pending_operation):
    sync_api = pytest.importorskip('playwright.sync_api')
    expect = sync_api.expect
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page(viewport={'width': 1440, 'height': 1100})
            mock_state = _install_dashboard_mocks(page, darkstar_server)
            active_org = 'tenant_db'
            pending = []
            switches = []
            writes = []
            hold_scope = False

            def identity():
                return {
                    'authenticated': True, 'organization': active_org, 'org_db': active_org,
                    'role': 'platform_admin', 'user': {'id': 1, 'theme': 'darkstar'},
                    'organizations': [{'org_name': org, 'org_db_name': org, 'role': 'platform_admin'}
                                      for org in ['tenant_db', 'other_tenant']],
                }

            def switch(route):
                nonlocal active_org
                active_org = route.request.post_data_json['org_db']
                switches.append(route)

            def scope(route):
                if route.request.method == 'PUT':
                    writes.append((active_org, route.request.post_data_json))
                if hold_scope:
                    pending.append(route)
                else:
                    _json(route, {'items': [{'target': '192.0.2.1'}]})

            page.route('**/api/me', lambda route: _json(route, identity()))
            page.route('**/api/auth/select-organization', switch)
            page.route('**/api/scanner-nodes', lambda route: _json(route, {'items': []}))
            page.route('**/api/admin/auth/policy', lambda route: _json(route, {}))
            page.route('**/api/admin/organizations', lambda route: _json(route, {'items': []}))
            page.route('**/api/admin/users', lambda route: _json(route, {'items': []}))
            page.route('**/api/scan-scope', scope)
            page.goto(darkstar_server, wait_until='networkidle')
            page.locator('[data-tab="settings"]').click()
            input_field = page.locator('#allowedTargetsInput')
            save_button = page.locator('#saveScanScopeBtn')
            expect(input_field).to_have_value('192.0.2.1')
            expect(save_button).to_be_enabled()
            hold_scope = True
            with page.expect_request('**/api/scan-scope'):
                if pending_operation == 'load':
                    page.locator('[data-tab="dashboard"]').click()
                    page.locator('[data-tab="settings"]').click()
                else:
                    input_field.fill('192.0.2.10')
                    save_button.click()

            with page.expect_request('**/api/auth/select-organization'):
                page.locator('#tenantSwitchSelect').select_option('other_tenant')
            # Lock immediately, before the new session's response reaches the UI.
            expect(input_field).to_have_value('')
            expect(input_field).not_to_be_editable()
            expect(save_button).to_be_disabled()
            _json(switches.pop(), identity())
            expect(page.locator('#dashboard-tab.active')).to_be_visible()
            with page.expect_request('**/api/scan-scope'):
                page.locator('[data-tab="settings"]').click()

            # The old request finishes while the new tenant's scope is loading.
            with page.expect_response('**/api/scan-scope') as response:
                if pending_operation == 'save_error':
                    _json(pending.pop(0), {'detail': 'Old tenant save failed'}, status=409)
                else:
                    _json(pending.pop(0), {'items': [{'target': '192.0.2.10'}]})
            response.value.finished()
            page.evaluate('() => new Promise(resolve => requestAnimationFrame(resolve))')
            expect(input_field).to_have_value('')
            expect(input_field).not_to_be_editable()
            expect(save_button).to_be_disabled()
            expect(page.locator('#scanScopeMessage')).to_have_text('')

            _json(pending.pop(0), {'items': [{'target': '198.51.100.1'}]})
            expect(input_field).to_have_value('198.51.100.1')
            expect(input_field).to_be_editable()
            expect(save_button).to_be_enabled()
            assert writes == ([] if pending_operation == 'load' else [('tenant_db', {'targets': ['192.0.2.10']})])
            assert mock_state['unexpected'] == []
        finally:
            browser.close()


@pytest.mark.parametrize('role', ['viewer', 'security_analyst', 'tenant_admin', 'platform_admin'])
def test_platform_navigation_and_scan_shortcuts_follow_role(darkstar_server, role):
    sync_api = pytest.importorskip('playwright.sync_api')
    expect = sync_api.expect
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page()
            mock_state = _install_dashboard_mocks(page, darkstar_server, role=role)
            page.goto(darkstar_server, wait_until='networkidle')
            admin = role == 'platform_admin'
            can_scan = role in ['tenant_admin', 'platform_admin']
            for selector in ['[data-tab="endpoints"]', '[data-tab="m365"]', 'a[href="/documentation"]']:
                if admin:
                    expect(page.locator(selector)).to_be_visible()
                else:
                    expect(page.locator(selector)).to_be_hidden()
            if not admin:
                for tab in ['endpoints', 'm365', 'docs']:
                    page.evaluate('(tab) => switchTab(tab)', tab)
                    expect(page.locator('#dashboard-tab')).to_have_class('tab-panel active')
            for selector in ['[data-tab="scan"]', '[data-tab-shortcut="scan"]']:
                if can_scan:
                    expect(page.locator(selector)).to_be_visible()
                else:
                    expect(page.locator(selector)).to_be_hidden()
            if not can_scan:
                for tab in ['scan', 'schedules']:
                    page.evaluate('(tab) => switchTab(tab)', tab)
                    expect(page.locator('#dashboard-tab')).to_have_class('tab-panel active')
                expect(page.locator('.stop-scan-btn')).to_have_count(0)
            page.locator('[data-tab="surface"]').click()
            expect(page.locator('#bbotSubdomainRows')).to_contain_text('app.example.com')
            if can_scan:
                expect(page.locator('#bbotSubdomainScanTypeInput')).to_be_visible()
                expect(page.locator('#scanSelectedSubdomainsBtn')).to_be_visible()
                expect(page.locator('.scan-subdomain-btn').first).to_be_visible()
            else:
                expect(page.locator('#bbotSubdomainScanTypeInput')).to_be_hidden()
                expect(page.locator('#scanSelectedSubdomainsBtn')).to_be_hidden()
                expect(page.locator('#scanAllSubdomainsBtn')).to_be_hidden()
                expect(page.locator('.scan-subdomain-btn')).to_have_count(0)
            assert mock_state['scan_requests'] == []
            assert mock_state['unexpected'] == []
        finally:
            browser.close()


@pytest.mark.parametrize('role', ['viewer', 'security_analyst', 'tenant_admin', 'platform_admin'])
def test_debug_navigation_and_logs_follow_role(darkstar_server, role):
    sync_api = pytest.importorskip('playwright.sync_api')
    expect = sync_api.expect
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page()
            mock_state = _install_dashboard_mocks(page, darkstar_server, role=role)
            debug_requests = []
            page.on('request', lambda request: debug_requests.append(request.url)
                    if '/api/scans/' in request.url else None)
            page.goto(darkstar_server, wait_until='networkidle')
            expect(page.locator('#scanRows')).to_contain_text('101')
            if role in ['tenant_admin', 'platform_admin']:
                expect(page.locator('[data-tab="debug"]')).to_be_visible()
                expect(page.locator('.scan-detail-row')).to_have_count(2)
                page.locator('[data-tab="debug"]').click()
                page.locator('#debugScanSelect').select_option('101')
                expect(page.locator('#debugOutput')).to_contain_text('Queued for scanner workers')
                page.wait_for_function('state.ws && state.wsPingTimer')
                # A role change must also close an existing stream and clear its output.
                page.evaluate('''() => {
                    window.previousDebugSocket = state.ws;
                    startDebugPolling(101);
                    state.role = 'viewer';
                    applyRoleUI();
                }''')
                expect(page.locator('[data-tab="debug"]')).to_be_hidden()
                expect(page.locator('#dashboard-tab.active')).to_be_visible()
                expect(page.locator('#debugOutput')).to_have_text('')
                assert page.evaluate('previousDebugSocket.readyState === WebSocket.CLOSED')
                assert page.evaluate('state.ws === null && state.wsPingTimer === null && state.debugPollTimer === null')
            else:
                expect(page.locator('[data-tab="debug"]')).to_be_hidden()
                expect(page.locator('.scan-detail-row')).to_have_count(0)
                page.evaluate('''async () => {
                    await switchTab('debug');
                    await openScanDetail(101);
                    await loadScanLogs(101);
                }''')
                expect(page.locator('#dashboard-tab.active')).to_be_visible()
                assert debug_requests == []
            assert mock_state['unexpected'] == []
        finally:
            browser.close()


def test_scan_detail_logs_close_when_admin_access_is_lost(darkstar_server):
    sync_api = pytest.importorskip('playwright.sync_api')
    expect = sync_api.expect
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page()
            mock_state = _install_dashboard_mocks(page, darkstar_server, role='tenant_admin')
            page.route('**/api/scans/101', lambda route: _json(route, {
                'scan': {'id': 101, 'scan_name': 'Test scan', 'status': 'completed'},
                'logs': [{'message': 'Scanner execution output'}],
            }))
            page.goto(darkstar_server, wait_until='networkidle')
            page.locator('.scan-detail-row[data-scan-id="101"]').click()
            expect(page.locator('#detailBody')).to_contain_text('Scanner execution output')
            page.evaluate("() => { state.role = 'security_analyst'; applyRoleUI(); }")
            expect(page.locator('#detailOverlay')).to_be_hidden()
            expect(page.locator('#detailBody')).to_have_text('')
            assert mock_state['unexpected'] == []
        finally:
            browser.close()


@pytest.mark.parametrize('role', ['viewer', 'security_analyst', 'tenant_admin', 'platform_admin'])
def test_members_see_their_organization_and_approved_targets(darkstar_server, role):
    sync_api = pytest.importorskip('playwright.sync_api')
    expect = sync_api.expect
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page()
            mock_state = _install_dashboard_mocks(page, darkstar_server, role=role)
            targets = ['192.0.2.1', '2001:db8::1', 'example.test', '192.0.2.0/24', '*.example.test']
            page.route('**/api/scan-scope', lambda route: _json(route, {
                'items': [{'target': target} for target in targets],
            }))
            page.goto(darkstar_server, wait_until='networkidle')
            expect(page.locator('#topOrganizationName')).to_have_text('Acme Security')
            assert not page.locator('#topOrganizationName').evaluate('(element) => element.isContentEditable')
            page.locator('[data-tab="assets"]').click()
            expect(page.locator('#approvedAssetRows tr')).to_have_count(5)
            for target in targets:
                expect(page.locator('#approvedAssetRows')).to_contain_text(target)
            expect(page.locator('#approvedAssetRows')).to_contain_text('Network range')
            expect(page.locator('#approvedAssetRows')).to_contain_text('Domain wildcard')
            if role in ['viewer', 'security_analyst']:
                expect(page.locator('.approved-asset-choice')).to_have_count(0)
                expect(page.locator('#scanApprovedAssetsBtn')).to_be_hidden()
            page.locator('#approvedAssetSearch').fill('EXAMPLE')
            expect(page.locator('#approvedAssetRows tr')).to_have_count(2)
            assert mock_state['unexpected'] == []
        finally:
            browser.close()


@pytest.mark.parametrize('role', ['tenant_admin', 'platform_admin'])
@pytest.mark.parametrize('recurring', [False, True])
def test_approved_assets_become_explicit_scan_targets(darkstar_server, role, recurring):
    sync_api = pytest.importorskip('playwright.sync_api')
    expect = sync_api.expect
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page()
            mock_state = _install_dashboard_mocks(page, darkstar_server, role=role)
            targets = ['192.0.2.1', '2001:db8::1', 'example.test', '192.0.2.0/24', '*.example.test']
            page.route('**/api/scan-scope', lambda route: _json(route, {'items': [{'target': target} for target in targets]}))
            page.goto(darkstar_server, wait_until='networkidle')
            page.locator('[data-tab="assets"]').click()
            expect(page.locator('.approved-asset-choice')).to_have_count(3)
            page.locator('#selectAllApprovedAssetsBtn').click()
            expect(page.locator('#approvedAssetSelectionCount')).to_have_text('3 selected')
            page.locator('#scanApprovedAssetsBtn').click()
            expect(page.locator('#targetsInput')).to_have_value('192.0.2.1\n2001:db8::1\nexample.test')
            expect(page.locator('.scan-asset-choice:checked')).to_have_count(3)
            page.locator('.scan-asset-choice[value="2001:db8::1"]').uncheck()
            expect(page.locator('#targetsInput')).to_have_value('192.0.2.1\nexample.test')
            expect(page.locator('#scanTargetCount')).to_have_text('2 targets')
            page.locator('.scan-appliance-choice[value="node-1"]').check()
            for scanner, profile in [('openvas', 'network-policy'), ('zap', 'default')]:
                field = page.locator('.scanner-engine').filter(has=page.locator(f'input[value="{scanner}"]'))
                field.locator('input[type="checkbox"]').check()
                field.locator('select').select_option(profile)
            if recurring:
                page.locator('#recurringScanInput').check()
            page.locator('#scanForm button[type="submit"]').click()
            if recurring:
                expect(page.locator('#scanMessage')).to_contain_text('1 recurring schedule created.')
            else:
                expect(page.locator('#scan-tab.active')).to_be_visible()
                expect(page.locator('#scanLaunchResults')).to_contain_text('Run #777')
            requests = mock_state['schedule_requests'] if recurring else mock_state['scan_requests']
            assert len(requests) == 1
            assert requests[0]['targets'] == '192.0.2.1\nexample.test'
            assert requests[0]['appliances'][0]['node_id'] == 'node-1'
            assert requests[0]['appliances'][0]['selections'] == [
                {'scanner': 'openvas', 'profile_id': 'network-policy'},
                {'scanner': 'zap', 'profile_id': 'default'},
            ]
            assert mock_state['unexpected'] == []
        finally:
            browser.close()


@pytest.mark.parametrize('result', ['empty', 'error', 'removed'])
def test_asset_selection_handles_missing_approvals(darkstar_server, result):
    sync_api = pytest.importorskip('playwright.sync_api')
    expect = sync_api.expect
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page()
            mock_state = _install_dashboard_mocks(page, darkstar_server, role='tenant_admin')
            targets = ['192.0.2.1'] if result == 'removed' else []
            page.route('**/api/scan-scope', lambda route: _json(route,
                {'detail': 'Scope unavailable'} if result == 'error' else {'items': [{'target': target} for target in targets]},
                status=503 if result == 'error' else 200))
            page.goto(darkstar_server, wait_until='networkidle')
            page.locator('[data-tab="assets"]').click()
            if result == 'removed':
                page.locator('.approved-asset-choice').check()
                targets.clear()
                page.locator('#scanApprovedAssetsBtn').click()
                expect(page.locator('#scanMessage')).to_contain_text('could not be verified')
                expect(page.locator('#targetsInput')).to_have_value('')
            else:
                expect(page.locator('#approvedAssetsMessage')).to_contain_text('Scope unavailable' if result == 'error' else 'No targets are approved')
                expect(page.locator('#scanApprovedAssetsBtn')).to_be_disabled()
                page.locator('[data-tab="scan"]').click()
            expect(page.locator('#selectAllScanAssetsBtn')).to_be_disabled()
            assert mock_state['scan_requests'] == []
            assert mock_state['unexpected'] == []
        finally:
            browser.close()


def test_organization_switch_discards_old_assets_and_identity(darkstar_server):
    sync_api = pytest.importorskip('playwright.sync_api')
    expect = sync_api.expect
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page()
            mock_state = _install_dashboard_mocks(page, darkstar_server, role='tenant_admin')
            active_org = 'tenant_db'
            hold_old = False
            old_scope, old_identity, switches = [], [], []
            def identity():
                return {'authenticated': True, 'organization': 'Alpha' if active_org == 'tenant_db' else 'Beta',
                        'org_db': active_org, 'role': 'tenant_admin',
                        'organizations': [{'org_db_name': org, 'org_name': name} for org, name in [('tenant_db', 'Alpha'), ('other_tenant', 'Beta')]]}
            def me(route):
                if hold_old and active_org == 'tenant_db':
                    old_identity.append((route, identity()))
                else:
                    _json(route, identity())
            def scope(route):
                if hold_old and active_org == 'tenant_db':
                    old_scope.append(route)
                else:
                    _json(route, {'items': [{'target': '192.0.2.1' if active_org == 'tenant_db' else '198.51.100.1'}]})
            def switch(route):
                nonlocal active_org
                active_org = route.request.post_data_json['org_db']
                switches.append(route)
            page.route('**/api/me', me)
            page.route('**/api/scan-scope', scope)
            page.route('**/api/auth/select-organization', switch)
            page.goto(darkstar_server, wait_until='networkidle')
            page.locator('[data-tab="assets"]').click()
            expect(page.locator('#approvedAssetRows')).to_contain_text('192.0.2.1')
            hold_old = True
            with page.expect_request('**/api/scan-scope'):
                page.locator('#refreshApprovedAssetsBtn').click()
            with page.expect_request('**/api/me'):
                page.evaluate('() => { void refreshDashboard(); }')
            with page.expect_request('**/api/auth/select-organization'):
                page.locator('#tenantSwitchSelect').select_option('other_tenant')
            expect(page.locator('#approvedAssetRows')).to_have_text('')
            # The cookie can change while the switch response is still pending.
            page.locator('[data-tab="scan"]').click()
            page.locator('#targetsInput').fill('198.51.100.1')
            page.locator('#scanForm button[type="submit"]').click()
            assert mock_state['scan_requests'] == []
            _json(switches.pop(), identity())
            expect(page.locator('#topOrganizationName')).to_have_text('Beta')
            expect(page.locator('#dashboard-tab.active')).to_be_visible()
            expect(page.locator('#targetsInput')).to_have_value('')
            page.locator('[data-tab="assets"]').click()
            expect(page.locator('#approvedAssetRows')).to_contain_text('198.51.100.1')
            with page.expect_response('**/api/scan-scope'):
                _json(old_scope.pop(), {'items': [{'target': '192.0.2.1'}]})
            with page.expect_response('**/api/me'):
                route, payload = old_identity.pop()
                _json(route, payload)
            page.evaluate('() => new Promise(resolve => requestAnimationFrame(resolve))')
            expect(page.locator('#topOrganizationName')).to_have_text('Beta')
            expect(page.locator('#approvedAssetRows')).not_to_contain_text('192.0.2.1')
            expect(page.locator('#approvedAssetRows')).to_contain_text('198.51.100.1')
            assert mock_state['unexpected'] == []
        finally:
            browser.close()


@pytest.mark.parametrize('tab', ['assets', 'scan'])
def test_identity_refresh_clears_previous_organization_assets(darkstar_server, tab):
    sync_api = pytest.importorskip('playwright.sync_api')
    expect = sync_api.expect
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page()
            mock_state = _install_dashboard_mocks(page, darkstar_server, role='tenant_admin')
            active_org = 'tenant_db'
            page.route('**/api/me', lambda route: _json(route, {
                'authenticated': True, 'organization': 'Alpha' if active_org == 'tenant_db' else 'Beta',
                'org_db': active_org, 'role': 'tenant_admin',
            }))
            page.route('**/api/scan-scope', lambda route: _json(route, {'items': [{
                'target': '192.0.2.1' if active_org == 'tenant_db' else '198.51.100.1',
            }]}))
            page.goto(darkstar_server, wait_until='networkidle')
            page.locator(f'[data-tab="{tab}"]').click()
            expect(page.locator('#approvedAssetRows')).to_contain_text('192.0.2.1')
            if tab == 'scan':
                page.locator('.scan-asset-choice').check()
                expect(page.locator('#targetsInput')).to_have_value('192.0.2.1')
                page.locator('.scan-appliance-choice').check()
                openvas = page.locator('.scanner-engine').filter(has=page.locator('input[value="openvas"]'))
                openvas.locator('.scanner-choice').check()
                openvas.locator('select').select_option('network-policy')
                page.locator('#scanNameInput').fill('Alpha private scan')
            # A second browser tab changes the session; this tab discovers it via /api/me.
            active_org = 'other_tenant'
            page.evaluate('() => refreshDashboard()')
            expect(page.locator('#topOrganizationName')).to_have_text('Beta')
            expect(page.locator('#dashboard-tab.active')).to_be_visible()
            expect(page.locator('#approvedAssetRows')).to_have_text('')
            expect(page.locator('#targetsInput')).to_have_value('')
            expect(page.locator('.scan-appliance-choice:checked')).to_have_count(0)
            expect(page.locator('#scanNameInput')).to_have_value('')
            page.locator('[data-tab="assets"]').click()
            expect(page.locator('#approvedAssetRows')).to_contain_text('198.51.100.1')
            expect(page.locator('#approvedAssetRows')).not_to_contain_text('192.0.2.1')
            assert mock_state['scan_requests'] == []
            assert mock_state['unexpected'] == []
        finally:
            browser.close()


def test_scan_builder_requires_appliance_scanner_and_installed_policy(darkstar_server):
    sync_api = pytest.importorskip('playwright.sync_api')
    expect = sync_api.expect
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page()
            mock_state = _install_dashboard_mocks(page, darkstar_server, role='platform_admin')
            page.goto(darkstar_server, wait_until='networkidle')
            page.locator('[data-tab="scan"]').click()
            page.locator('#targetsInput').fill('192.0.2.1')
            page.locator('#launchScanBtn').click()
            expect(page.locator('#scanMessage')).to_have_text('Select at least one connected appliance.')
            page.locator('.scan-appliance-choice[value="node-1"]').check()
            expect(page.locator('.scanner-appliance-status')).to_have_text('Online · 0 active jobs · capacity 2')
            page.locator('#launchScanBtn').click()
            expect(page.locator('#scanMessage')).to_have_text('Choose at least one scanner on each selected appliance.')
            openvas = page.locator('.scanner-engine').filter(has=page.locator('input[value="openvas"]'))
            openvas.locator('.scanner-choice').check()
            page.locator('#launchScanBtn').click()
            expect(page.locator('#scanMessage')).to_have_text('Choose a profile for each selected scanner.')
            assert mock_state['scan_requests'] == []
            expect(openvas.locator('.profile-search')).to_be_hidden()
            expect(openvas.locator('.profile-pagination')).to_be_hidden()
            openvas.locator('select').select_option('network-policy')
            page.locator('#launchScanBtn').click()
            expect(page.locator('#scanLaunchResults')).to_contain_text('Run #777')
            assert mock_state['scan_requests'][-1]['appliances'] == [
                {'node_id': 'node-1', 'selections': [{'scanner': 'openvas', 'profile_id': 'network-policy'}]}]
            assert mock_state['unexpected'] == []
        finally:
            browser.close()


def test_profile_catalog_deduplicates_pending_loads_and_retries_empty_catalog(darkstar_server):
    sync_api = pytest.importorskip('playwright.sync_api')
    expect = sync_api.expect
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page()
            mock_state = _install_dashboard_mocks(page, darkstar_server, role='platform_admin')
            catalog_requests = []
            def catalog(route):
                catalog_requests.append(route)
                if len(catalog_requests) > 1:
                    _json(route, {'items': [], 'scanners': ['openvas'], 'total': 1})
            page.route('**/api/scanner-nodes/node-1/profiles?limit=1', catalog)
            page.goto(darkstar_server, wait_until='networkidle')
            with page.expect_request('**/api/scanner-nodes/node-1/profiles?limit=1'):
                page.locator('[data-tab="scan"]').click()
            with page.expect_response('**/api/scanner-nodes/available') as available:
                page.locator('[data-tab="scan"]').click()
            available.value.finished()
            page.evaluate('() => new Promise(resolve => requestAnimationFrame(resolve))')
            assert len(catalog_requests) == 1
            _json(catalog_requests[0], {'items': [], 'scanners': [], 'total': 0})
            expect(page.locator('.scanner-appliance-engines')).to_have_text('No installed profiles reported')
            with page.expect_response('**/api/scanner-nodes/node-1/profiles?limit=1'):
                page.locator('[data-tab="scan"]').click()
            assert len(catalog_requests) == 2
            page.locator('.scan-appliance-choice[value="node-1"]').check()
            page.locator('.scanner-choice[value="openvas"]').check()
            openvas = page.locator('.scanner-engine').filter(has=page.locator('input[value="openvas"]'))
            expect(openvas.locator('select option')).to_have_count(2)
            openvas.locator('select').select_option('network-policy')
            expect(openvas.locator('select')).to_have_value('network-policy')
            assert mock_state['scan_requests'] == []
            assert mock_state['unexpected'] == []
        finally:
            browser.close()


def test_unattached_appliance_is_disabled_while_connected_profiles_are_available(darkstar_server):
    sync_api = pytest.importorskip('playwright.sync_api')
    expect = sync_api.expect
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page()
            mock_state = _install_dashboard_mocks(page, darkstar_server, role='platform_admin')
            page.route('**/api/scanner-nodes/available', lambda route: _json(route, {'items': [
                {'node_id': 'unattached', 'name': 'openvas', 'status': 'registered', 'last_seen_at': None},
                {'node_id': 'node-1', 'name': 'local-scanner', 'status': 'online',
                 'last_seen_at': datetime.now(timezone.utc).replace(tzinfo=None).isoformat()},
            ]}))
            page.goto(darkstar_server, wait_until='networkidle')
            page.locator('[data-tab="scan"]').click()
            expect(page.locator('.scan-appliance-choice[value="node-1"]')).to_be_enabled()
            expect(page.locator('.scan-appliance-choice[value="unattached"]')).to_be_disabled()
            expect(page.locator('.scanner-appliance-card[data-node-id="unattached"]')).to_contain_text('Not connected')
            page.locator('.scan-appliance-choice[value="node-1"]').check()
            page.locator('.scanner-choice[value="openvas"]').check()
            openvas = page.locator('.scanner-engine').filter(has=page.locator('input[value="openvas"]'))
            expect(openvas.locator('select')).to_be_visible()
            expect(openvas.locator('select option')).to_have_count(2)
            assert mock_state['scan_requests'] == []
            assert mock_state['unexpected'] == []
        finally:
            browser.close()


def test_large_profile_catalog_keeps_selection_during_paging_and_search(darkstar_server):
    sync_api = pytest.importorskip('playwright.sync_api')
    expect = sync_api.expect
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page()
            mock_state = _install_dashboard_mocks(page, darkstar_server, role='tenant_admin')
            profiles = [{'scanner': 'nuclei', 'id': f'template-{number}', 'name': f'Template {number:03}'}
                        for number in range(120)]

            def catalog(route):
                query = parse_qs(urlparse(route.request.url).query)
                search = query.get('search', [''])[0].lower()
                offset = int(query.get('offset', ['0'])[0])
                limit = int(query.get('limit', ['100'])[0])
                matches = [item for item in profiles if search in item['name'].lower()]
                _json(route, {'scanners': ['nuclei'], 'total': len(matches), 'items': matches[offset:offset + limit]})

            page.route('**/api/scanner-nodes/node-1/profiles?*', catalog)
            page.goto(darkstar_server, wait_until='networkidle')
            page.locator('[data-tab="scan"]').click()
            page.locator('.scan-appliance-choice').check()
            field = page.locator('.scanner-engine')
            field.locator('.scanner-choice').check()
            expect(field.locator('.profile-search')).to_be_visible()
            expect(field.locator('.profile-count')).to_have_text('1–100 of 120')
            field.locator('select').select_option('template-0')
            field.locator('.profile-next').click()
            expect(field.locator('.profile-count')).to_have_text('101–120 of 120')
            expect(field.locator('select')).to_have_value('template-0')
            expect(field.locator('select option')).to_have_count(22)  # blank, retained selection, current page
            field.locator('[type="search"]').fill('119')
            expect(field.locator('select option')).to_have_count(3)
            expect(field.locator('select')).to_have_value('template-0')
            field.locator('select').select_option('template-119')
            expect(page.locator('#scanLaunchPlan')).to_contain_text('Nuclei / Template 119')
            page.locator('#targetsInput').fill('192.0.2.1')
            page.locator('#launchScanBtn').click()
            expect(page.locator('#scanLaunchResults')).to_contain_text('Run #777')
            assert mock_state['scan_requests'][-1]['appliances'] == [
                {'node_id': 'node-1', 'selections': [{'scanner': 'nuclei', 'profile_id': 'template-119'}]}]
            assert mock_state['unexpected'] == []
        finally:
            browser.close()
