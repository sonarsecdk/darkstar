import json
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


def _install_dashboard_mocks(page, base_url):
    state = {
        "scan_requests": [],
        "schedule_requests": [],
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
            'data-organization="Acme Security" data-org-db="tenant_db"',
        )
        html = html.replace('data-role=""', 'data-role="tenant_admin"')
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
        for index, request in enumerate(state["scan_requests"], start=1):
            items.insert(
                0,
                {
                    "id": 776 + index,
                    "scan_name": request.get("scan_name") or "Playwright queued scan",
                    "scan_mode": str(request.get("mode") or request.get("scanner") or ""),
                    "status": "queued",
                    "targets": request.get("targets", ""),
                    "created_at": "2026-05-14T10:00:00Z",
                },
            )
        return {"items": items}

    def api_handler(route):
        request = route.request
        parsed = urlparse(request.url)
        path = parsed.path
        query = parse_qs(parsed.query)
        method = request.method.upper()

        if path == "/api/me":
            _json(
                route,
                {
                    "authenticated": True,
                    "organization": "Acme Security",
                    "org_db": "tenant_db",
                    "role": "tenant_admin",
                    "user": {"email": "analyst@example.org"},
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
            _json(route, {"ok": True, "scan_id": 776 + len(state["scan_requests"]), "status": "queued"})
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
        if path == "/api/scanner-nodes/available":
            _json(
                route,
                {"items": [{"node_id": "node-1", "name": "Office scanner", "status": "online", "running_jobs": 0, "max_parallel_jobs": 2}]},
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
            _json(route, {"ok": True, "schedule_id": 12})
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
            mock_state = _install_dashboard_mocks(page, darkstar_server)
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
            page.locator("#modeInput").select_option("2")
            page.locator("#applianceInput").select_option("node-1")
            page.get_by_role("button", name="Launch Scan").click()
            expect(page.locator("#debug-tab.active")).to_be_visible()
            expect(page.locator("#debugOutput")).to_contain_text("Queued for scanner workers")

            assert mock_state["scan_requests"][-1] == {
                "targets": "app.example.com, portal.example.com",
                "mode": 2,
                "scanner": None,
                "preferred_node_id": "node-1",
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
            mock_state = _install_dashboard_mocks(page, darkstar_server)
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


def test_scan_center_selects_profiles_and_keeps_them_in_schedules(darkstar_server):
    sync_api = pytest.importorskip('playwright.sync_api')
    expect = sync_api.expect
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page(viewport={"width": 1440, "height": 1200})
            state = _install_dashboard_mocks(page, darkstar_server)
            page.goto(f'{darkstar_server}/', wait_until='networkidle')
            page.locator('[data-tab="scan"]').click()
            page.locator('#applianceInput').select_option('node-1')
            page.locator('#targetsInput').fill('192.0.2.1')
            page.locator('#modeInput').select_option('2')
            openvas = page.locator('#scannerSelections fieldset').filter(has=page.locator('input[value="openvas"]'))
            zap = page.locator('#scannerSelections fieldset').filter(has=page.locator('input[value="zap"]'))
            openvas.locator('[type="checkbox"]').check()
            zap.locator('[type="checkbox"]').check()
            expect(page.locator('#modeInput')).to_have_value('')
            page.get_by_role('button', name='Launch Scan').click()
            expect(page.locator('#scanMessage')).to_have_text('Choose a profile for each selected scanner.')
            openvas.locator('select').select_option('network-policy')
            zap.locator('[type="search"]').fill('Recon')
            expect(zap.locator('select option')).to_have_count(2)
            zap.locator('select').select_option('default')
            page.get_by_role('button', name='Launch Scan').click()
            expect(page.locator('#debug-tab.active')).to_be_visible()
            selections = [{'scanner': 'openvas', 'profile_id': 'network-policy'}, {'scanner': 'zap', 'profile_id': 'default'}]
            assert state['scan_requests'][-1]['selections'] == selections
            assert state['scan_requests'][-1]['mode'] is None
            page.locator('[data-tab="scan"]').click()
            page.locator('#recurringScanInput').check()
            page.get_by_role('button', name='Launch Scan').click()
            expect(page.locator('#scanMessage')).to_have_text('Recurring scan created.')
            assert state['schedule_requests'][-1]['selections'] == selections
            page.locator('#modeInput').select_option('1')
            expect(openvas.locator('[type="checkbox"]')).not_to_be_checked()
            expect(zap.locator('[type="checkbox"]')).not_to_be_checked()
            assert state['unexpected'] == []
            page.screenshot(path='test-results/playwright/scanner-selection.png', full_page=True)
        finally:
            browser.close()
