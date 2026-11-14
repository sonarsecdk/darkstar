"""Asset discovery UI boundaries; network discovery is mocked, never executed."""
import copy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from test_dashboard_workflows import _install_dashboard_mocks, _json

pytestmark = pytest.mark.playwright


ASSETS = [
    {'target': '192.0.2.10', 'approved': True, 'addresses': ['192.0.2.10'],
     'services': [{'port': 22, 'protocol': 'tcp', 'service': 'ssh', 'url': None},
                  {'port': 3000, 'protocol': 'tcp', 'service': 'http', 'url': 'http://192.0.2.10:3000/'}],
     'compatible_scanners': ['openvas', 'zap', 'nuclei'], 'enabled_scanners': None,
     'discovered_at': '2026-11-12T10:00:00', 'source_node_id': 'node-1'},
    {'target': 'app.example.test', 'approved': True, 'addresses': ['203.0.113.20'],
     'services': [{'port': 8443, 'protocol': 'tcp', 'service': 'https', 'url': 'https://app.example.test:8443/'}],
     'compatible_scanners': ['openvas', 'zap', 'nuclei'], 'enabled_scanners': ['openvas', 'zap'],
     'discovered_at': '2026-11-12T10:00:00'},
    {'target': '198.51.100.30', 'approved': False, 'addresses': ['198.51.100.30'],
     'services': [{'port': 8080, 'protocol': 'tcp', 'service': 'http', 'url': 'http://198.51.100.30:8080/'}],
     'compatible_scanners': ['openvas', 'zap', 'nuclei'], 'enabled_scanners': None,
     'discovered_at': '2026-11-12T10:00:00'},
    {'target': 'new.example.test', 'approved': False, 'addresses': ['198.51.100.30'],
     'services': [{'port': 8080, 'protocol': 'tcp', 'service': 'http', 'url': 'http://new.example.test:8080/'}],
     'compatible_scanners': ['openvas', 'zap', 'nuclei'], 'enabled_scanners': None,
     'discovered_at': '2026-11-12T10:00:00'},
]


def install_inventory(page, base_url, role='platform_admin'):
    state = _install_dashboard_mocks(page, base_url, role=role)
    state.update(assets=copy.deepcopy(ASSETS), discoveries=[], discovery_available=True,
                 approvals=[], scanner_settings=[], management_reads=[])
    appliances = {'openvas': [{'node_id': 'network', 'name': 'Network scanner'}],
                  'zap': [{'node_id': 'web', 'name': 'Web scanner'}]}

    def inventory(route):
        # Include pending items deliberately: the UI should also hide them from members.
        _json(route, {'items': state['assets'], 'pending_count': sum(not item['approved'] for item in state['assets']),
                      'scanner_appliances': appliances})

    def scope(route):
        _json(route, {'items': [{'target': item['target']} for item in state['assets'] if item['approved']]})

    def discoveries(route):
        if route.request.method == 'POST':
            payload = route.request.post_data_json
            state['discoveries'].append({'id': 901, 'scan_name': 'Asset discovery', 'status': 'queued',
                                         'targets': payload['targets'], 'created_at': '2026-11-12T11:00:00', 'request': payload})
            _json(route, {'ok': True, 'scan_id': 901})
        else:
            state['management_reads'].append('/api/discoveries')
            _json(route, {'items': state['discoveries'], 'available': state['discovery_available']})

    def approve(route):
        payload = route.request.post_data_json
        state['approvals'].append(payload)
        if 'new.example.test' in payload['targets'] and '198.51.100.30' not in payload['targets']:
            _json(route, {'detail': 'new.example.test resolves to unapproved IP 198.51.100.30'}, status=403)
            return
        for asset in state['assets']:
            if asset['target'] in payload['targets']:
                asset['approved'] = True
                asset['enabled_scanners'] = payload['enabled_scanners']
        _json(route, {'items': state['assets'], 'scanner_appliances': appliances})

    def settings(route):
        payload = route.request.post_data_json
        state['scanner_settings'].append(payload)
        next(item for item in state['assets'] if item['target'] == payload['target'])['enabled_scanners'] = payload['enabled_scanners']
        _json(route, {'items': state['assets'], 'scanner_appliances': appliances})

    page.route('**/api/asset-inventory', inventory)
    page.route('**/api/scan-scope', scope)
    page.route('**/api/discoveries', discoveries)
    page.route('**/api/asset-inventory/approve', approve)
    page.route('**/api/asset-inventory/scanners', settings)
    page.route('**/api/scanner-nodes/node-no-discovery/profiles?*', lambda route: _json(route, {
        'scanners': [], 'items': [], 'total': 0,
    }))
    page.route('**/api/scanner-nodes/available', lambda route: _json(route, {'items': [
        {'node_id': 'node-1', 'name': 'Office discovery worker', 'status': 'online', 'discovery_supported': True,
         'last_seen_at': datetime.now(timezone.utc).replace(tzinfo=None).isoformat(), 'running_jobs': 0, 'max_parallel_jobs': 1},
        {'node_id': 'node-no-discovery', 'name': 'Unsupported worker', 'status': 'online', 'discovery_supported': False,
         'last_seen_at': datetime.now(timezone.utc).replace(tzinfo=None).isoformat(), 'running_jobs': 0, 'max_parallel_jobs': 1},
    ]}))
    return state


@pytest.fixture
def browser():
    sync_api = pytest.importorskip('playwright.sync_api')
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        yield browser
        browser.close()


@pytest.mark.parametrize('role', ['viewer', 'security_analyst', 'tenant_admin'])
def test_members_see_whole_assets_and_services_without_management(browser, darkstar_server, role):
    from playwright.sync_api import expect
    page = browser.new_page()
    state = install_inventory(page, darkstar_server, role)
    page.goto(darkstar_server, wait_until='networkidle')
    page.locator('[data-tab="assets"]').click()
    expect(page.locator('#approvedAssetRows tr')).to_have_count(2)
    expect(page.locator('#approvedInventoryCount')).to_have_text('2')
    expect(page.locator('#discoveredServiceCount')).to_have_text('3')
    expect(page.locator('#assetDiscoveryPanel')).to_be_hidden()
    expect(page.locator('#pendingAssetsPanel')).to_be_hidden()
    expect(page.locator('.pending-asset-choice')).to_have_count(0)
    expect(page.locator('.asset-scanners-form')).to_have_count(0)
    row = page.locator('#approvedAssetRows tr').filter(has_text='192.0.2.10')
    row.locator('.asset-service-details summary').click()
    expect(row).to_contain_text('All ports approved')
    expect(row.locator('.asset-service-list')).to_contain_text('TCP 3000')
    expect(row.locator('.asset-service-list a')).to_have_attribute('href', 'http://192.0.2.10:3000/')
    expect(row.locator('.asset-service-list input')).to_have_count(0)
    assert state['management_reads'] == []
    assert state['unexpected'] == []
    page.close()


def test_platform_discovers_then_approves_whole_hosts(browser, darkstar_server):
    from playwright.sync_api import expect
    page = browser.new_page(viewport={'width': 1440, 'height': 1100})
    state = install_inventory(page, darkstar_server)
    page.goto(darkstar_server, wait_until='networkidle')
    page.locator('[data-tab="assets"]').click()
    expect(page.locator('#pendingAssetRows tr')).to_have_count(2)
    page.locator('#assetDiscoveryPanel > summary').click()
    expect(page.locator('#discoveryApplianceInput')).to_have_count(0)
    expect(page.locator('#pendingAssetRows')).to_contain_text('Available on: Web scanner')
    expect(page.locator('#pendingAssetRows')).to_contain_text('Available on: Network scanner')
    output = Path('test-results/playwright')
    output.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(output / 'asset-discovery-platform.png'), full_page=True)
    page.locator('#discoveryTargetsInput').fill('198.51.100.30\nnew.example.test')
    page.locator('#startAssetDiscoveryBtn').click()
    expect(page.locator('#assetDiscoveryRuns')).to_contain_text('queued')
    assert state['discoveries'][0]['request'] == {
        'targets': '198.51.100.30\nnew.example.test', 'port_mode': 'full'}
    state['discoveries'][0]['status'] = 'completed'
    page.locator('#refreshDiscoveriesBtn').click()
    expect(page.locator('#assetDiscoveryRuns')).to_contain_text('completed')
    page.locator('.pending-asset-choice[value="new.example.test"]').check()
    page.locator('#approveInventoryTargetsBtn').click()
    expect(page.locator('#assetApprovalMessage')).to_contain_text('unapproved IP 198.51.100.30')
    page.locator('#selectAllPendingAssetsBtn').click()
    page.locator('#approvalScannerChoices input[value="nuclei"]').uncheck()
    page.locator('#approveInventoryTargetsBtn').click()
    expect(page.locator('#pendingInventoryCount')).to_have_text('0')
    expect(page.locator('#approvedInventoryCount')).to_have_text('4')
    assert state['approvals'][-1] == {'targets': ['198.51.100.30', 'new.example.test'], 'enabled_scanners': ['openvas', 'zap']}
    assert all(':' not in target for target in state['approvals'][-1]['targets'])
    assert state['unexpected'] == []
    page.close()


def test_platform_sets_scanner_access_for_an_entire_asset(browser, darkstar_server):
    from playwright.sync_api import expect
    page = browser.new_page()
    state = install_inventory(page, darkstar_server)
    page.goto(darkstar_server, wait_until='networkidle')
    page.locator('[data-tab="assets"]').click()
    row = page.locator('#approvedAssetRows tr').filter(has_text='192.0.2.10')
    row.locator('.asset-scanner-settings > summary').click()
    form = row.locator('.asset-scanners-form')
    form.locator('[name="default_scanners"]').uncheck()
    form.locator('[value="openvas"]').uncheck()
    form.locator('[value="nuclei"]').uncheck()
    form.locator('button[type="submit"]').click()
    expect(form.locator('.form-message')).to_contain_text('saved for this whole asset')
    assert state['scanner_settings'][-1] == {'target': '192.0.2.10', 'enabled_scanners': ['zap']}
    expect(row.locator('.asset-scanner-badges')).to_contain_text('OpenVAS · disabled')
    form.locator('[name="default_scanners"]').check()
    form.locator('button[type="submit"]').click()
    expect(form.locator('.form-message')).to_contain_text('saved for this whole asset')
    assert state['scanner_settings'][-1]['enabled_scanners'] is None
    assert state['unexpected'] == []
    page.close()


def test_scanner_settings_display_inherited_restrictions(browser, darkstar_server):
    from playwright.sync_api import expect
    page = browser.new_page()
    state = install_inventory(page, darkstar_server)

    def inherited_settings(route):
        state['scanner_settings'].append(route.request.post_data_json)
        state['assets'][0]['enabled_scanners'] = ['openvas']
        _json(route, {'items': state['assets']})

    page.route('**/api/asset-inventory/scanners', inherited_settings)
    page.goto(darkstar_server, wait_until='networkidle')
    page.locator('[data-tab="assets"]').click()
    row = page.locator('#approvedAssetRows tr').filter(has_text='192.0.2.10')
    row.locator('.asset-scanner-settings > summary').click()
    form = row.locator('.asset-scanners-form')
    form.locator('button[type="submit"]').click()
    expect(form.locator('.form-message')).to_contain_text('saved for this whole asset')
    assert state['scanner_settings'][-1]['enabled_scanners'] is None
    expect(form.locator('[name="default_scanners"]')).not_to_be_checked()
    expect(form.locator('[value="openvas"]')).to_be_checked()
    expect(form.locator('[value="zap"]')).not_to_be_checked()
    expect(row.locator('.asset-scanner-badges')).to_contain_text('ZAP · disabled')
    page.close()


def test_role_change_hides_existing_asset_management_controls(browser, darkstar_server):
    from playwright.sync_api import expect
    page = browser.new_page()
    state = install_inventory(page, darkstar_server)
    page.goto(darkstar_server, wait_until='networkidle')
    page.locator('[data-tab="assets"]').click()
    expect(page.locator('.asset-scanner-settings').first).to_be_visible()
    page.evaluate("() => { state.role = 'tenant_admin'; applyRoleUI(); }")
    expect(page.locator('.asset-scanner-settings').first).to_be_hidden()
    expect(page.locator('#pendingAssetsPanel')).to_be_hidden()
    expect(page.locator('#assetDiscoveryPanel')).to_be_hidden()
    page.evaluate("() => document.getElementById('assetDiscoveryForm').dispatchEvent(new Event('submit', {cancelable: true}))")
    assert state['discoveries'] == []
    page.close()


def test_tenant_scans_a_host_without_selecting_each_service(browser, darkstar_server):
    from playwright.sync_api import expect
    page = browser.new_page()
    state = install_inventory(page, darkstar_server, 'tenant_admin')
    page.goto(darkstar_server, wait_until='networkidle')
    page.locator('[data-tab="assets"]').click()
    page.locator('.approved-asset-choice[value="192.0.2.10"]').check()
    page.locator('#scanApprovedAssetsBtn').click()
    expect(page.locator('#targetsInput')).to_have_value('192.0.2.10')
    expect(page.locator('#scanAssetChoices')).to_contain_text('Discovered web URLs are used for ZAP')
    assert state['scan_requests'] == []
    assert state['unexpected'] == []
    page.close()


def test_discovery_drafts_and_delayed_results_do_not_cross_organizations(browser, darkstar_server):
    from playwright.sync_api import expect
    page = browser.new_page()
    state = install_inventory(page, darkstar_server)
    active_org = 'tenant_db'
    held_inventory = []
    hold = False

    def identity():
        return {'authenticated': True, 'organization': 'Alpha' if active_org == 'tenant_db' else 'Beta',
                'org_db': active_org, 'role': 'platform_admin',
                'organizations': [{'org_db_name': 'tenant_db', 'org_name': 'Alpha'}, {'org_db_name': 'other_tenant', 'org_name': 'Beta'}]}

    def switch(route):
        nonlocal active_org
        active_org = route.request.post_data_json['org_db']
        _json(route, identity())

    def inventory(route):
        if hold and active_org == 'tenant_db':
            held_inventory.append(route)
        else:
            _json(route, {'items': state['assets'] if active_org == 'tenant_db' else [], 'pending_count': 0})

    page.route('**/api/me', lambda route: _json(route, identity()))
    page.route('**/api/auth/select-organization', switch)
    page.route('**/api/asset-inventory', inventory)
    page.goto(darkstar_server, wait_until='networkidle')
    page.locator('[data-tab="assets"]').click()
    expect(page.locator('.pending-asset-choice')).to_have_count(2)
    page.locator('#assetDiscoveryPanel > summary').click()
    page.locator('#discoveryTargetsInput').fill('private.alpha.example')
    hold = True
    with page.expect_request('**/api/asset-inventory'):
        page.locator('#refreshApprovedAssetsBtn').click()
    page.locator('#tenantSwitchSelect').select_option('other_tenant')
    expect(page.locator('#topOrganizationName')).to_have_text('Beta')
    expect(page.locator('#discoveryTargetsInput')).to_have_value('')
    page.locator('[data-tab="assets"]').click()
    expect(page.locator('#approvedInventoryCount')).to_have_text('0')
    with page.expect_response('**/api/asset-inventory'):
        _json(held_inventory.pop(), {'items': state['assets'], 'pending_count': 2})
    page.evaluate('() => new Promise(resolve => requestAnimationFrame(resolve))')
    expect(page.locator('#pendingAssetRows')).not_to_contain_text('new.example.test')
    expect(page.locator('#approvedAssetRows')).not_to_contain_text('192.0.2.10')
    expect(page.locator('#approveInventoryTargetsBtn')).to_be_disabled()
    assert state['unexpected'] == []
    page.close()


@pytest.mark.parametrize('theme', ['midnight', 'daylight'])
def test_inventory_controls_fit_mobile(browser, darkstar_server, theme):
    from playwright.sync_api import expect
    page = browser.new_page(viewport={'width': 390, 'height': 844})
    install_inventory(page, darkstar_server)
    page.route('**/api/me', lambda route: _json(route, {
        'authenticated': True, 'organization': 'Discovery Verification',
        'org_db': 'tenant_db', 'role': 'platform_admin', 'user': {'id': 1, 'theme': 'darkstar'},
        'organizations': [{'org_db_name': 'tenant_db', 'org_name': 'Discovery Verification'},
                          {'org_db_name': 'other_tenant', 'org_name': 'Other customer'}],
    }))
    page.goto(darkstar_server, wait_until='networkidle')
    page.evaluate('(theme) => document.documentElement.dataset.theme = theme', theme)
    page.locator('[data-tab="assets"]').click()
    page.locator('#assetDiscoveryPanel > summary').click()
    page.locator('#discoveryTargetsInput').fill('https://application.customer.example:8443/account')
    expect(page.locator('#discoveryPortModeInput')).to_be_visible()
    assert page.locator('#assetDiscoveryPanel').evaluate('(element) => element.scrollWidth <= element.clientWidth + 1')
    assert page.locator('#assets-tab').evaluate('(element) => element.scrollWidth <= element.clientWidth + 1')
    for selector in ('#tenantSwitchSelect', '#topRoleName', '#logoutBtn'):
        assert page.locator(selector).evaluate('(element) => { const box = element.getBoundingClientRect(); return box.left >= 0 && box.right <= innerWidth; }')
    output = Path('test-results/playwright')
    output.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(output / f'asset-discovery-mobile-{theme}.png'), full_page=True)
    page.close()


def test_discovery_unavailable_does_not_offer_an_appliance_picker(browser, darkstar_server):
    from playwright.sync_api import expect
    page = browser.new_page()
    state = install_inventory(page, darkstar_server)
    state['discovery_available'] = False
    page.goto(darkstar_server, wait_until='networkidle')
    page.locator('[data-tab="assets"]').click()
    page.locator('#assetDiscoveryPanel > summary').click()
    expect(page.locator('#startAssetDiscoveryBtn')).to_be_disabled()
    expect(page.locator('#assetDiscoveryMessage')).to_contain_text('No discovery worker is online')
    expect(page.locator('#discoveryApplianceInput')).to_have_count(0)
    assert state['discoveries'] == []
    state['discovery_available'] = True
    page.locator('#refreshApprovedAssetsBtn').click()
    expect(page.locator('#startAssetDiscoveryBtn')).to_be_enabled()
    expect(page.locator('#assetDiscoveryMessage')).not_to_contain_text('No discovery worker is online')
    page.close()
