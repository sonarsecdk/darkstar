"""A short mobile viewport must be able to scroll past the admin navigation."""
import pytest

from test_dashboard_workflows import _install_dashboard_mocks, _json


pytestmark = pytest.mark.playwright


@pytest.mark.parametrize('theme', ['midnight', 'daylight'])
@pytest.mark.parametrize('size', [(320, 568), (390, 844)])
def test_short_mobile_can_reach_asset_content(darkstar_server, theme, size):
    from playwright.sync_api import sync_playwright, expect

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={'width': size[0], 'height': size[1]})
        _install_dashboard_mocks(page, darkstar_server, role='platform_admin')
        page.route('**/api/me', lambda route: _json(route, {
            'authenticated': True, 'organization': 'Development Alpha', 'org_db': 'tenant_db',
            'role': 'platform_admin', 'user': {'id': 1, 'theme': theme},
            'organizations': [{'org_db_name': 'tenant_db', 'org_name': 'Development Alpha'},
                              {'org_db_name': 'other_tenant', 'org_name': 'Development Beta'}],
        }))
        page.route('**/api/asset-inventory', lambda route: _json(route, {'items': [], 'pending_count': 0}))
        page.route('**/api/discoveries', lambda route: _json(route, {'items': [], 'available': True}))
        page.goto(darkstar_server, wait_until='networkidle')
        page.locator('[data-tab="assets"]').click()
        page.evaluate('window.scrollTo({top: 0, behavior: "instant"})')
        page.mouse.move(size[0] // 2, size[1] // 2)
        page.mouse.wheel(0, 500)
        page.wait_for_function('window.scrollY > 0')
        expect(page.locator('#assetDiscoveryPanel > summary')).to_be_in_viewport()
        page.locator('#assetDiscoveryPanel > summary').click()
        page.locator('#discoveryTargetsInput').fill('192.0.2.10')
        expect(page.locator('#discoveryTargetsInput')).to_be_in_viewport()
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        browser.close()
