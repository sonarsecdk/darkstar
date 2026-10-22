import json
from pathlib import Path

import pytest

from darkstar.tests.playwright.test_dashboard_workflows import _install_dashboard_mocks

pytestmark = pytest.mark.playwright


@pytest.fixture()
def theme_page(darkstar_server):
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 1050})
        mock = _install_dashboard_mocks(page, darkstar_server)
        account = {"id": 12, "email": "viewer@example.test", "theme": "darkstar"}
        changes = []
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))

        def me(route):
            route.fulfill(json={"authenticated": True, "organization": "Acme Security", "org_db": "tenant_db", "role": "viewer", "user": account, "organizations": []})

        def save(route):
            payload = route.request.post_data_json
            changes.append(payload)
            account["theme"] = payload["theme"]
            route.fulfill(json={"theme": account["theme"]})

        page.route("**/api/me", me)
        page.route("**/api/me/theme", save)
        page.goto(darkstar_server, wait_until="networkidle")
        yield page, account, changes, errors
        browser.close()
        assert not errors
        assert not mock["unexpected"]


@pytest.mark.parametrize("theme", ["darkstar", "midnight", "daylight", "aurora", "sandstone"])
def test_theme_picker_saves_and_restores_for_viewers(theme_page, theme):
    from playwright.sync_api import expect

    page, account, changes, _ = theme_page
    page.locator('[data-tab="settings"]').click()
    if theme == "darkstar":
        page.get_by_role("radio", name="Midnight", exact=True).check()
        expect(page.locator("html")).to_have_attribute("data-theme", "midnight")
    choice = page.locator(f'input[name="theme"][value="{theme}"]')
    expect(choice).to_be_enabled()
    choice.check()
    expect(page.locator("html")).to_have_attribute("data-theme", theme)
    expect(page.locator("#themeMessage")).to_have_text("Theme saved to your account.")
    assert changes[-1] == {"theme": theme}
    assert account["theme"] == theme
    output = Path("test-results/playwright")
    output.mkdir(parents=True, exist_ok=True)
    page.locator(".appearance-card").screenshot(path=str(output / f"theme-{theme}-picker.png"))
    page.locator('[data-tab="dashboard"]').click()
    page.screenshot(path=str(output / f"theme-{theme}-dashboard.png"), animations="disabled")
    # A new page load obtains the account preference from /api/me.
    page.reload(wait_until="networkidle")
    expect(page.locator("html")).to_have_attribute("data-theme", theme)
    assert page.evaluate('severityPalette.high === themeColor("--sev-high")')
    assert page.evaluate('getComputedStyle(document.body).color !== getComputedStyle(document.body).backgroundColor')


def test_failed_save_preserves_previous_theme(theme_page):
    from playwright.sync_api import expect

    page, _, _, _ = theme_page
    page.route("**/api/me/theme", lambda route: route.fulfill(status=503, json={"detail": "Database unavailable"}))
    page.locator('[data-tab="settings"]').click()
    page.get_by_role("radio", name="Daylight", exact=True).check()
    expect(page.locator("#themeMessage")).to_contain_text("Could not save theme")
    expect(page.locator("html")).to_have_attribute("data-theme", "darkstar")
    expect(page.get_by_role("radio", name="Darkstar", exact=True)).to_be_checked()
    expect(page.get_by_role("radio", name="Daylight", exact=True)).to_be_enabled()


def test_theme_picker_supports_keyboard_and_mobile(theme_page):
    from playwright.sync_api import expect

    page, _, _, _ = theme_page
    page.set_viewport_size({"width": 390, "height": 844})
    page.locator('[data-tab="settings"]').click()
    page.get_by_role("radio", name="Darkstar", exact=True).focus()
    page.keyboard.press("ArrowRight")
    expect(page.locator("html")).to_have_attribute("data-theme", "midnight")
    expect(page.get_by_role("radio", name="Midnight", exact=True)).to_be_checked()
    expect(page.get_by_role("radio", name="Midnight", exact=True)).to_be_focused()
    page.keyboard.press("ArrowRight")
    expect(page.locator("html")).to_have_attribute("data-theme", "daylight")
    expect(page.get_by_role("radio", name="Daylight", exact=True)).to_be_focused()
    card = page.locator(".appearance-card").bounding_box()
    assert card["x"] >= 0 and card["x"] + card["width"] <= 391
    assert page.locator("#themeChoices").evaluate("el => el.scrollWidth <= el.clientWidth")
    output = Path("test-results/playwright")
    output.mkdir(parents=True, exist_ok=True)
    page.locator(".appearance-card").screenshot(path=str(output / "theme-picker-mobile.png"))


def test_account_change_and_logout_do_not_reuse_another_users_theme(theme_page):
    from playwright.sync_api import expect

    page, account, _, _ = theme_page
    page.locator('[data-tab="settings"]').click()
    page.get_by_role("radio", name="Aurora", exact=True).check()
    expect(page.locator("html")).to_have_attribute("data-theme", "aurora")
    account.update(id=34, email="other@example.test", theme="daylight")
    page.evaluate("refreshDashboard()")
    expect(page.locator("html")).to_have_attribute("data-theme", "daylight")
    page.route("**/api/auth/logout", lambda route: route.fulfill(json={"ok": True}))
    page.locator("#logoutBtn").click()
    expect(page.locator("html")).to_have_attribute("data-theme", "darkstar")
    assert page.evaluate("localStorage.length") == 0


def test_legacy_login_cannot_save_personal_preferences(theme_page):
    from playwright.sync_api import expect

    page, _, _, _ = theme_page
    page.route("**/api/scanner-nodes", lambda route: route.fulfill(json={"items": []}))
    page.route("**/api/me", lambda route: route.fulfill(json={"authenticated": True, "organization": "Legacy", "role": "platform_admin", "user": None}))
    page.evaluate("refreshDashboard()")
    page.locator('[data-tab="settings"]').click()
    expect(page.locator("#themeMessage")).to_contain_text("personal account")
    expect(page.get_by_role("radio", name="Daylight", exact=True)).to_be_disabled()


def test_slow_dashboard_refresh_cannot_undo_a_saved_theme(theme_page):
    from playwright.sync_api import expect

    page, _, _, _ = theme_page
    pending = []
    page.route("**/api/me", lambda route: pending.append(route))
    with page.expect_request("**/api/me"):
        page.evaluate("window.pendingRefresh = refreshDashboard(); void 0")
    page.locator('[data-tab="settings"]').click()
    page.get_by_role("radio", name="Daylight", exact=True).check()
    expect(page.locator("#themeMessage")).to_have_text("Theme saved to your account.")
    assert len(pending) == 1
    pending[0].fulfill(json={"authenticated": True, "organization": "Acme Security", "role": "viewer", "user": {"id": 12, "theme": "darkstar"}})
    page.evaluate("window.pendingRefresh")
    expect(page.locator("html")).to_have_attribute("data-theme", "daylight")


def test_pending_save_cannot_apply_after_logout(theme_page):
    from playwright.sync_api import expect

    page, _, _, _ = theme_page
    pending = []
    page.route("**/api/me/theme", lambda route: pending.append(route))
    page.route("**/api/auth/logout", lambda route: route.fulfill(json={"ok": True}))
    page.locator('[data-tab="settings"]').click()
    page.get_by_role("radio", name="Aurora", exact=True).check()
    expect(page.locator("#themeMessage")).to_have_text("Saving your theme…")
    page.locator("#logoutBtn").click()
    expect(page.locator("#loginScreen")).to_be_visible()
    assert len(pending) == 1
    with page.expect_response("**/api/me/theme"):
        pending[0].fulfill(json={"theme": "aurora"})
    expect(page.locator("html")).to_have_attribute("data-theme", "darkstar")


def test_organization_switch_during_save_keeps_picker_usable(theme_page):
    from playwright.sync_api import expect

    page, account, _, _ = theme_page
    pending = []
    page.route("**/api/me/theme", lambda route: pending.append(route))
    page.locator('[data-tab="settings"]').click()
    page.get_by_role("radio", name="Aurora", exact=True).check()
    expect(page.locator("#themeMessage")).to_have_text("Saving your theme…")
    page.evaluate("user => completeAuth({organization: 'Another tenant', org_db: 'tenant_b', role: 'viewer', user})", account)
    expect(page.get_by_role("radio", name="Daylight", exact=True)).to_be_enabled()
    with page.expect_response("**/api/me/theme"):
        pending[0].fulfill(json={"theme": "aurora"})
    expect(page.get_by_role("radio", name="Daylight", exact=True)).to_be_enabled()
    expect(page.locator("html")).to_have_attribute("data-theme", "darkstar")
