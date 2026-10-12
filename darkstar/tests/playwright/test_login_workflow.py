"""Organization selection is a login step, not a second password submission."""
import pytest

from darkstar.tests.playwright.test_dashboard_workflows import _install_dashboard_mocks

pytestmark = pytest.mark.playwright


@pytest.fixture()
def login_page(darkstar_server):
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        mock = _install_dashboard_mocks(page, darkstar_server)
        page.route(f"{darkstar_server}/", lambda route: route.continue_())
        calls = {"login": 0, "organizations": [], "mfa": []}

        def login(route):
            calls["login"] += 1
            route.fulfill(json={
                "organization_required": True,
                "organizations": [
                    {"org_db": "tenant_db", "org_name": "Theme Studio", "role": "viewer"},
                    {"org_db": "tenant_b", "org_name": "Theme Lab", "role": "viewer"},
                ],
            })

        def select(route):
            calls["organizations"].append(route.request.post_data_json)
            route.fulfill(json={"ok": True, "org_db": "tenant_db", "organization": "Theme Studio", "role": "viewer", "user": {"id": 12, "theme": "darkstar"}})

        page.route("**/api/auth/login", login)
        page.route("**/api/auth/select-organization", select)
        page.route("**/api/auth/logout", lambda route: route.fulfill(json={"ok": True}))
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        yield page, calls, darkstar_server
        browser.close()
        assert not errors
        assert not mock["unexpected"]


def submit_credentials(page, base_url):
    page.goto(base_url, wait_until="networkidle")
    page.locator("#emailInput").fill("viewer@example.test")
    page.locator("#passwordInput").fill("TestPassword1!")
    page.locator("#loginSubmitBtn").click()


@pytest.mark.parametrize("viewport", [(1366, 768), (390, 844), (844, 390)])
def test_organization_login_has_one_clear_next_action(login_page, viewport):
    from playwright.sync_api import expect

    page, calls, base_url = login_page
    page.set_viewport_size({"width": viewport[0], "height": viewport[1]})
    submit_credentials(page, base_url)
    organization = page.locator("#loginForm").get_by_label("Organization", exact=True)
    expect(organization).to_be_visible()
    expect(page.locator("#loginMessage")).to_contain_text("Password accepted")
    expect(page.locator("#emailInput")).to_be_hidden()
    expect(page.locator("#ssoLoginBtn")).to_be_hidden()
    expect(page.locator('#loginForm button[type="submit"]:visible')).to_have_count(1)
    expect(page.get_by_role("button", name="Open organization", exact=True)).to_be_visible()
    assert page.locator(".login-container").evaluate("el => getComputedStyle(el).overflowY") == "auto"
    organization.select_option("tenant_db")
    page.get_by_role("button", name="Open organization", exact=True).press("Enter")
    expect(page.locator("#mainDashboard")).to_be_visible()
    assert calls["login"] == 1
    assert calls["organizations"] == [{"org_db": "tenant_db"}]
    page.locator("#logoutBtn").click()
    expect(page.locator("#emailInput")).to_be_visible()
    expect(page.locator("#emailInput")).to_be_enabled()
    expect(page.locator("#passwordInput")).to_have_value("")
    expect(page.locator("#orgChoiceGroup")).to_be_hidden()
    expect(page.get_by_role("button", name="Sign In", exact=True)).to_be_visible()


@pytest.mark.parametrize("challenge,endpoint", [("mfa_required", "verify"), ("mfa_setup_required", "enable")])
def test_organization_selection_continues_to_mfa(login_page, challenge, endpoint):
    from playwright.sync_api import expect

    page, calls, base_url = login_page
    page.route("**/api/auth/select-organization", lambda route: route.fulfill(json={challenge: True, "secret": "TESTSECRET", "otpauth_url": "otpauth://totp/test"}))

    def verify(route):
        calls["mfa"].append(route.request.post_data_json)
        route.fulfill(json={"ok": True, "org_db": "tenant_db", "organization": "Theme Studio", "role": "viewer", "user": {"id": 12, "theme": "darkstar"}})

    page.route(f"**/api/auth/mfa/{endpoint}", verify)
    submit_credentials(page, base_url)
    page.get_by_role("button", name="Open organization", exact=True).click()
    expect(page.locator("#orgChoiceGroup")).to_be_hidden()
    expect(page.locator("#passwordInput")).to_be_disabled()
    expect(page.get_by_role("button", name="Verify code", exact=True)).to_be_visible()
    page.locator("#mfaCodeInput").fill("123456")
    page.locator("#mfaCodeInput").press("Enter")
    expect(page.locator("#mainDashboard")).to_be_visible()
    assert calls["login"] == 1
    assert calls["mfa"] == [{"code": "123456"}]
