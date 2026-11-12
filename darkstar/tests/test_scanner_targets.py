import socket

import pytest

from darkstar.core.scan_scope import ScanScopeError
from darkstar.core.scanner_targets import require_enabled_scanner, zap_targets


def test_host_approval_engine_rule_covers_all_ports():
    rules = [{'target': '192.0.2.1', 'enabled_scanners': ['zap']}]
    require_enabled_scanner(['http://192.0.2.1:3000/'], 'zap', rules)
    require_enabled_scanner(['https://192.0.2.1:8443/'], 'zap', rules)
    with pytest.raises(ScanScopeError, match='not enabled'):
        require_enabled_scanner(['192.0.2.1'], 'openvas', rules)


def test_network_scan_cannot_bypass_a_restricted_child_host():
    rules = [{'target': '192.0.2.1', 'enabled_scanners': ['zap']}]
    with pytest.raises(ScanScopeError, match='not enabled'):
        require_enabled_scanner(['192.0.2.0/24'], 'openvas', rules)


def test_domain_alias_cannot_bypass_ip_scanner_rules(monkeypatch):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.1', 0))])
    with pytest.raises(ScanScopeError, match='not enabled'):
        require_enabled_scanner(['https://app.example.test/'], 'zap', [{'target': '192.0.2.1', 'enabled_scanners': []}])


def test_modes_require_explicit_scanners_for_restricted_assets():
    with pytest.raises(ScanScopeError, match='instead of a scan mode'):
        require_enabled_scanner(['192.0.2.1'], None, [{'target': '192.0.2.1', 'enabled_scanners': ['zap']}])
    require_enabled_scanner(['192.0.2.2'], None, [])


def test_nuclei_profiles_share_the_nuclei_permission():
    require_enabled_scanner(['192.0.2.1'], 'nucleinetwork', [{'target': '192.0.2.1', 'enabled_scanners': ['nuclei']}])


def test_bare_ip_and_domain_get_discovered_urls_without_port_approvals():
    inventory = [
        {'target': '192.0.2.1', 'approved': True, 'services': [{'url': 'http://192.0.2.1:3000/'}]},
        {'target': 'app.example.test', 'approved': True, 'services': [{'url': 'https://app.example.test:8443/'}]},
    ]
    assert zap_targets(['192.0.2.1', 'app.example.test'], inventory) == [
        'http://192.0.2.1:3000/', 'https://app.example.test:8443/',
    ]
    assert zap_targets(['https://app.example.test/specific'], inventory) == ['https://app.example.test/specific']


def test_network_expansion_only_uses_approved_web_inventory():
    inventory = [
        {'target': '192.0.2.1', 'approved': True, 'services': [{'url': 'http://192.0.2.1:3000/'}]},
        {'target': '192.0.2.2', 'approved': False, 'services': [{'url': 'http://192.0.2.2:3000/'}]},
        {'target': '198.51.100.1', 'approved': True, 'services': [{'url': 'http://198.51.100.1/'}]},
    ]
    assert zap_targets(['192.0.2.0/24'], inventory) == ['http://192.0.2.1:3000/']


def test_no_web_services_is_an_actionable_error_and_legacy_hosts_still_work():
    with pytest.raises(ScanScopeError, match='No discovered web applications'):
        zap_targets(['192.0.2.1'], [{'target': '192.0.2.1', 'approved': True, 'services': [], 'discovered_at': 'today'}])
    assert zap_targets(['192.0.2.1'], []) == ['192.0.2.1']
    with pytest.raises(ScanScopeError, match='HTTP or HTTPS'):
        zap_targets(['ftp://192.0.2.1/'], [])


@pytest.mark.parametrize('target', ['192.0.2.1:8443', 'app.example.test:3000', '[2001:db8::1]:8443'])
def test_explicit_ports_are_never_replaced_by_other_discovered_services(target):
    inventory = [{'target': '192.0.2.1', 'approved': True, 'services': [{'url': 'http://192.0.2.1:3000/'}]}]
    assert zap_targets([target], inventory) == ['http://' + target]


def test_bare_ipv6_web_target_is_bracketed():
    assert zap_targets(['2001:db8::1'], []) == ['http://[2001:db8::1]/']


def test_ipv6_network_expands_to_discovered_web_urls():
    inventory = [{'target': '2001:db8::1', 'approved': True,
                  'services': [{'url': 'https://[2001:db8::1]:8443/'}]}]
    assert zap_targets(['2001:db8::/120'], inventory) == ['https://[2001:db8::1]:8443/']


@pytest.mark.asyncio
async def test_worker_rechecks_engine_permissions_after_dns_changes(monkeypatch):
    from darkstar import main
    monkeypatch.setattr(main, 'get_allowed_scan_targets', lambda org: [{'target': target} for target in ['app.example.test', '192.0.2.0/24']])
    monkeypatch.setattr(main, 'get_asset_scanner_rules', lambda org: [{'target': '192.0.2.2', 'enabled_scanners': []}])
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.2', 0))])
    scanner = main.worker(None, 'zap', 'http://app.example.test:3000/', 'org_test')
    with pytest.raises(ScanScopeError, match='not enabled'):
        await scanner.run()
