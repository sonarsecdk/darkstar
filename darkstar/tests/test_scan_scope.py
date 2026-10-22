import socket

import pytest

from darkstar.core.scan_scope import ScanScope, ScanScopeError, normalize_scope_entry


@pytest.mark.parametrize('entry,normalized', [('EXAMPLE.com.', 'example.com'), ('192.0.2.1', '192.0.2.1'),
                                             ('2001:db8::/32', '2001:db8::/32'), ('*.example.com', '*.example.com')])
def test_normalize_approval(entry, normalized):
    assert normalize_scope_entry(entry) == normalized


@pytest.mark.parametrize('entry', ['', '*', '*.com', 'https://example.com', 'example.com:443', '192.0.2.3/24', '../targets', 'fe80::1%eth0'])
def test_invalid_approvals(entry):
    with pytest.raises(ScanScopeError):
        normalize_scope_entry(entry)


@pytest.mark.parametrize('target,allowed', [
    ('example.com', True), ('https://example.com/path', True), ('https://EXAMPLE.com:8443/', True),
    ('sub.example.com', False), ('example.com.evil.test', False), ('https://example.com@evil.test', False),
    ('https://evil.test@example.com', False), ('file:///etc/passwd', False), ('-o', False),
    ('192.0.2.10', True), ('192.0.2.128/25', True), ('192.0.0.0/16', False),
    ('2001:db8::1', True), ('https://[2001:db8::1]:443/', True), ('2001:db9::1', False),
])
def test_target_boundaries(target, allowed):
    assert ScanScope(['example.com', '192.0.2.0/24', '2001:db8::/32']).allows(target) is allowed


def test_explicit_wildcard_excludes_apex_and_suffix_lookalikes():
    scope = ScanScope(['*.example.com'])
    assert scope.allows('a.b.example.com')
    assert not scope.allows('example.com')
    assert not scope.allows('notexample.com')
    assert not scope.allows('example.com.evil.test')


def test_empty_scope_blocks_every_scan():
    with pytest.raises(ScanScopeError, match='No scan targets'):
        ScanScope([]).require(['192.0.2.1'])


def test_new_dns_addresses_require_explicit_approval(monkeypatch):
    scope = ScanScope(['example.com', '192.0.2.1'])
    def resolve(host, *args, **kwargs):
        assert host == 'example.com'
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.1', 0))]
    monkeypatch.setattr(socket, 'getaddrinfo', resolve)
    scope.require(['https://example.com/'])
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.2', 0))])
    with pytest.raises(ScanScopeError, match='unapproved IP 192.0.2.2'):
        scope.require(['example.com'])


def test_dns_failure_does_not_allow_a_scan(monkeypatch):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *args, **kwargs: (_ for _ in ()).throw(socket.gaierror('unresolved')))
    with pytest.raises(ScanScopeError, match='Cannot verify DNS'):
        ScanScope(['example.com']).require(['example.com'])


@pytest.mark.asyncio
async def test_cli_checks_scope_before_executing_any_scanner(monkeypatch):
    from darkstar import main
    from unittest.mock import AsyncMock
    monkeypatch.setattr(main, 'get_allowed_scan_targets', lambda org: [])
    scanner = main.worker(None, 'nuclei', '192.0.2.1', 'org')
    execute = AsyncMock()
    monkeypatch.setattr(scanner, '_run_scanners', execute)
    with pytest.raises(ScanScopeError, match='No scan targets are approved'):
        await scanner.run()
    execute.assert_not_called()


@pytest.mark.asyncio
async def test_later_scanner_stage_rechecks_dns(monkeypatch):
    from darkstar import main
    from unittest.mock import Mock
    from darkstar.core.scan_scope import scan_scope_context
    scanner = main.worker(None, 'nuclei', 'example.test', 'org')
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.2', 0))])
    native = Mock()
    monkeypatch.setattr(main, 'NucleiScanner', native)
    with scan_scope_context(ScanScope(['example.test', '192.0.2.1'])):
        with pytest.raises(ScanScopeError, match='unapproved IP'):
            await scanner.run_nuclei('example.test')
    native.assert_not_called()
