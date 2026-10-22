"""Approved target matching shared by the API and scanner runner."""
from contextlib import contextmanager
from contextvars import ContextVar
import ipaddress
import re
import socket
from urllib.parse import urlsplit


class ScanScopeError(ValueError):
    pass


def _hostname(value: str) -> str:
    value = value.rstrip('.').lower()
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise ScanScopeError('Invalid hostname') from exc
    if len(value) > 253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', value):
        raise ScanScopeError('Invalid hostname')
    return value


def normalize_scope_entry(value: str) -> str:
    value = value.strip()
    if not value or '%' in value or '\\' in value:
        raise ScanScopeError('Allowed targets must be IPs, CIDRs, hostnames, or *.domain patterns')
    try:
        network = ipaddress.ip_network(value, strict=True)
        return str(network) if '/' in value else str(network.network_address)
    except ValueError:
        if '/' in value or ':' in value:
            raise ScanScopeError('Use an IP, a CIDR with no host bits, or a hostname without a URL/port')
    return '*.' + _hostname(value[2:]) if value.startswith('*.') else _hostname(value)


def target_host(value: str):
    value = value.strip()
    if not value or any(c.isspace() or ord(c) < 32 for c in value) or '\\' in value or '%' in value.split('/')[0]:
        raise ScanScopeError('Invalid scan target')
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        pass
    try:
        url = urlsplit(value if '://' in value else '//' + value)
        if url.scheme and url.scheme.lower() not in {'http', 'https', 'ftp'}:
            raise ValueError('Unsupported scheme')
        if url.username is not None or url.password is not None or not url.hostname:
            raise ValueError('Invalid authority')
        if url.port is not None and not 1 <= url.port <= 65535:
            raise ValueError('Invalid port')
        if '%' in url.hostname:
            raise ValueError('Encoded or scoped host')
        try:
            return ipaddress.ip_network(url.hostname)
        except ValueError:
            return _hostname(url.hostname)
    except ValueError as exc:
        raise ScanScopeError(f'Invalid scan target: {value}') from exc


class ScanScope:
    def __init__(self, entries):
        self.entries = [normalize_scope_entry(entry) for entry in entries]
        self.networks = []
        self.hosts = set()
        self.subdomains = set()
        for entry in self.entries:
            try:
                self.networks.append(ipaddress.ip_network(entry))
            except ValueError:
                if entry.startswith('*.'):
                    self.subdomains.add(entry[2:])
                else:
                    self.hosts.add(entry)

    def allows(self, target: str) -> bool:
        try:
            host = target_host(target)
        except ScanScopeError:
            return False
        if not isinstance(host, str):
            return any(host.version == net.version and host.subnet_of(net) for net in self.networks)
        return host in self.hosts or any(host.endswith('.' + parent) for parent in self.subdomains)

    def require(self, targets, *, verify_dns: bool = True):
        if not self.entries:
            raise ScanScopeError('No scan targets are approved for this organization. Contact a platform admin.')
        targets = list(targets)
        if not targets:
            raise ScanScopeError("No scan targets supplied")
        for target in targets:
            if not self.allows(target):
                raise ScanScopeError(f'Scan target is not approved for this organization: {target}')
            host = target_host(target)
            if verify_dns and isinstance(host, str):
                try:
                    addresses = {item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
                except socket.gaierror as exc:
                    raise ScanScopeError(f'Cannot verify DNS addresses for {host}') from exc
                if not addresses:
                    raise ScanScopeError(f'No DNS addresses found for {host}')
                for address in addresses:
                    if not self.allows(address):
                        raise ScanScopeError(f'{host} resolves to unapproved IP {address}. A platform admin must approve that IP or CIDR first.')


_current_scope = ContextVar('darkstar_scan_scope', default=None)


@contextmanager
def scan_scope_context(scope: ScanScope):
    token = _current_scope.set(scope)
    try:
        yield
    finally:
        _current_scope.reset(token)


def current_scan_scope() -> ScanScope | None:
    return _current_scope.get()
