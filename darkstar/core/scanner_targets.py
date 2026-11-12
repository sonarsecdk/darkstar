"""Apply asset scanner choices and turn approved hosts into web application URLs."""
import ipaddress
import socket
from urllib.parse import urlsplit

from .scan_scope import ScanScope, ScanScopeError, target_host


NUCLEI_SCANNERS = {'nuclei', 'nucleinetwork', 'wordpressnuclei'}


def scanner_family(scanner):
    return 'nuclei' if scanner in NUCLEI_SCANNERS else scanner


def _overlaps(entry, target):
    try:
        first, second = ipaddress.ip_network(entry), ipaddress.ip_network(target)
        return first.version == second.version and first.overlaps(second)
    except ValueError:
        return ScanScope([entry]).allows(target)


def require_enabled_scanner(targets, scanner, rules):
    """Restrictions apply to the host and its addresses, regardless of URL port."""
    if not rules:
        return
    family = scanner_family(scanner)
    for target in targets:
        host = target_host(target)
        candidates = [host if isinstance(host, str) else str(host)]
        if isinstance(host, str):
            try:
                candidates.extend({item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
            except socket.gaierror as exc:
                raise ScanScopeError(f'Cannot verify DNS addresses for {host}') from exc
        matching = [rule for rule in rules if any(_overlaps(rule['target'], candidate) for candidate in candidates)]
        if matching and scanner is None:
            raise ScanScopeError('This asset has scanner restrictions. Choose scanners and profiles instead of a scan mode.')
        if any(family not in rule['enabled_scanners'] for rule in matching):
            raise ScanScopeError(f'{scanner} is not enabled for this asset: {target}')


def zap_targets(targets, inventory):
    """Preserve explicit URLs; use discovered endpoints for hosts and networks."""
    result = []
    for target in targets:
        if '://' in target:
            if urlsplit(target).scheme.lower() not in {'http', 'https'}:
                raise ScanScopeError('ZAP requires an HTTP or HTTPS target')
            result.append(target)
            continue
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            parsed = urlsplit('//' + target)
            if parsed.port is not None:
                # An explicit port is a user choice, even without a scheme.
                result.append('http://' + target)
                continue
        host = target_host(target)
        name = host if isinstance(host, str) else str(host.network_address)
        is_network = not isinstance(host, str) and host.num_addresses > 1
        matches = [row for row in inventory if row.get('approved') and (
            _overlaps(str(host), row['target']) if is_network else row['target'] == name
        )]
        urls = [service['url'] for row in matches for service in row.get('services', [])
                if service.get('url')]
        if urls:
            result.extend(urls)
        elif is_network or any(row.get('discovered_at') or row.get('last_attempt_at') for row in matches):
            raise ScanScopeError(f'No discovered web applications for {target}. Refresh discovery or enter a full web URL.')
        else:
            # Existing installations can still supply a host on the default HTTP
            # port before they have any discovery inventory.
            result.append(f'http://[{name}]/' if not isinstance(host, str) and host.version == 6 else target)
    return list(dict.fromkeys(result))
