"""Bounded discovery of platform-admin-submitted hosts and web applications.

The API prepares an address snapshot before queuing a job. Workers use that
snapshot for discovery only; finding a service never grants scan approval.
"""
from __future__ import annotations

import argparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import shutil
import subprocess
import tempfile
import time
from urllib.parse import urlsplit, urlunsplit
import warnings
import xml.etree.ElementTree as ET

import dns.exception
import dns.resolver
import urllib3

from darkstar.core.scan_scope import normalize_scope_entry


MAX_HOSTS = 256
MAX_TARGET_BYTES = 60 * 1024
MAX_XML_BYTES = 8 * 1024 * 1024
MAX_SERVICES_PER_HOST = 1024
MAX_TOTAL_SERVICES = 4096
COMMON_PORTS = (
    "21,22,23,25,53,80,110,143,443,445,465,587,993,995,1433,1521,2049,2375,2376,"
    "3000,3306,3389,5000,5432,5900,6379,8000,8008,8080,8081,8443,8888,9000,9090,"
    "9200,9443,11211,27017"
)
# Nmap also excludes raw printer ports from service probing by default.
EXCLUDED_PROBE_PORTS = frozenset(range(9100, 9108))


class DiscoveryError(ValueError):
    pass


def _address(value: str) -> str:
    if not isinstance(value, str) or "%" in value:
        raise DiscoveryError("Invalid discovery address")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise DiscoveryError("Invalid discovery address") from exc


def _resolve_addresses(host: str) -> list[str]:
    try:
        return [_address(host)]
    except DiscoveryError:
        pass
    try:
        resolver = dns.resolver.Resolver()
    except dns.exception.DNSException as exc:
        raise DiscoveryError("DNS resolver is not configured on this appliance") from exc
    resolver.timeout = 1.5
    resolver.lifetime = 3
    addresses = set()
    for record_type in ("A", "AAAA"):
        try:
            addresses.update(_address(str(answer)) for answer in resolver.resolve(host, record_type))
        except dns.resolver.NoAnswer:
            continue
        except dns.exception.DNSException as exc:
            raise DiscoveryError(f"Cannot verify DNS addresses for {host}") from exc
    if not addresses:
        raise DiscoveryError(f"No DNS addresses found for {host}")
    if len(addresses) > MAX_HOSTS:
        raise DiscoveryError(f"DNS for {host} exceeds the {MAX_HOSTS}-address discovery limit")
    return sorted(addresses)


def _seed(value: str) -> dict:
    if not value or any(character.isspace() or ord(character) < 32 for character in value) or "\\" in value:
        raise DiscoveryError("Use an IP, CIDR, hostname, or HTTP/HTTPS URL")
    if "://" in value:
        if len(value) > 4096:
            raise DiscoveryError("Discovery URLs must be at most 4096 characters")
        try:
            parsed = urlsplit(value)
            if parsed.scheme.lower() not in {"http", "https"}:
                raise ValueError("Only HTTP/HTTPS URLs are supported")
            if parsed.username is not None or parsed.password is not None or not parsed.hostname:
                raise ValueError("URL credentials are not supported")
            host = normalize_scope_entry(parsed.hostname)
            if host.startswith("*.") or "/" in host:
                raise ValueError("Use an exact URL hostname")
            port = parsed.port
            if port is not None and not 1 <= port <= 65535:
                raise ValueError("Invalid URL port")
            authority = f"[{host}]" if ":" in host else host
            if port is not None:
                authority += f":{port}"
            url = urlunsplit((parsed.scheme.lower(), authority, parsed.path or "/", parsed.query, ""))
        except ValueError as exc:
            raise DiscoveryError("Invalid HTTP/HTTPS discovery URL; use an exact host and valid port without credentials") from exc
        if len(url) > 4096:
            raise DiscoveryError("Discovery URLs must be at most 4096 characters")
        return {"target": url, "host": host, "kind": "url", "url": url}
    try:
        host = normalize_scope_entry(value)
    except ValueError as exc:
        raise DiscoveryError("Use an IP, CIDR, hostname, or HTTP/HTTPS URL") from exc
    if host.startswith("*.") or "/" in host:
        raise DiscoveryError("Discovery requires an exact hostname or IP")
    try:
        _address(host)
        kind = "ip"
    except DiscoveryError:
        kind = "domain"
    return {"target": host, "host": host, "kind": kind, "url": None}


def _validate_target_size(seeds) -> None:
    # scans.targets is a MySQL TEXT column, whose limit is bytes, not characters.
    if len(",".join(seed["target"] for seed in seeds).encode("utf-8")) > MAX_TARGET_BYTES:
        raise DiscoveryError("Discovery target list exceeds the 60 KiB storage limit")


def prepare_discovery(targets: str, port_mode: str = "full") -> dict:
    """Normalize submitted scope and resolve its addresses without probing ports."""
    if port_mode not in {"common", "full"}:
        raise DiscoveryError("Choose common or full port discovery")
    if not isinstance(targets, str) or len(targets) > 65536:
        raise DiscoveryError("Discovery target list is too large")
    entries = [value.strip() for value in re.split(r"[,\r\n]+", targets) if value.strip()]
    if not entries or len(entries) > MAX_HOSTS:
        raise DiscoveryError(f"Enter between 1 and {MAX_HOSTS} discovery targets")
    seeds = {}
    for entry in entries:
        expanded = [entry]
        if "/" in entry and "://" not in entry:
            try:
                network = ipaddress.ip_network(entry, strict=True)
            except ValueError as exc:
                raise DiscoveryError("Invalid CIDR; network ranges must have no host bits") from exc
            # Check size before expanding, including very large IPv6 networks.
            if network.num_addresses > MAX_HOSTS:
                raise DiscoveryError(f"Discovery ranges are limited to {MAX_HOSTS} addresses")
            expanded = [str(address) for address in network.hosts()]
        for value in expanded:
            seed = _seed(value)
            seeds[seed["target"]] = seed
            if len(seeds) > MAX_HOSTS:
                raise DiscoveryError(f"Discovery is limited to {MAX_HOSTS} targets per job")
    _validate_target_size(seeds.values())
    resolved = {}
    names = set()
    for seed in seeds.values():
        try:
            resolved[seed["host"]] = [_address(seed["host"])]
        except DiscoveryError:
            names.add(seed["host"])
    # Bound the synchronous API preflight even for a batch of slow DNS names.
    if names:
        executor = ThreadPoolExecutor(max_workers=8)
        futures = {executor.submit(_resolve_addresses, host): host for host in names}
        try:
            for future in as_completed(futures, timeout=12):
                resolved[futures[future]] = future.result()
        except TimeoutError as exc:
            raise DiscoveryError("DNS verification timed out; submit a smaller discovery batch") from exc
        finally:
            executor.shutdown(wait=True, cancel_futures=True)
    addresses = set()
    for seed in seeds.values():
        host = seed["host"]
        seed["addresses"] = resolved[host]
        addresses.update(seed["addresses"])
        if len(addresses) > MAX_HOSTS:
            raise DiscoveryError(f"Discovery is limited to {MAX_HOSTS} resolved addresses per job")
    return {
        "seeds": list(seeds.values()),
        "authorized_targets": sorted(addresses | set(resolved)),
        "port_mode": port_mode,
    }


def validate_discovery_plan(plan: dict) -> None:
    """Reject malformed queued plans before any DNS or network activity."""
    if not isinstance(plan, dict) or plan.get("port_mode") not in {"common", "full"}:
        raise DiscoveryError("Invalid discovery plan")
    seeds = plan.get("seeds")
    authorized = plan.get("authorized_targets")
    if not isinstance(seeds, list) or not 1 <= len(seeds) <= MAX_HOSTS or not isinstance(authorized, list):
        raise DiscoveryError("Invalid discovery scope")
    expected = set()
    addresses = set()
    for seed in seeds:
        if not isinstance(seed, dict) or not isinstance(seed.get("target"), str):
            raise DiscoveryError("Invalid discovery target")
        normalized = _seed(seed["target"])
        if any(seed.get(key) != value for key, value in normalized.items()):
            raise DiscoveryError("Discovery target does not match its submitted scope")
        supplied = seed.get("addresses")
        if not isinstance(supplied, list) or not 1 <= len(supplied) <= MAX_HOSTS:
            raise DiscoveryError("Discovery target has no address snapshot")
        canonical = {_address(address) for address in supplied}
        if set(supplied) != canonical:
            raise DiscoveryError("Invalid discovery address snapshot")
        if normalized["kind"] == "ip" and canonical != {normalized["host"]}:
            raise DiscoveryError("Discovery IP does not match its address snapshot")
        try:
            literal = _address(normalized["host"])
        except DiscoveryError:
            literal = None
        if literal and canonical != {literal}:
            raise DiscoveryError("Discovery URL does not match its address snapshot")
        expected.update(canonical)
        expected.add(normalized["host"])
        addresses.update(canonical)
    _validate_target_size(seeds)
    if len(addresses) > MAX_HOSTS or any(not isinstance(item, str) for item in authorized) or set(authorized) != expected:
        raise DiscoveryError("Discovery authorization does not match its submitted targets")


def _nmap(address: str, ports: str, output: Path, *, identify: bool, log) -> list[dict]:
    command = ["nmap", "-sT", "-Pn", "-n", "--stats-every", "5s"]
    if ipaddress.ip_address(address).version == 6:
        command.append("-6")
    command.extend(["-p", ports])
    if identify:
        command.extend(["-sV", "--version-light", "--host-timeout", "5m"])
        timeout = 330
    else:
        command.extend(["--max-rate", "200", "--host-timeout", "15m"])
        timeout = 930
    command.extend(["-oX", str(output), address])
    phase = "Identifying services" if identify else "Discovering TCP ports"
    log(f"{phase} on {address}")
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    tail = deque(maxlen=8)
    deadline = time.monotonic() + timeout
    last_progress = time.monotonic()
    buffer = ""
    host_timed_out = False
    try:
        while True:
            if time.monotonic() > deadline:
                raise DiscoveryError(f"Nmap timed out on {address}; discovery is incomplete")
            ready, _, _ = select.select([process.stdout], [], [], 1)
            if ready:
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                buffer += chunk.decode("utf-8", errors="replace")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = re.sub(r"[\x00-\x1f\x7f]", "", line).strip()
                    tail.append(line[-500:])
                    host_timed_out |= "host timeout" in line.lower()
                    if "Timing:" in line or line.startswith("Stats:"):
                        log(line[:500])
                        last_progress = time.monotonic()
                buffer = buffer[-4096:]
            if time.monotonic() - last_progress >= 5:
                log(f"{phase} on {address} is still running")
                last_progress = time.monotonic()
        return_code = process.wait(timeout=5)
        if host_timed_out:
            raise DiscoveryError(f"Nmap timed out on {address}; discovery is incomplete")
        if return_code:
            raise DiscoveryError(f"Nmap failed on {address} (exit {return_code}): " + " ".join(tail)[-1000:])
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        process.stdout.close()
    return _nmap_ports(output, address)


def _nmap_ports(path: Path, address: str) -> list[dict]:
    try:
        if path.stat().st_size > MAX_XML_BYTES:
            raise DiscoveryError("Nmap report exceeds the discovery size limit")
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise DiscoveryError("Nmap did not produce a complete XML report") from exc
    finished = root.find("runstats/finished")
    if root.tag != "nmaprun" or finished is None or finished.get("exit") != "success":
        raise DiscoveryError("Nmap did not finish successfully")
    hosts = [host for host in root.findall("host") if any(item.get("addr") == address for item in host.findall("address"))]
    if len(hosts) != 1 or hosts[0].get("timedout") == "true":
        raise DiscoveryError("Nmap did not return a complete result for the requested address")
    ports = []
    for port in hosts[0].findall("ports/port"):
        state = port.find("state")
        if port.get("protocol") != "tcp" or state is None or state.get("state") != "open":
            continue
        try:
            number = int(port.get("portid", ""))
            if not 1 <= number <= 65535:
                raise ValueError()
        except ValueError as exc:
            raise DiscoveryError("Nmap returned an invalid port") from exc
        service = port.find("service")
        ports.append({
            "port": number, "protocol": "tcp",
            "service": service.get("name", "unknown") if service is not None else "unknown",
            "method": service.get("method", "table") if service is not None else "table",
            "tunnel": service.get("tunnel") if service is not None else None,
        })
    return sorted(ports, key=lambda item: item["port"])


def _http_response(url: str, address: str) -> bool:
    """Connect to a snapshot IP while retaining the URL's Host and TLS SNI."""
    parsed = urlsplit(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    timeout = urllib3.Timeout(connect=3, read=5)
    kwargs = {"port": port, "timeout": timeout, "retries": False}
    if parsed.scheme == "https":
        pool = urllib3.HTTPSConnectionPool(address, server_hostname=parsed.hostname,
                                         cert_reqs="CERT_NONE", assert_hostname=False, **kwargs)
    else:
        pool = urllib3.HTTPConnectionPool(address, **kwargs)
    response = None
    try:
        with warnings.catch_warnings():
            # An internal/self-signed certificate must not hide a web service.
            warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
            response = pool.urlopen("GET", urlunsplit(("", "", parsed.path or "/", parsed.query, "")),
                                    headers={"Host": parsed.netloc, "User-Agent": "Darkstar asset discovery"},
                                    redirect=False, preload_content=False, retries=False)
        return 100 <= response.status <= 599
    except (urllib3.exceptions.HTTPError, OSError, ValueError):
        return False
    finally:
        if response is not None:
            response.close()
        pool.close()


def _service_urls(seed: dict, address: str, service: dict) -> list[str]:
    if service["port"] in EXCLUDED_PROBE_PORTS:
        return []
    if seed["url"]:
        candidates = [seed["url"]]
    else:
        name = service["service"].lower()
        if service["method"] == "probed" and name not in {"unknown", "tcpwrapped", "ssl"} and "http" not in name:
            return []
        schemes = ["https"] if service["tunnel"] == "ssl" or name == "https" else ["http", "https"]
        authority = f"[{seed['host']}]" if ":" in seed["host"] else seed["host"]
        candidates = [f"{scheme}://{authority}:{service['port']}/" for scheme in schemes]
    return [url for url in candidates if _http_response(url, address)]


def discover(plan: dict, log=print) -> list[dict]:
    """Discover only the supplied snapshot; return partial inventory on errors."""
    validate_discovery_plan(plan)
    results = {}
    total_services = 0
    has_nmap = bool(shutil.which("nmap"))
    with tempfile.TemporaryDirectory(prefix="darkstar_discovery_") as directory:
        for index, seed in enumerate(plan["seeds"]):
            row = results.setdefault(seed["host"], {"target": seed["host"], "addresses": [], "services": [], "error": None})
            row["addresses"] = sorted(set(row["addresses"]) | set(seed["addresses"]))
            try:
                if not has_nmap:
                    raise DiscoveryError("Nmap is not installed on this appliance")
                if total_services >= MAX_TOTAL_SERVICES:
                    raise DiscoveryError("Discovery service limit reached; submit a smaller batch")
                current = _resolve_addresses(seed["host"])
                if set(current) - set(seed["addresses"]):
                    raise DiscoveryError(f"DNS addresses changed for {seed['host']}; submit a new discovery job to verify them")
                row["addresses"] = current
                for address in current:
                    if seed["url"]:
                        parsed = urlsplit(seed["url"])
                        ports = str(parsed.port or (443 if parsed.scheme == "https" else 80))
                    else:
                        ports = "1-65535" if plan["port_mode"] == "full" else COMMON_PORTS
                        opened = _nmap(address, ports, Path(directory) / f"ports-{index}.xml", identify=False, log=log)
                        if not opened:
                            log(f"No open TCP ports found on {address}")
                            continue
                        if len(opened) > MAX_SERVICES_PER_HOST:
                            raise DiscoveryError(f"More than {MAX_SERVICES_PER_HOST} open ports on {address}; service discovery is incomplete")
                        ports = ",".join(str(item["port"]) for item in opened)
                    services = _nmap(address, ports, Path(directory) / f"services-{index}.xml", identify=True, log=log)
                    web_count = 0
                    http_deadline = time.monotonic() + 120
                    last_http_progress = time.monotonic()
                    log(f"Checking HTTP/HTTPS responses from {len(services)} services on {address}")
                    for service_number, service in enumerate(services, start=1):
                        if time.monotonic() > http_deadline:
                            raise DiscoveryError(f"HTTP verification timed out on {address}; discovery is incomplete")
                        urls = _service_urls(seed, address, service)
                        for url in urls or [None]:
                            found = {key: service[key] for key in ("port", "protocol", "service")}
                            found["url"] = url
                            if url:
                                found["service"] = "https" if url.startswith("https://") else "http"
                                web_count += 1
                            if found not in row["services"]:
                                if len(row["services"]) >= MAX_SERVICES_PER_HOST or total_services >= MAX_TOTAL_SERVICES:
                                    raise DiscoveryError("Discovery service limit reached; submit a smaller batch")
                                row["services"].append(found)
                                total_services += 1
                        if time.monotonic() - last_http_progress >= 5:
                            log(f"HTTP verification on {address}: {service_number}/{len(services)} services checked")
                            last_http_progress = time.monotonic()
                    log(f"Discovered {len(services)} TCP services and {web_count} web endpoints on {address}")
                    if seed["url"] and not web_count:
                        raise DiscoveryError(f"No HTTP response from the submitted application on {seed['host']}:{ports}")
            except (DiscoveryError, OSError, subprocess.SubprocessError) as exc:
                message = str(exc)[:2000]
                row["error"] = "; ".join(filter(None, [row["error"], message]))[:2000]
                log(f"Discovery incomplete for {seed['host']}: {message}")
    return list(results.values())


def main() -> int:
    parser = argparse.ArgumentParser(description="Discover submitted assets without approving them")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        plan = json.loads(Path(args.input).read_text())
        rows = discover(plan, log=lambda message: print(message, flush=True))
        Path(args.output).write_text(json.dumps(rows))
    except (ValueError, OSError) as exc:
        print(f"Discovery failed: {exc}", flush=True)
        return 1
    return 1 if any(row["error"] for row in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())
