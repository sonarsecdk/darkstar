"""Discovery scope, service classification and subprocess contracts."""
import json
import subprocess
import sys
from unittest.mock import Mock

import dns.resolver
import pytest

from darkstar import asset_discovery as discovery


pytestmark = pytest.mark.unit


def service(port, name="unknown", method="table", tunnel=None):
    return {"port": port, "protocol": "tcp", "service": name, "method": method, "tunnel": tunnel}


def xml_report(address="192.0.2.1", *, ports=None, exit_status="success", timedout=False):
    ports = ports or '''<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" method="probed"/></port>
        <port protocol="tcp" portid="3000"><state state="open"/><service name="http" method="probed"/></port>
        <port protocol="tcp" portid="443"><state state="closed"/></port>'''
    timeout = ' timedout="true"' if timedout else ""
    return f'''<nmaprun><host{timeout}><address addr="{address}"/><ports>{ports}</ports></host>
        <runstats><finished exit="{exit_status}"/></runstats></nmaprun>'''


def test_prepare_retains_application_urls_and_deduplicates_hosts(monkeypatch):
    resolve = Mock(return_value=["192.0.2.10", "2001:db8::10"])
    monkeypatch.setattr(discovery, "_resolve_addresses", resolve)
    plan = discovery.prepare_discovery("192.0.2.1\n192.0.2.1\nEXAMPLE.test.\nhttps://EXAMPLE.test:8443/login?next=/home#fragment")
    assert plan["port_mode"] == "full"
    assert len(plan["seeds"]) == 3
    assert plan["seeds"][0] == {"target": "192.0.2.1", "host": "192.0.2.1", "kind": "ip", "url": None, "addresses": ["192.0.2.1"]}
    assert plan["seeds"][2]["url"] == "https://example.test:8443/login?next=/home"
    assert plan["seeds"][2]["kind"] == "url"
    resolve.assert_called_once_with("example.test")
    assert plan["authorized_targets"] == ["192.0.2.1", "192.0.2.10", "2001:db8::10", "example.test"]
    discovery.validate_discovery_plan(plan)


def test_prepare_ipv6_url_and_small_cidr():
    plan = discovery.prepare_discovery("192.0.2.0/30\nhttps://[2001:db8::1]:8443/a", "common")
    assert [seed["host"] for seed in plan["seeds"]] == ["192.0.2.1", "192.0.2.2", "2001:db8::1"]
    assert plan["seeds"][-1]["url"] == "https://[2001:db8::1]:8443/a"
    discovery.validate_discovery_plan(plan)


@pytest.mark.parametrize("target", [
    "", "*.example.test", "file:///etc/passwd", "/tmp/targets.txt", "-oN", "example.test:3000",
    "http://user:password@example.test", "http://example.test:65536", "http://example.test:0",
    "http://example.test/a\tb", "http://example.test\\@evil.test", "fe80::1%eth0", "192.0.2.1;id",
    "192.0.2.1/24", "http://%65xample.test/", "example.test$(id)",
])
def test_prepare_rejects_invalid_or_ambiguous_targets_without_dns(monkeypatch, target):
    resolve = Mock()
    monkeypatch.setattr(discovery, "_resolve_addresses", resolve)
    with pytest.raises(discovery.DiscoveryError):
        discovery.prepare_discovery(target)
    resolve.assert_not_called()


@pytest.mark.parametrize("target", ["0.0.0.0/0", "::/0", "192.0.0.0/16"])
def test_large_network_is_rejected_before_expansion_or_dns(monkeypatch, target):
    resolve = Mock()
    monkeypatch.setattr(discovery, "_resolve_addresses", resolve)
    with pytest.raises(discovery.DiscoveryError, match="limited"):
        discovery.prepare_discovery(target)
    resolve.assert_not_called()


def test_total_expansion_and_input_limits():
    with pytest.raises(discovery.DiscoveryError, match="limited"):
        discovery.prepare_discovery("192.0.2.0/24,198.51.100.0/24")
    with pytest.raises(discovery.DiscoveryError, match="between"):
        discovery.prepare_discovery(",".join(["192.0.2.1"] * 257))
    with pytest.raises(discovery.DiscoveryError, match="too large"):
        discovery.prepare_discovery("x" * 65537)
    with pytest.raises(discovery.DiscoveryError, match="common or full"):
        discovery.prepare_discovery("192.0.2.1", "-A")
    with pytest.raises(discovery.DiscoveryError, match="4096 characters"):
        discovery.prepare_discovery("http://192.0.2.1/" + "a" * 4096)


def test_dns_queries_are_bounded_and_both_address_families_checked(monkeypatch):
    resolver = Mock()
    resolver.resolve.side_effect = [["192.0.2.1"], ["2001:db8::1"]]
    monkeypatch.setattr(discovery.dns.resolver, "Resolver", lambda: resolver)
    assert discovery._resolve_addresses("example.test") == ["192.0.2.1", "2001:db8::1"]
    assert resolver.lifetime == 3
    assert resolver.timeout == 1.5
    assert [call.args for call in resolver.resolve.call_args_list] == [("example.test", "A"), ("example.test", "AAAA")]


def test_unicode_targets_fit_database_byte_limit_before_dns_and_on_worker(monkeypatch):
    urls = [f"https://example.test/{index}/" + "\U0001f600" * 3000 for index in range(8)]
    targets = ",".join(urls)
    assert len(targets) < 65536 < len(targets.encode("utf-8"))
    resolve = Mock()
    monkeypatch.setattr(discovery, "_resolve_addresses", resolve)
    with pytest.raises(discovery.DiscoveryError, match="60 KiB"):
        discovery.prepare_discovery(targets)
    resolve.assert_not_called()

    plan = {
        "seeds": [dict(discovery._seed(url), addresses=["192.0.2.1"]) for url in urls],
        "authorized_targets": ["192.0.2.1", "example.test"],
        "port_mode": "full",
    }
    with pytest.raises(discovery.DiscoveryError, match="60 KiB"):
        discovery.validate_discovery_plan(plan)


def test_url_limit_also_applies_after_hostname_canonicalization():
    url = "https://\u00e9.example/" + "a" * (4096 - len("https://\u00e9.example/"))
    with pytest.raises(discovery.DiscoveryError, match="4096 characters"):
        discovery.prepare_discovery(url)


def test_dns_family_without_answers_is_allowed_but_failure_is_not(monkeypatch):
    resolver = Mock()
    resolver.resolve.side_effect = [["192.0.2.1"], dns.resolver.NoAnswer()]
    monkeypatch.setattr(discovery.dns.resolver, "Resolver", lambda: resolver)
    assert discovery._resolve_addresses("example.test") == ["192.0.2.1"]
    resolver.resolve.side_effect = [["192.0.2.1"], dns.resolver.LifetimeTimeout()]
    with pytest.raises(discovery.DiscoveryError, match="Cannot verify DNS"):
        discovery._resolve_addresses("example.test")


def test_dns_preparation_has_batch_deadline(monkeypatch):
    monkeypatch.setattr(discovery, "_resolve_addresses", lambda host: ["192.0.2.1"])
    def timed_out(futures, timeout):
        assert timeout == 12
        raise TimeoutError()
    monkeypatch.setattr(discovery, "as_completed", timed_out)
    with pytest.raises(discovery.DiscoveryError, match="smaller discovery batch"):
        discovery.prepare_discovery("one.example.test,two.example.test")


def test_missing_dns_configuration_is_a_clear_discovery_error(monkeypatch):
    monkeypatch.setattr(discovery.dns.resolver, "Resolver", Mock(side_effect=dns.resolver.NoResolverConfiguration()))
    with pytest.raises(discovery.DiscoveryError, match="not configured"):
        discovery._resolve_addresses("example.test")


def test_tampered_snapshot_is_rejected_before_network(monkeypatch):
    plan = discovery.prepare_discovery("http://192.0.2.1:3000/")
    plan["seeds"][0]["addresses"] = ["192.0.2.2"]
    plan["authorized_targets"].append("192.0.2.2")
    nmap = Mock()
    monkeypatch.setattr(discovery, "_nmap", nmap)
    with pytest.raises(discovery.DiscoveryError, match="address snapshot"):
        discovery.discover(plan)
    nmap.assert_not_called()


def test_unrelated_authorization_entry_is_rejected():
    plan = discovery.prepare_discovery("192.0.2.1")
    plan["authorized_targets"].append("0.0.0.0/0")
    with pytest.raises(discovery.DiscoveryError, match="authorization"):
        discovery.validate_discovery_plan(plan)


def test_changed_dns_never_starts_port_scan(monkeypatch):
    monkeypatch.setattr(discovery, "_resolve_addresses", lambda host: ["192.0.2.1"])
    plan = discovery.prepare_discovery("example.test")
    monkeypatch.setattr(discovery, "_resolve_addresses", lambda host: ["192.0.2.2"])
    monkeypatch.setattr(discovery.shutil, "which", lambda name: "/usr/bin/nmap")
    nmap = Mock()
    monkeypatch.setattr(discovery, "_nmap", nmap)
    rows = discovery.discover(plan, log=lambda message: None)
    assert "DNS addresses changed" in rows[0]["error"]
    assert rows[0]["addresses"] == ["192.0.2.1"]
    assert rows[0]["services"] == []
    nmap.assert_not_called()


def test_full_discovery_hands_only_open_ports_to_service_detection(monkeypatch):
    plan = discovery.prepare_discovery("192.0.2.1")
    nmap = Mock(side_effect=[[service(22), service(3000)], [service(22, "ssh", "probed"), service(3000, "ppp", "table")]])
    monkeypatch.setattr(discovery, "_nmap", nmap)
    monkeypatch.setattr(discovery.shutil, "which", lambda name: "/usr/bin/nmap")
    http = Mock(side_effect=lambda url, address: url == "http://192.0.2.1:3000/")
    monkeypatch.setattr(discovery, "_http_response", http)
    rows = discovery.discover(plan, log=lambda message: None)
    assert nmap.call_args_list[0].args[1] == "1-65535"
    assert nmap.call_args_list[1].args[1] == "22,3000"
    assert nmap.call_args_list[1].kwargs["identify"] is True
    assert rows == [{"target": "192.0.2.1", "addresses": ["192.0.2.1"], "services": [
        {"port": 22, "protocol": "tcp", "service": "ssh", "url": None},
        {"port": 3000, "protocol": "tcp", "service": "http", "url": "http://192.0.2.1:3000/"},
    ], "error": None}]
    assert all(":22/" not in call.args[0] for call in http.call_args_list)


def test_explicit_url_checks_only_its_port_and_keeps_path(monkeypatch):
    monkeypatch.setattr(discovery, "_resolve_addresses", lambda host: ["192.0.2.1"])
    plan = discovery.prepare_discovery("https://app.example.test:8443/login")
    nmap = Mock(return_value=[service(8443, "http", "probed", "ssl")])
    monkeypatch.setattr(discovery, "_nmap", nmap)
    monkeypatch.setattr(discovery.shutil, "which", lambda name: "/usr/bin/nmap")
    http = Mock(return_value=True)
    monkeypatch.setattr(discovery, "_http_response", http)
    rows = discovery.discover(plan, log=lambda message: None)
    assert nmap.call_count == 1
    assert nmap.call_args.args[:2] == ("192.0.2.1", "8443")
    assert nmap.call_args.kwargs["identify"] is True
    http.assert_called_once_with("https://app.example.test:8443/login", "192.0.2.1")
    assert rows[0]["services"][0]["url"] == "https://app.example.test:8443/login"


def test_unreachable_explicit_url_has_clear_error(monkeypatch):
    monkeypatch.setattr(discovery.shutil, "which", lambda name: "/usr/bin/nmap")
    monkeypatch.setattr(discovery, "_nmap", lambda *args, **kwargs: [])
    rows = discovery.discover(discovery.prepare_discovery("http://192.0.2.1:3000/"), log=lambda message: None)
    assert rows[0]["error"] == "No HTTP response from the submitted application on 192.0.2.1:3000"


def test_host_failure_keeps_other_results(monkeypatch):
    plan = discovery.prepare_discovery("192.0.2.1,192.0.2.2")
    monkeypatch.setattr(discovery.shutil, "which", lambda name: "/usr/bin/nmap")
    monkeypatch.setattr(discovery, "_nmap", Mock(side_effect=[discovery.DiscoveryError("Nmap timed out"), []]))
    rows = discovery.discover(plan, log=lambda message: None)
    assert rows[0]["error"] == "Nmap timed out"
    assert rows[1]["error"] is None


def test_missing_nmap_is_reported_without_network(monkeypatch):
    monkeypatch.setattr(discovery.shutil, "which", lambda name: None)
    resolve = Mock()
    monkeypatch.setattr(discovery, "_resolve_addresses", resolve)
    rows = discovery.discover(discovery.prepare_discovery("192.0.2.1"), log=lambda message: None)
    assert "not installed" in rows[0]["error"]
    resolve.assert_not_called()


def test_tls_service_and_printer_exclusion(monkeypatch):
    seed = discovery.prepare_discovery("192.0.2.1")["seeds"][0]
    http = Mock(return_value=True)
    monkeypatch.setattr(discovery, "_http_response", http)
    assert discovery._service_urls(seed, "192.0.2.1", service(8443, "http", "probed", "ssl")) == ["https://192.0.2.1:8443/"]
    assert discovery._service_urls(seed, "192.0.2.1", service(9100)) == []
    http.assert_called_once_with("https://192.0.2.1:8443/", "192.0.2.1")


@pytest.mark.parametrize("status", [200, 301, 401, 403, 404, 500])
def test_http_probe_is_pinned_preserves_host_and_does_not_follow_redirects(monkeypatch, status):
    response = Mock(status=status)
    pool = Mock()
    pool.urlopen.return_value = response
    factory = Mock(return_value=pool)
    monkeypatch.setattr(discovery.urllib3, "HTTPConnectionPool", factory)
    assert discovery._http_response("http://app.example.test:3000/login?next=home", "192.0.2.1") is True
    assert factory.call_args.args == ("192.0.2.1",)
    assert factory.call_args.kwargs["port"] == 3000
    assert pool.urlopen.call_args.args == ("GET", "/login?next=home")
    assert pool.urlopen.call_args.kwargs["headers"]["Host"] == "app.example.test:3000"
    assert pool.urlopen.call_args.kwargs["redirect"] is False
    assert pool.urlopen.call_args.kwargs["preload_content"] is False
    response.close.assert_called_once()
    pool.close.assert_called_once()


def test_https_probe_sets_original_hostname_for_sni(monkeypatch):
    pool = Mock()
    pool.urlopen.return_value.status = 403
    factory = Mock(return_value=pool)
    monkeypatch.setattr(discovery.urllib3, "HTTPSConnectionPool", factory)
    assert discovery._http_response("https://app.example.test/", "2001:db8::1")
    assert factory.call_args.args == ("2001:db8::1",)
    assert factory.call_args.kwargs["server_hostname"] == "app.example.test"
    assert factory.call_args.kwargs["port"] == 443


def test_xml_parser_uses_actual_open_ports_and_service_method(tmp_path):
    report = tmp_path / "nmap.xml"
    report.write_text(xml_report())
    ports = discovery._nmap_ports(report, "192.0.2.1")
    assert ports == [service(22, "ssh", "probed"), service(3000, "http", "probed")]


@pytest.mark.parametrize("report", [
    "<nmaprun>", "<other/>", xml_report("192.0.2.2"), xml_report(exit_status="error"),
    xml_report(timedout=True), xml_report(ports='<port protocol="tcp" portid="65536"><state state="open"/></port>'),
])
def test_incomplete_foreign_or_invalid_xml_is_not_success(tmp_path, report):
    path = tmp_path / "nmap.xml"
    path.write_text(report)
    with pytest.raises(discovery.DiscoveryError):
        discovery._nmap_ports(path, "192.0.2.1")


def test_xml_size_limit(tmp_path, monkeypatch):
    report = tmp_path / "nmap.xml"
    report.write_text(xml_report())
    monkeypatch.setattr(discovery, "MAX_XML_BYTES", 10)
    with pytest.raises(discovery.DiscoveryError, match="size limit"):
        discovery._nmap_ports(report, "192.0.2.1")


def test_nmap_process_uses_ipv6_arguments_and_streams_progress(tmp_path, monkeypatch):
    output = tmp_path / "nmap.xml"
    actual_popen = subprocess.Popen
    commands = []
    def fake_nmap(command, **kwargs):
        commands.append(command)
        code = "from pathlib import Path; print('Stats: discovering'); Path(" + repr(str(output)) + ").write_text(" + repr(xml_report("2001:db8::1")) + ")"
        return actual_popen([sys.executable, "-c", code], **kwargs)
    monkeypatch.setattr(discovery.subprocess, "Popen", fake_nmap)
    logs = []
    ports = discovery._nmap("2001:db8::1", "1-65535", output, identify=False, log=logs.append)
    assert [item["port"] for item in ports] == [22, 3000]
    assert "-6" in commands[0]
    assert commands[0][-1] == "2001:db8::1"
    assert commands[0][commands[0].index("-p") + 1] == "1-65535"
    assert any("Stats:" in line for line in logs)


def test_nmap_host_timeout_is_not_reported_as_empty_success(tmp_path, monkeypatch):
    actual_popen = subprocess.Popen
    def fake_nmap(command, **kwargs):
        return actual_popen([sys.executable, "-c", "print('Skipping host 192.0.2.1 due to host timeout')"], **kwargs)
    monkeypatch.setattr(discovery.subprocess, "Popen", fake_nmap)
    with pytest.raises(discovery.DiscoveryError, match="timed out"):
        discovery._nmap("192.0.2.1", "1-65535", tmp_path / "result.xml", identify=False, log=lambda message: None)


def test_process_deadline_terminates_nmap(tmp_path, monkeypatch):
    actual_popen = subprocess.Popen
    children = []
    def fake_nmap(command, **kwargs):
        process = actual_popen([sys.executable, "-c", "import time; time.sleep(60)"], **kwargs)
        children.append(process)
        return process
    clock = iter([0, 0])
    monkeypatch.setattr(discovery.subprocess, "Popen", fake_nmap)
    monkeypatch.setattr(discovery.time, "monotonic", lambda: next(clock, 1000))
    with pytest.raises(discovery.DiscoveryError, match="timed out"):
        discovery._nmap("192.0.2.1", "80", tmp_path / "result.xml", identify=False, log=lambda message: None)
    assert len(children) == 1 and children[0].poll() is not None


def test_excessive_open_ports_are_incomplete_without_service_probe(monkeypatch):
    monkeypatch.setattr(discovery, "MAX_SERVICES_PER_HOST", 1)
    monkeypatch.setattr(discovery.shutil, "which", lambda name: "/usr/bin/nmap")
    nmap = Mock(return_value=[service(80), service(443)])
    monkeypatch.setattr(discovery, "_nmap", nmap)
    rows = discovery.discover(discovery.prepare_discovery("192.0.2.1"), log=lambda message: None)
    assert "More than 1 open ports" in rows[0]["error"]
    assert nmap.call_count == 1


def test_total_service_limit_preserves_first_result_and_bounds_later_work(monkeypatch):
    monkeypatch.setattr(discovery, "MAX_TOTAL_SERVICES", 1)
    monkeypatch.setattr(discovery.shutil, "which", lambda name: "/usr/bin/nmap")
    nmap = Mock(return_value=[service(22, "ssh", "probed")])
    monkeypatch.setattr(discovery, "_nmap", nmap)
    rows = discovery.discover(discovery.prepare_discovery("192.0.2.1,192.0.2.2"), log=lambda message: None)
    assert rows[0]["services"] == [{"port": 22, "protocol": "tcp", "service": "ssh", "url": None}]
    assert rows[0]["error"] is None
    assert "service limit reached" in rows[1]["error"]
    assert nmap.call_count == 2  # First host's port discovery and service identification only.


def test_http_verification_has_deadline(monkeypatch):
    monkeypatch.setattr(discovery.shutil, "which", lambda name: "/usr/bin/nmap")
    monkeypatch.setattr(discovery, "_nmap", Mock(return_value=[service(3000)]))
    probe = Mock()
    monkeypatch.setattr(discovery, "_http_response", probe)
    clock = iter([0])
    monkeypatch.setattr(discovery.time, "monotonic", lambda: next(clock, 121))
    rows = discovery.discover(discovery.prepare_discovery("http://192.0.2.1:3000/"), log=lambda message: None)
    assert "HTTP verification timed out" in rows[0]["error"]
    probe.assert_not_called()


def test_dns_addresses_removed_since_submission_are_not_current_inventory(monkeypatch):
    monkeypatch.setattr(discovery, "_resolve_addresses", lambda host: ["192.0.2.1", "192.0.2.2"])
    plan = discovery.prepare_discovery("example.test")
    monkeypatch.setattr(discovery, "_resolve_addresses", lambda host: ["192.0.2.1"])
    monkeypatch.setattr(discovery.shutil, "which", lambda name: "/usr/bin/nmap")
    monkeypatch.setattr(discovery, "_nmap", lambda *args, **kwargs: [])
    rows = discovery.discover(plan, log=lambda message: None)
    assert rows[0]["addresses"] == ["192.0.2.1"]


def test_cli_keeps_partial_results_and_returns_failure(tmp_path, monkeypatch):
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(json.dumps(discovery.prepare_discovery("192.0.2.1")))
    expected = [{"target": "192.0.2.1", "addresses": ["192.0.2.1"], "services": [], "error": "Timed out"}]
    monkeypatch.setattr(discovery, "discover", lambda plan, log: expected)
    monkeypatch.setattr(sys, "argv", ["discovery", "--input", str(input_path), "--output", str(output_path)])
    assert discovery.main() == 1
    assert json.loads(output_path.read_text()) == expected
