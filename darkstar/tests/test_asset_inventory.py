"""Validate inventory input without probing services or resolving real DNS."""
import pytest

from darkstar.core.asset_inventory import _normalize_observation, _scanner_names


def test_observations_normalize_hosts_addresses_and_duplicate_services():
    service = {"port": 443, "protocol": "tcp", "service": "https", "url": "https://example.test/"}
    row = _normalize_observation({
        "target": "EXAMPLE.test.", "addresses": ["2001:db8::1", "2001:0db8::1"],
        "services": [service, service],
    })
    assert row == {"target": "example.test", "addresses": ["2001:db8::1"], "services": [service], "error": None}


@pytest.mark.parametrize("target", ["*.example.test", "192.0.2.0/24", "https://example.test", "example.test:443"])
def test_observations_require_a_host_not_an_approval_rule(target):
    with pytest.raises(ValueError):
        _normalize_observation({"target": target})


@pytest.mark.parametrize("service", [
    {"port": 0}, {"port": 65536}, {"port": True}, {"port": "443"},
    {"port": 53, "protocol": "udp"},
    {"port": 80, "url": "http://other.test"},
    {"port": 80, "url": "http://user:secret@example.test"},
    {"port": 443, "url": "http://example.test"},
    {"port": 80, "url": "file:///etc/passwd"},
])
def test_invalid_or_unrelated_services_are_rejected(service):
    with pytest.raises(ValueError):
        _normalize_observation({"target": "example.test", "services": [service]})


def test_ipv6_web_service_url_and_explicit_scanner_settings():
    row = _normalize_observation({"target": "2001:db8::1", "services": [
        {"port": 8443, "url": "https://[2001:db8::1]:8443/"},
    ]})
    assert row["services"][0]["url"] == "https://[2001:db8::1]:8443/"
    assert _scanner_names(None) is None
    assert _scanner_names([]) == []
    assert _scanner_names(["zap", "openvas", "zap"]) == ["openvas", "zap"]
    with pytest.raises(ValueError):
        _scanner_names(["discovery"])
