"""ZAP failures must retain their cause and never become an empty clean report."""
import io
import json
import logging
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urlsplit
from unittest.mock import Mock

import pytest

from scanners.external_vuln import ZAPScanner


def response(body):
    return io.BytesIO(json.dumps(body).encode())


@pytest.mark.parametrize("http_error", [False, True])
def test_api_error_keeps_zap_reason_without_exposing_key(monkeypatch, caplog, http_error):
    scanner = ZAPScanner("https://example.test", "org")
    scanner.API_KEY = "unit-test-zap-secret"
    body = {"code": "url_not_found", "message": "URL Not Found", "detail": scanner.API_KEY}

    def request(url, **kwargs):
        if http_error:
            raise urllib.error.HTTPError(url, 400, "Bad Request", {}, response(body))
        return response(body)

    monkeypatch.setattr(urllib.request, "urlopen", request)
    with pytest.raises(RuntimeError, match="url_not_found: URL Not Found") as error:
        scanner._zap_api("JSON/ascan/action/scan/?url=https%3A%2F%2Fexample.test")
    assert scanner.API_KEY not in str(error.value) + caplog.text
    assert "[redacted]" in str(error.value)


def test_non_json_http_error_reports_status(monkeypatch):
    def request(url, **kwargs):
        raise urllib.error.HTTPError(url, 503, "Unavailable", {}, io.BytesIO(b"<html>Unavailable</html>"))

    monkeypatch.setattr(urllib.request, "urlopen", request)
    with pytest.raises(RuntimeError, match="HTTP 503"):
        ZAPScanner("example.test", "org")._zap_api("JSON/core/view/version/")


def test_transport_failure_is_raised_and_redacted(monkeypatch, caplog):
    scanner = ZAPScanner("example.test", "org")

    def request(url, **kwargs):
        raise urllib.error.URLError(f"Connection refused for {url}")

    monkeypatch.setattr(urllib.request, "urlopen", request)
    with pytest.raises(RuntimeError, match="Connection refused") as error:
        scanner._zap_api("JSON/core/view/version/")
    assert scanner.API_KEY not in str(error.value) + caplog.text


@pytest.mark.parametrize("body", [b"not-json", b"null", b'"unexpected string"'])
def test_invalid_api_response_fails(monkeypatch, body):
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: io.BytesIO(body))
    with pytest.raises(RuntimeError):
        ZAPScanner("example.test", "org")._zap_api("JSON/core/view/version/")


@pytest.mark.parametrize("messages", [[], None, [{}], [{"responseHeader": ""}], [{"responseHeader": "HTTP/1.1 0"}]])
def test_no_fetched_response_stops_before_spider_or_active_scan(messages):
    scanner = ZAPScanner("https://example.test", "org")
    scanner.policy_name = "Selected policy"
    scanner._zap_api = Mock(return_value={"accessUrl": messages})
    with pytest.raises(RuntimeError, match="no HTTP response"):
        scanner._scan_target(scanner.targets[0])
    scanner._zap_api.assert_called_once()
    path = scanner._zap_api.call_args.args[0]
    assert "/accessUrl/" in path
    assert parse_qs(urlsplit(path).query)["followRedirects"] == ["false"]


@pytest.mark.parametrize("status", ["200 OK", "401 Unauthorized", "404 Not Found", "500 Internal Server Error"])
def test_http_error_pages_are_real_responses_and_can_be_scanned(status):
    scanner = ZAPScanner("https://example.test", "org")
    scanner._zap_api = Mock(side_effect=[
        {"accessUrl": [{"responseHeader": f"HTTP/1.1 {status}\r\n"}]},
        {"scan": "1"}, {"status": "100"}, {"recordsToScan": "0"}, {"alerts": []},
    ])
    assert scanner._scan_target(scanner.targets[0]) == []
    assert any("/spider/action/scan/" in call.args[0] for call in scanner._zap_api.call_args_list)


def test_selected_policy_failure_propagates_actual_zap_reason(monkeypatch):
    scanner = ZAPScanner("https://example.test", "org")
    scanner.policy_name = "Selected policy"

    def request(url, **kwargs):
        if "/accessUrl/" in url:
            return response({"accessUrl": [{"responseHeader": "HTTP/1.1 200 OK\r\n"}]})
        if "/spider/action/" in url:
            return response({"scan": "1"})
        if "/status/" in url:
            return response({"status": "100"})
        raise urllib.error.HTTPError(url, 400, "Bad Request", {}, response({
            "code": "url_not_found", "message": "URL Not Found", "detail": "https://example.test",
        }))

    monkeypatch.setattr(urllib.request, "urlopen", request)
    with pytest.raises(RuntimeError, match="url_not_found: URL Not Found"):
        scanner._scan_target(scanner.targets[0])


def test_policy_cleanup_failure_does_not_skip_daemon_shutdown(monkeypatch, caplog):
    scanner = ZAPScanner("example.test", "org")
    scanner.policy_name = "Imported policy"
    scanner._zap_api = Mock(side_effect=RuntimeError("ZAP unavailable"))
    scanner._zap_process = Mock()
    monkeypatch.setattr(urllib.request, "urlopen", Mock(side_effect=OSError(scanner.API_KEY)))
    with caplog.at_level(logging.DEBUG):
        scanner._stop_daemon()
    scanner._zap_process.terminate.assert_called_once()
    scanner._zap_process.wait.assert_called_once_with(timeout=10)
    assert scanner.policy_name is None
    assert scanner.API_KEY not in caplog.text
