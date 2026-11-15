"""ZAP API severities must survive import, including alerts on later pages."""
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest

from scanners import external_vuln


@pytest.mark.parametrize("risk, expected", [
    ("High", "high"), ("Medium", "medium"), ("Low", "low"), ("Informational", "info"),
    (" HIGH ", "high"), (0, "info"), (1, "low"), (2, "medium"), (3, "high"),
])
def test_api_risk_labels_and_exported_codes(risk, expected):
    assert external_vuln._normalize_zap_risk(risk) == expected


@pytest.mark.parametrize("risk", [None, "", "Critical", "unknown", 4, -1, True])
def test_missing_or_unrecognized_risk_never_silently_becomes_low(risk):
    with pytest.raises(ValueError, match="unsupported alert risk"):
        external_vuln._normalize_zap_risk(risk)


def scanner_with_alerts(alerts):
    scanner = external_vuln.ZAPScanner("http://192.0.2.1:3000/", "org")

    def api(path):
        if '/accessUrl/' in path:
            return {"accessUrl": [{"responseHeader": "HTTP/1.1 200 OK\r\n"}]}
        if '/spider/action/' in path:
            return {"scan": "1"}
        if '/status/' in path:
            return {"status": "100"}
        if '/recordsToScan/' in path:
            return {"recordsToScan": "0"}
        if '/alerts/' in path:
            start = int(parse_qs(urlsplit(path).query)['start'][0])
            return {"alerts": alerts[start:start + 500]}
        raise AssertionError(path)

    scanner._zap_api = Mock(side_effect=api)
    return scanner


def test_native_api_alerts_keep_severity_when_saved(monkeypatch):
    # The live alerts API returns risk labels, not jsonreport's riskcode field.
    alerts = [{"alert": title, "risk": risk, "confidence": "Medium", "pluginId": str(index),
               "url": "http://192.0.2.1:3000/search?q=test", "description": "Scanner evidence",
               "solution": "Fix the issue", "cweid": "89"}
              for index, (title, risk) in enumerate([
                  ("SQL Injection", "High"), ("CSP Header Not Set", "Medium"),
                  ("Timestamp Disclosure", "Low"), ("Modern Web Application", "Informational"),
              ])]
    scanner = scanner_with_alerts(alerts)
    scanner._start_daemon = Mock(return_value=True)
    scanner._stop_daemon = Mock()
    save = Mock(return_value=True)
    monkeypatch.setattr(external_vuln, "insert_vulnerability_to_database", save)
    scanner.run()
    saved = [call.kwargs['vuln'] for call in save.call_args_list]
    assert [(v.title, v.severity) for v in saved] == [
        ("SQL Injection", "high"), ("CSP Header Not Set", "medium"), ("Timestamp Disclosure", "low"),
    ]
    assert all(call.kwargs['org_name'] == 'org' for call in save.call_args_list)
    scanner._stop_daemon.assert_called_once()


def test_exported_riskcode_is_supported_but_api_risk_takes_precedence():
    scanner = scanner_with_alerts([{"riskcode": "3"}, {"risk": "High", "riskcode": "1"}, {"riskcode": 0}])
    assert [item['severity'] for item in scanner._scan_target(scanner.targets[0])] == ['high', 'high']


def test_high_alert_after_first_page_is_imported():
    scanner = scanner_with_alerts([{"risk": "Low", "alert": f"Low {i}"} for i in range(500)] + [
        {"risk": "High", "alert": "SQL Injection"},
    ])
    findings = scanner._scan_target(scanner.targets[0])
    assert len(findings) == 501
    assert findings[-1]['severity'] == 'high'
    pages = [parse_qs(urlsplit(call.args[0]).query) for call in scanner._zap_api.call_args_list if '/alerts/' in call.args[0]]
    assert [page['start'] for page in pages] == [['0'], ['500']]
    assert all(page['baseurl'] == ['http://192.0.2.1:3000/'] for page in pages)


@pytest.mark.parametrize("invalid", [{}, {"alerts": None}, {"alerts": "not a list"}, {"alerts": [None]}])
def test_invalid_report_is_not_an_empty_success(invalid):
    scanner = scanner_with_alerts([])
    scanner._zap_api = Mock(return_value=invalid)
    with pytest.raises(RuntimeError, match="retrieve its report"):
        scanner._get_alerts(scanner.targets[0])


def test_second_page_failure_is_not_reported_as_a_complete_scan():
    scanner = scanner_with_alerts([])
    scanner._zap_api = Mock(side_effect=[{"alerts": [{"risk": "Low"}] * 500}, RuntimeError("ZAP connection lost")])
    with pytest.raises(RuntimeError, match="connection lost"):
        scanner._get_alerts(scanner.targets[0])
