"""Browser crawling is required for active policies and cannot silently fail."""
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest

from scanners import external_vuln


def test_browser_uses_headless_firefox_and_strict_target_scope():
    scanner = external_vuln.ZAPScanner('https://example.test/app/', 'org')
    scanner._zap_api = Mock(side_effect=[
        {'stats.client.spider.urls': '4'}, {'scan': '7'}, {'status': '100'},
        {'stats.client.spider.urls': '12'},
    ])
    scanner._crawl_browser(scanner.targets[0])
    paths = [call.args[0] for call in scanner._zap_api.call_args_list]
    options = parse_qs(urlsplit(paths[1]).query)
    assert options == {'url': ['https://example.test/app/'], 'browser': ['firefox-headless'],
                       'subtreeOnly': ['true'], 'numberOfBrowsers': ['1'], 'scopeCheck': ['STRICT']}
    assert 'scanId=7' in paths[2]


def test_browser_reporting_done_without_fetching_urls_is_failure(monkeypatch):
    scanner = external_vuln.ZAPScanner('https://example.test/', 'org')
    scanner._zap_api = Mock(side_effect=[{}, {'scan': '1'}, {'status': '100'}] + [{}] * 5)
    monkeypatch.setattr(external_vuln.time, 'sleep', Mock())
    with pytest.raises(RuntimeError, match='fetched no URLs'):
        scanner._crawl_browser(scanner.targets[0])


def test_finished_browser_counters_can_arrive_after_status(monkeypatch):
    scanner = external_vuln.ZAPScanner('https://example.test/', 'org')
    scanner._zap_api = Mock(side_effect=[{}, {'scan': '1'}, {'status': '100'}, {}, {'stats.client.spider.urls': '8'}])
    sleep = Mock()
    monkeypatch.setattr(external_vuln.time, 'sleep', sleep)
    scanner._crawl_browser(scanner.targets[0])
    sleep.assert_called_once_with(0.5)


def test_native_browser_time_limit_is_not_a_complete_crawl():
    scanner = external_vuln.ZAPScanner('https://example.test/', 'org')
    scanner._zap_api = Mock(side_effect=[
        {'stats.client.spider.event.max.time': '1'}, {'scan': '1'}, {'status': '100'},
        {'stats.client.spider.urls': '8', 'stats.client.spider.event.max.time': '2'},
    ])
    with pytest.raises(RuntimeError, match='configured time limit'):
        scanner._crawl_browser(scanner.targets[0])


def test_missing_client_spider_is_not_silently_replaced_with_basic_crawl():
    scanner = external_vuln.ZAPScanner('https://example.test/', 'org')
    scanner._zap_api = Mock(side_effect=[{}, RuntimeError('no_implementor: clientSpider')])
    with pytest.raises(RuntimeError, match='no_implementor'):
        scanner._crawl_browser(scanner.targets[0])


@pytest.mark.parametrize('stop_error', [False, True])
def test_browser_timeout_stops_its_scan_and_keeps_timeout_reason(monkeypatch, stop_error):
    scanner = external_vuln.ZAPScanner('https://example.test/', 'org')
    scanner._zap_api = Mock(side_effect=[{}, {'scan': '9'},
                                        RuntimeError('already stopped') if stop_error else {'Result': 'OK'}])
    monkeypatch.setattr(external_vuln.time, 'monotonic', Mock(side_effect=[0, 601]))
    with pytest.raises(RuntimeError, match='ten minutes'):
        scanner._crawl_browser(scanner.targets[0])
    assert '/clientSpider/action/stop/?scanId=9' in scanner._zap_api.call_args.args[0]


def test_active_policy_requires_installed_browser(monkeypatch):
    monkeypatch.setattr(external_vuln.shutil, 'which', lambda name: None)
    scanner = external_vuln.ZAPScanner('https://example.test/', 'org', profile='Pen Test.policy')
    with pytest.raises(RuntimeError, match='require Firefox'):
        scanner._start_daemon()


def test_active_policy_waits_for_browser_before_attacking(monkeypatch):
    scanner = external_vuln.ZAPScanner('https://example.test/', 'org')
    scanner.policy_name = 'Imported policy'
    phases = []
    scanner._crawl_browser = lambda url: phases.append('browser')

    def api(path):
        if '/accessUrl/' in path:
            return {'accessUrl': [{'responseHeader': 'HTTP/1.1 200 OK\r\n'}]}
        if '/spider/action/' in path:
            phases.append('traditional')
            return {'scan': '1'}
        if '/ascan/action/' in path:
            phases.append('active')
            return {'scan': '2'}
        if '/status/' in path:
            return {'status': '100'}
        if '/recordsToScan/' in path:
            return {'recordsToScan': '0'}
        return {'alerts': []}

    scanner._zap_api = api
    assert scanner._scan_target(scanner.targets[0]) == []
    assert phases == ['traditional', 'browser', 'active']


def test_browser_failure_prevents_active_scan_and_still_stops_daemon():
    scanner = external_vuln.ZAPScanner('https://example.test/', 'org', profile='Pen Test.policy')
    scanner._start_daemon = Mock(return_value=True)
    scanner._stop_daemon = Mock()
    scanner._load_policy = Mock(side_effect=lambda: setattr(scanner, 'policy_name', 'Imported policy'))
    scanner._zap_api = Mock(side_effect=[
        {'accessUrl': [{'responseHeader': 'HTTP/1.1 200 OK\r\n'}]}, {'scan': '1'}, {'status': '100'},
    ])
    scanner._crawl_browser = Mock(side_effect=RuntimeError('Browser startup failed'))
    with pytest.raises(RuntimeError, match='Browser startup failed'):
        scanner.run()
    assert not any('/ascan/' in call.args[0] for call in scanner._zap_api.call_args_list)
    scanner._stop_daemon.assert_called_once()
