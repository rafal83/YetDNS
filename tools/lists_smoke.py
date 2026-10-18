"""Validate list update failure retention and public configuration on a real ESP.

Temporarily installs a nonexistent source, then restores original sources if no
other client changed them meanwhile. The active DNS filter remains in service.
"""
import argparse
import json
from pathlib import Path
import time
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ip', required=True)
    parser.add_argument('--output', type=Path, default=Path('build-device/lists-results.json'))
    args = parser.parse_args()

    def api(path, method='GET', body=None):
        request = urllib.request.Request('http://' + args.ip + '/api/' + path, method=method,
            headers={'X-YetDNS': '1', 'Content-Type': 'application/json'},
            data=None if body is None else json.dumps(body).encode())
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.load(response)

    def settings(value):
        return {k: value[k] for k in ('automatic', 'interval_hours', 'sources')}

    def await_idle(min_generation=0, timeout=100):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            value = api('lists'); state = value['status']
            if not state['busy'] and not state['pending'] and state['generation'] >= min_generation:
                return value
            time.sleep(1)
        raise RuntimeError('Update did not complete')

    before = await_idle(); original = settings(before); count = before['status']['domains']
    assert count > 4 and before['status']['last_success'] > 0
    cfg = api('config'); assert cfg['logging'] is True
    mqtt = api('mqtt'); assert 'password' not in mqtt and mqtt['device_id']
    try:
        api('config', 'PUT', {'doh_url': 'http://invalid.example/dns-query'})
    except urllib.error.HTTPError as error:
        assert error.code == 400
    else:
        raise AssertionError('Invalid DoH URL was accepted')
    assert api('config') == cfg
    failure_config = {'automatic': original['automatic'], 'interval_hours': original['interval_hours'],
        'sources': [{'name': 'Failure validation', 'enabled': True,
                     'url': 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/yetdns-nonexistent-validation.txt'}]}
    restored = False
    try:
        api('lists', 'PUT', failure_config)
        failed = await_idle()
        assert failed['status']['domains'] == count
        assert failed['status']['generation'] == before['status']['generation']
        assert failed['status']['outdated'] and 'failed' in failed['status']['message'].lower()
        print('Failed download retained', count, 'active domains', flush=True)
    finally:
        if settings(api('lists')) == failure_config:
            api('lists', 'PUT', original); restored = True
    final = await_idle(before['status']['generation'] + 1) if restored else api('lists')
    assert final['status']['domains'] >= count and not final['status']['outdated']
    result = {'no_auth': True, 'logging_enabled': True, 'invalid_advanced_config_rejected': True,
        'failure_retained_domains': count, 'config_restored': restored, 'final_status': final['status'],
        'mqtt_ready': bool(mqtt['device_id']), 'mqtt_connected': mqtt['connected']}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
