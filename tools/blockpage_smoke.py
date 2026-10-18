"""Verify optional HTTP blocking and compact rule persistence on a live ESP."""
import argparse
import json
from pathlib import Path
import socket
import struct
import urllib.error
import urllib.request
from playwright.sync_api import sync_playwright, expect
from device_smoke import packet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ip', required=True)
    parser.add_argument('--chrome', default=r'C:\Program Files\Google\Chrome\Application\chrome.exe')
    args = parser.parse_args()

    def api(path, value=None):
        req = urllib.request.Request('http://' + args.ip + '/api/' + path,
            data=None if value is None else json.dumps(value).encode(), method='GET' if value is None else 'PUT',
            headers={'X-YetDNS': '1', 'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.load(r)

    def http(path, host):
        req = urllib.request.Request('http://' + args.ip + path, headers={'Host': host})
        try:
            response = urllib.request.urlopen(req, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.read()

    def answer(qtype):
        data = packet('yetdns-block-test.invalid', qtype)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.settimeout(8); connection.connect((args.ip, 53)); connection.send(data)
            result = connection.recv(4096)
        assert result[:2] == data[:2] and not result[3] & 15 and struct.unpack('!H', result[6:8])[0] == 1
        return result[-(4 if qtype == 1 else 16):]

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.connect((args.ip, 53)); client = connection.getsockname()[0]
    original = api('config'); original_rules = api('rules')
    probe = dict(domain='yetdns-block-test.invalid', action='deny', client=client)
    assert probe not in original_rules and len(original_rules) < 26
    temporary = [dict(domain=f'nvs{i}.yetdns-test.invalid', action='allow', client='192.0.2.1') for i in range(6)]
    all_temporary = temporary[1:] + [dict(domain=f'nvs0-{i}.yetdns-test.invalid', action='allow', client='192.0.2.1') for i in range(2)]
    written = False
    previous = original_rules
    try:
        # Repeated rewrites exercise replacement/collection after the former full-blob NVS failure.
        for i in range(12):
            assert api('rules') == previous, 'Concurrent changes detected; stopping the temporary rule test'
            temporary[0]['domain'] = f'nvs0-{i % 2}.yetdns-test.invalid'
            api('rules', original_rules + temporary + [probe]); written = True
            previous = api('rules'); assert previous == original_rules + temporary + [probe]
        api('config', {'block_page': True})
        assert answer(1) == socket.inet_aton(args.ip)
        assert answer(28) == bytes(16)
        for path in ('/', '/some/page?test=1', '/api/config'):
            status, body = http(path, 'yetdns-block-test.invalid')
            assert status == 403 and b'YetDNS' in body and b'Acc\xc3\xa8s bloqu\xc3\xa9' in body
            assert b'mqtt-password' not in body and b'config-form' not in body
        assert http('/', args.ip)[0] == 200
        assert http('/', args.ip + ':80')[0] == 200
        assert http('/api/config', args.ip)[0] == 200
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=args.chrome, headless=True,
                args=['--host-resolver-rules=MAP yetdns-block-test.invalid ' + args.ip])
            page = browser.new_page(viewport={'width': 390, 'height': 844})
            response = page.goto('http://yetdns-block-test.invalid/some/page', wait_until='domcontentloaded')
            assert response.status == 403
            expect(page.locator('h1')).to_contain_text('YetDNS')
            page.screenshot(path='build-device/blocked-page.png', full_page=True)
            browser.close()
    finally:
        api('config', {'block_page': original['block_page']})
        if written:
            current = api('rules')
            clean = [r for r in current if r != probe and r not in all_temporary]
            api('rules', clean)
    assert api('config')['block_page'] == original['block_page']
    assert all(r in api('rules') for r in original_rules)
    result = dict(nvs_six_domains_saved=True, repeated_replacements=12, dns_a_redirects_to_esp=True,
        aaaa_remains_sinkhole=True, http_page_root_and_paths=True, blocked_hosts_cannot_access_admin=True,
        direct_ip_admin_works=True, mobile_page_rendered=True, original_settings_restored=True)
    Path('build-device/blockpage-results.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
