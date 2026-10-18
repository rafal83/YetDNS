"""Exercise application/white/black controls on this computer's IP, then restore.

Uses Playwright with Chrome. Does not change global policies. A concurrent change
to the temporary device scope is preserved instead of being overwritten.
"""
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

    def api(path, body=None):
        req = urllib.request.Request('http://' + args.ip + '/api/' + path,
            data=None if body is None else json.dumps(body).encode(), method='GET' if body is None else 'PUT',
            headers={'X-YetDNS': '1', 'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.load(response)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.connect((args.ip, 53)); client = connection.getsockname()[0]

    def query(name, qtype=1, blocked=True, tcp=False):
        data = packet(name, qtype)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as connection:
            connection.settimeout(8); connection.connect((args.ip, 53))
            if tcp:
                connection.sendall(struct.pack('!H', len(data)) + data)
                prefix = connection.recv(2); assert len(prefix) == 2
                size = struct.unpack('!H', prefix)[0]; reply = b''
                while len(reply) < size:
                    chunk = connection.recv(size - len(reply)); assert chunk; reply += chunk
            else:
                connection.send(data); reply = connection.recv(4096)
        assert reply[:2] == data[:2] and not (reply[3] & 15) and struct.unpack('!H', reply[6:8])[0]
        sinkhole = reply[-(16 if qtype == 28 else 4):] == bytes(16 if qtype == 28 else 4)
        assert sinkhole == blocked, 'Unexpected DNS policy for ' + name

    def device_apps(data):
        return next((c['blocked'] for c in data['clients'] if c['client'] == client), [])

    original_apps = api('apps'); original_rules = api('rules')
    assert len(original_apps['catalog']) == 43
    assert not any(r['domain'] in ('youtube.com', 'www.youtube.com', 'com') for r in original_rules), 'Choose a scope without pre-existing YouTube exceptions'
    expected_apps, expected_rules = None, None
    errors = []
    try:
        try:
            api('apps', {'client': client, 'blocked': ['unknown-service']})
        except urllib.error.HTTPError as error:
            assert error.code == 400
        else:
            raise AssertionError('Unknown application accepted')
        assert api('apps') == original_apps
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=args.chrome, headless=True)
            page = browser.new_page(viewport={'width': 1180, 'height': 1000})
            def open_filter(group):
                page.locator('[data-panel="filtering"]').click()
                detail = page.locator('#filter-' + group)
                if detail.get_attribute('open') is None:
                    detail.locator(':scope > summary').click()
            page.on('pageerror', lambda e: errors.append(str(e)))
            page.goto('http://' + args.ip, wait_until='domcontentloaded')
            open_filter('applications')
            expect(page.locator('#app-cards label')).to_have_count(43)
            page.locator('#apps-client').fill(client); page.locator('#apps-load').click()
            expect(page.locator('#apps-scope')).to_contain_text('Appareil ' + client)
            checkbox = page.locator('#app-cards input[value="youtube"]')
            if not checkbox.is_disabled():
                checkbox.check(); page.locator('#apps-save').click()
                expected_apps = sorted(set(device_apps(original_apps)) | {'youtube'})
                expect(page.locator('#message')).to_contain_text('Blocages des applications enregistr')
            query('www.youtube.com'); query('r1.googlevideo.com'); query('www.youtube.com', 28)
            query('www.youtube.com', tcp=True)
            for kind, domain in [('allow', 'www.youtube.com'), ('deny', 'yetdns-app-test.invalid')]:
                open_filter('exceptions')
                page.locator('#' + kind + '-client').fill(client); page.locator('#' + kind + '-load').click()
                expect(page.locator('#' + kind + '-scope')).to_contain_text('Appareil ' + client)
                field = page.locator('#' + kind + '-domains')
                field.fill(field.input_value() + '\n' + domain)
                baseline = api('rules')
                expected_rules = baseline + [dict(domain=domain, action=kind, client=client)]
                page.locator('#' + kind + '-save').click()
                expect(page.locator('#message')).to_contain_text(('Liste blanche' if kind == 'allow' else 'Liste noire') + ' enregistr')
                expected_rules = api('rules')
                assert all(rule in expected_rules for rule in original_rules), 'Existing rules were lost'
                query(domain, blocked=kind == 'deny')
            open_filter('applications')
            page.locator('#apps-search').fill('youtube')
            assert page.locator('#app-cards label:visible').count() == 1
            page.screenshot(path='build-device/applications-v03.png', full_page=True)
            assert not errors, errors
            browser.close()
    finally:
        if expected_rules is not None:
            if api('rules') == expected_rules:
                api('rules', original_rules)
            else:
                raise RuntimeError('Concurrent rule change preserved; inspect temporary test rules')
        if expected_apps is not None:
            if sorted(device_apps(api('apps'))) == expected_apps:
                api('apps', dict(client=client, blocked=device_apps(original_apps)))
            else:
                raise RuntimeError('Concurrent application change preserved; inspect test scope')
    assert api('rules') == original_rules and api('apps') == original_apps
    result = dict(catalog=43, invalid_id_rejected=True, per_device_blocking=True, dns_a_aaaa_udp_tcp=True,
                  whitelist_overrides_application=True, blacklist_blocks=True, ui_search=True,
                  existing_rules_preserved=True, original_settings_restored=True, javascript_errors=errors)
    Path('build-device/apps-results.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
