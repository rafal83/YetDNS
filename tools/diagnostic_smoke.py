"""Validate the browser-only diagnostic in Chromium with controlled network outcomes."""
import argparse
import json
from pathlib import Path
import urllib.parse
import urllib.request
from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--url', default='http://127.0.0.1:8765/diagnostic')
parser.add_argument('--embedded', action='store_true', help='Open the ESP dashboard and its diagnostic iframe')
parser.add_argument('--chrome', default=r'C:\Program Files\Google\Chrome\Application\chrome.exe')
args = parser.parse_args()
out = Path('build-device/diagnostic-controlled-tests'); out.mkdir(parents=True, exist_ok=True)
origin = urllib.parse.urlsplit(args.url)
base = origin.scheme + '://' + origin.netloc
for route, asset in (('/diagnostic', 'diagnostic.html'), ('/diagnostic.js', 'diagnostic.js')):
    with urllib.request.urlopen(base + route, timeout=10) as response:
        assert response.read().rstrip(b'\0') == (Path('main') / asset).read_bytes(), 'Wrong embedded resource: ' + route

with sync_playwright() as playwright:
    browser = playwright.chromium.launch(executable_path=args.chrome, headless=True)
    page = browser.new_page(viewport={'width': 1180, 'height': 1000}, accept_downloads=True)
    errors = []; page.on('pageerror', lambda error: errors.append(str(error)))
    requested = []

    def network(route):
        requested.append(route.request)
        host = route.request.url.split('/')[2]
        if host in ('example.com', 'www.mozilla.org', 'www.wikipedia.org', 'malware.testcategory.com'):
            route.fulfill(status=200, content_type='image/png', body=b'')
        else:
            route.abort('failed')

    page.route('https://**/*', network)
    page.goto(args.url, wait_until='domcontentloaded')
    if args.embedded:
        page.locator('[data-panel="diagnostic"]').click()
        ui = page.frame_locator('iframe[title="Test de protection depuis ce navigateur"]')
    else:
        ui = page
    ui.locator('#start-test').click()
    expect(ui.locator('#progress-text')).to_have_text('Test terminé. Rapport disponible.', timeout=20000)
    assert len(requested) == 26
    assert all(request.method == 'HEAD' for request in requested)
    assert all('cookie' not in request.headers and 'referer' not in request.headers for request in requested)
    with page.expect_download() as download:
        ui.locator('#export-json').click()
    download.value.save_as(str(out / 'controlled-report.json'))
    report = json.loads((out / 'controlled-report.json').read_text(encoding='utf-8'))
    summary = report['summary']
    assert summary['controls_reachable'] == 3 and summary['complete']
    groups = list(summary['groups'].values())
    assert groups[0]['apparent'] == 12 and groups[1]['apparent'] == 10 and groups[2]['reachable'] == 1
    assert not any(request.url.startswith(('http:', 'https://dns.google', 'https://cloudflare-dns.com')) for request in requested)
    with page.expect_download() as download:
        ui.locator('#export-html').click()
    download.value.save_as(str(out / 'controlled-report.html'))
    assert '<script' not in (out / 'controlled-report.html').read_text(encoding='utf-8')
    page.screenshot(path=str(out / 'diagnostic.png'), full_page=True)
    page.unroute('https://**/*', network)
    page.route('https://**/*', lambda route: route.abort('failed'))
    ui.locator('#start-test').click()
    expect(ui.locator('#progress-text')).to_contain_text('Test partiel', timeout=15000)
    expect(ui.locator('#report .warn')).to_contain_text('non concluant')
    assert ui.locator('#report tbody tr').count() == 3
    assert not errors, errors
    print(json.dumps(dict(browser_probes_only=True, controls_guard=True, category_results=True,
        json_export=True, offline_html_export=True, no_cookies_or_referrer=True,
        no_javascript_errors=True, embedded=args.embedded), indent=2))
    browser.close()
