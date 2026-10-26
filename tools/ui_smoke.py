"""Check the deployed tabbed UI in a real Chromium browser (Playwright)."""
import argparse
import json
from pathlib import Path
from playwright.sync_api import sync_playwright

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--ip', required=True)
parser.add_argument('--chrome', default=r'C:\Program Files\Google\Chrome\Application\chrome.exe')
args = parser.parse_args()
out = Path('build-device'); out.mkdir(exist_ok=True)
with sync_playwright() as playwright:
    browser = playwright.chromium.launch(executable_path=args.chrome, headless=True)
    page = browser.new_page(viewport={'width': 1180, 'height': 1000})
    errors = []
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.goto('http://' + args.ip, wait_until='domcontentloaded')
    for _ in range(100):
        if page.locator('#queries').inner_text() != '\u2014':
            break
        page.wait_for_timeout(200)
    else:
        raise AssertionError('Dashboard did not load its live state')
    tabs = ['live', 'filtering', 'advanced', 'journal', 'diagnostic', 'home-assistant']
    def open_filter(group):
        page.locator('[data-panel="filtering"]').click()
        detail = page.locator('#filter-' + group)
        if detail.get_attribute('open') is None:
            detail.locator(':scope > summary').click()
    def check_menu():
        boxes = [page.locator('[data-panel="' + tab + '"]').bounding_box() for tab in tabs]
        row = max(b['y'] for b in boxes) - min(b['y'] for b in boxes) < 1
        column = max(b['x'] for b in boxes) - min(b['x'] for b in boxes) < 1
        assert row or column, boxes
    check_menu()
    for tab in tabs:
        page.locator('[data-panel="' + tab + '"]').click()
        assert page.locator('#' + tab).is_visible(), tab
        for other in tabs:
            if other != tab:
                assert not page.locator('#' + other).is_visible(), (tab, other)
    page.locator('[data-panel="advanced"]').click()
    assert not page.locator('#logging').is_visible()
    assert page.locator('#block_page').is_visible()
    assert page.locator('#primary').input_value()
    assert page.locator('#doh_url').input_value().startswith('https://')
    open_filter('applications')
    for _ in range(100):
        if page.locator('#app-cards label').count() == 43:
            break
        page.wait_for_timeout(100)
    assert page.locator('#app-cards label').count() == 43
    page.locator('#apps-search').fill('youtube')
    assert page.locator('#app-cards label:visible').count() == 1
    assert 'YouTube' in page.locator('#app-cards label:visible').inner_text()
    page.locator('#apps-search').fill('')
    open_filter('exceptions')
    assert page.locator('#allow-domains').is_visible()
    assert page.locator('#deny-domains').is_visible()
    page.locator('[data-panel="journal"]').click()
    assert page.locator('#log-blocked-only').is_visible()
    assert page.locator('#logging').is_visible() and page.locator('#logging').is_checked()
    page.locator('[data-panel="diagnostic"]').click()
    assert page.locator('iframe[title="Test de protection depuis ce navigateur"]').is_visible()
    open_filter('rules')
    assert page.locator('#rules-help').is_visible()
    example = json.loads(page.locator('#rules-example').inner_text())
    assert {rule['action'] for rule in example} == {'rewrite'}
    assert any(rule.get('client') == '192.168.1.50' for rule in example)
    page.locator('[data-panel="home-assistant"]').click()
    assert page.locator('#mqtt-form').is_visible()
    open_filter('lists')
    for group in ('applications', 'exceptions', 'rules'):
        page.locator('#filter-' + group).evaluate('(element) => element.open = false')
    assert page.locator('#sources .source').count() >= 3
    assert not page.locator('input#token').count()
    page.screenshot(path=str(out / 'dashboard-v02.png'), full_page=True)
    page.set_viewport_size({'width': 1000, 'height': 844})
    check_menu()
    page.set_viewport_size({'width': 390, 'height': 844})
    check_menu()
    page.screenshot(path=str(out / 'dashboard-mobile-v02.png'), full_page=True)
    assert not errors, errors
    result = {'tabs': tabs, 'menu_single_line': True, 'filter_groups': 4, 'mutually_exclusive': True, 'logging_checked': True, 'no_login': True, 'per_device_example': True, 'javascript_errors': errors}
    (out / 'ui-results.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    browser.close()
