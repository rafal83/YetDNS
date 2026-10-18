"""Launch the same browser-based protection test on a PC, independently of the ESP.

Python standard library only. Probes use the user's browser networking/DNS; the
Python server only serves the UI and saves reports on this PC. No DNS reconfiguration.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import threading
import webbrowser

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--output', type=Path, default=ROOT / 'build-reports')
    parser.add_argument('--run', action='store_true', help='Start the default probes when the page opens')
    parser.add_argument('--no-open', action='store_true', help='Print the URL without opening a browser')
    parser.add_argument('--once', action='store_true', help='Exit after saving one report')
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error('port must be 0..65535')
    assets = {'/': ('diagnostic.html', 'text/html; charset=utf-8'),
              '/diagnostic': ('diagnostic.html', 'text/html; charset=utf-8'),
              '/diagnostic.js': ('diagnostic.js', 'application/javascript; charset=utf-8')}
    output = args.output.resolve()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, data=b'', content_type='text/plain; charset=utf-8'):
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self' https:; frame-ancestors 'self'; base-uri 'none'")
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            asset = assets.get(self.path.split('?', 1)[0])
            if not asset:
                return self.reply(404)
            return self.reply(200, (ROOT / 'main' / asset[0]).read_bytes(), asset[1])

        def do_POST(self):
            if self.path != '/report':
                return self.reply(404)
            origin = 'http://127.0.0.1:' + str(self.server.server_port)
            if self.headers.get('Origin') != origin or self.headers.get('X-YetDNS-Test') != '1':
                return self.reply(403)
            try:
                size = int(self.headers.get('Content-Length', 0))
                if not 0 < size <= 2 * 1024 * 1024:
                    return self.reply(413)
                value = json.loads(self.rfile.read(size))
                report, html = value['report'], value['html']
                if report['schema'] != 1 or report['execution'] != 'browser' or len(report['results']) > 500 or not isinstance(html, str):
                    return self.reply(400)
                stamp = re.sub(r'[^0-9TZ-]', '-', report['generated_at'])[:40]
                output.mkdir(parents=True, exist_ok=True)
                base = output / ('yetdns-report-' + stamp)
                base.with_suffix('.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
                base.with_suffix('.html').write_text(html, encoding='utf-8')
            except (ValueError, KeyError, TypeError, OSError):
                return self.reply(400, b'Cannot save report')
            self.reply(200, b'{"saved":true}', 'application/json')
            print('Report:', base.with_suffix('.html'), flush=True)
            print('JSON:', base.with_suffix('.json'), flush=True)
            if args.once:
                threading.Thread(target=self.server.shutdown, daemon=True).start()

    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    url = 'http://127.0.0.1:' + str(server.server_port) + '/diagnostic?save=1' + ('&run=1' if args.run else '')
    print('Browser test:', url, flush=True)
    print('Reports stay on this PC. Ctrl+C to stop.', flush=True)
    if not args.no_open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
