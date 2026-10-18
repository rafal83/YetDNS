"""Emit independent application domain fixtures for the native test runner."""
import json
from pathlib import Path
import sys

snapshot = json.loads((Path(__file__).resolve().parents[1] / 'data/applications.json').read_text(encoding='utf-8'))
Path(sys.argv[1]).write_text(''.join(app['id'] + ' ' + domain + '\n' for app in snapshot['services'] for domain in app['domains']), encoding='utf-8')
