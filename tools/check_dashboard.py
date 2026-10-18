"""Extract the embedded JavaScript for `node --check` (no browser required)."""
from pathlib import Path
import argparse

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('output', type=Path)
args = parser.parse_args()
html = (Path(__file__).parents[1] / 'main/dashboard.html').read_text(encoding='utf-8')
script = html.split('<script>', 1)[1].split('</script>', 1)[0]
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(script, encoding='utf-8')
