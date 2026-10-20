"""Compile local hosts/domain/limited Adblock lists to an exact flash index.

No downloads or hashes. Unsupported rules fail rather than change their meaning.
Format: YDNS, version:u32, count:u32, pool_size:u32, crc32(payload):u32;
count+1 little endian u32 offsets followed by sorted ASCII domain bytes.
"""
import argparse
import ipaddress
from pathlib import Path
import re
import struct
import zlib


def normalize(value):
    name = value.rstrip('.').lower().encode('idna').decode('ascii')
    if len(name) > 253 or not name or any(
        not re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?', part)
        for part in name.split('.')
    ):
        raise ValueError(f'invalid domain: {value!r}')
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise ValueError(f'IP address is not a domain: {value!r}')


def parse_file(path):
    domains = set()
    for line_no, raw in enumerate(Path(path).read_text(encoding='utf-8-sig').splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(('#', '!')):
            continue
        if re.fullmatch(r'\[[^\[|^/$]+\]', line):  # Adblock Plus header, e.g. [Adblock Plus]
            continue
        line = line.split('#', 1)[0].strip()
        if line.startswith('||') and line.endswith('^'):
            values = [line[2:-1]]
        else:
            values = line.split()
            if ':' in values[0] and len(values) == 2 and (values[1] == 'localhost' or values[1].startswith('ip6-')):
                continue
            if values[0] in ('0.0.0.0', '127.0.0.1', '255.255.255.255', '::', '::1'):
                values = values[1:]
                values = [s for s in values if s not in ('0.0.0.0', '127.0.0.1')]
            elif len(values) != 1:
                raise ValueError(f'{path}:{line_no}: unsupported rule: {raw}')
        for value in values:
            if value in ('localhost', 'local', 'localhost.localdomain', 'broadcasthost') or value.startswith('ip6-'):
                continue
            try:
                domains.add(normalize(value))
            except (ValueError, UnicodeError) as error:
                raise ValueError(f'{path}:{line_no}: {error}') from error
    return domains


def compile_domains(domains):
    values = [s.encode('ascii') for s in sorted(domains)]
    offsets, pos = [0], 0
    for value in values:
        pos += len(value)
        offsets.append(pos)
    payload = struct.pack(f'<{len(offsets)}I', *offsets) + b''.join(values)
    return struct.pack('<4sIIII', b'YDNS', 1, len(values), pos, zlib.crc32(payload)) + payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('sources', nargs='+', type=Path)
    args = parser.parse_args()
    domains = set()
    for source in args.sources:
        domains.update(parse_file(source))
    blob = compile_domains(domains)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(blob)
    print(f'YetDNS: {len(domains):,} exact domains, {len(blob):,} bytes')


if __name__ == '__main__':
    main()
