"""Compile local hosts/domain/limited Adblock lists to an exact flash index.

No downloads or hashes. Unsupported rules fail rather than change their meaning.
Format (version 2): YDNS, version:u32, count:u32, data_size:u32, crc32(payload):u32;
then ceil(count/16)+1 little endian u32 block offsets and the front-coded entries.
Domains are reversed ("com.example.ads") and sorted bytewise. Each entry is
shared:u8, suffix_len:u8, suffix bytes; the first entry of a block shares nothing.
Domains already covered by a listed parent are dropped (same blocking result).
Adblock Plus lists (header "[Adblock Plus...]") are read leniently: only ||domain^ and
||domain^$third-party are kept; every other rule is skipped.
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


def abp_domain(line):
    """Domain of an Adblock Plus rule DNS can express (||domain^ or ||domain^$third-party), else None."""
    match = re.fullmatch(r'\|\|([^^]*)\^(?:\$(?:third-party|3p))?', line)
    if not match or not match.group(1).isascii():
        return None
    value = match.group(1).lower().rstrip('.')
    if value in ('localhost', 'local', 'localhost.localdomain', 'broadcasthost') or value.startswith('ip6-'):
        return None
    try:
        return normalize(value)
    except (ValueError, UnicodeError):
        return None


def parse_file(path):
    domains, abp = set(), False
    for line_no, raw in enumerate(Path(path).read_text(encoding='utf-8-sig').splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(('#', '!')):
            continue
        if re.fullmatch(r'\[[^\[|^/$]+\]', line):  # Adblock Plus header, e.g. [Adblock Plus]
            abp = line.lower().startswith('[adblock')
            continue
        if abp:  # keep what DNS can express, skip every other rule (exceptions, URL patterns, cosmetic...)
            domain = abp_domain(line)
            if domain:
                domains.add(domain)
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


BLOCK_ENTRIES = 16


def prune(domains):
    """Drop every domain whose parent domain is also listed."""
    kept = set()
    for name in domains:
        labels = name.split('.')
        if not any('.'.join(labels[i:]) in domains for i in range(1, len(labels))):
            kept.add(name)
    return kept


def compile_domains(domains):
    values = sorted(s[::-1].encode('ascii') for s in prune(domains))
    offsets, body, previous = [], bytearray(), b''
    for i, value in enumerate(values):
        shared = 0
        if i % BLOCK_ENTRIES:
            while shared < min(len(value), len(previous)) and value[shared] == previous[shared]:
                shared += 1
        else:
            offsets.append(len(body))
        body += bytes((shared, len(value) - shared)) + value[shared:]
        previous = value
    offsets.append(len(body))
    payload = struct.pack(f'<{len(offsets)}I', *offsets) + bytes(body)
    return struct.pack('<4sIIII', b'YDNS', 2, len(values), len(body), zlib.crc32(payload)) + payload


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
    print(f'YetDNS: {len(domains):,} domains read, {len(blob):,} bytes')


if __name__ == '__main__':
    main()
