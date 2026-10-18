"""Capture a boot over USB and smoke-test YetDNS on its assigned LAN address.

Uses pyserial from the ESP-IDF Python environment. Credentials/token stay in the
selected ignored build directory; serial output printed to the terminal is redacted.
"""
import argparse
import json
from pathlib import Path
import re
import secrets
import socket
import struct
import time
import urllib.request

import serial


def capture(port, seconds, directory):
    connection = serial.Serial(baudrate=115200, timeout=.2)
    connection.dtr = False
    connection.rts = False
    connection.port = port
    connection.open()
    connection.rts = True
    time.sleep(.15)
    connection.reset_input_buffer()
    connection.rts = False
    token, ip = None, None
    pending = b''
    log = []
    deadline = time.monotonic() + seconds
    try:
        while time.monotonic() < deadline:
            pending += connection.read(4096)
            while b'\n' in pending:
                raw, pending = pending.split(b'\n', 1)
                line = raw.decode('utf-8', 'replace').rstrip('\r')
                match = re.search(r'Admin bearer token \(keep private\): ([0-9a-f]{64})', line)
                if match:
                    token = match.group(1)
                    line = line.replace(token, '[legacy token redacted]')
                match = re.search(r'DNS ready at (\d+\.\d+\.\d+\.\d+):53', line)
                if match:
                    ip = match.group(1)
                print(line, flush=True)
                log.append(line)
    finally:
        connection.close()
        (directory / 'boot.log').write_text('\n'.join(log) + '\n', encoding='utf-8')
    return ip, token


def packet(name, qtype):
    ident = secrets.randbelow(65536)
    question = b''.join(bytes([len(label)]) + label.encode('ascii') for label in name.split('.'))
    question += b'\0' + struct.pack('!HH', qtype, 1)
    return struct.pack('!6H', ident, 0x100, 1, 0, 0, 0) + question


def receive_exact(connection, size):
    data = b''
    while len(data) < size:
        part = connection.recv(size - len(data))
        if not part:
            raise RuntimeError('TCP connection closed early')
        data += part
    return data


def dns(ip, name, qtype=1, tcp=False, expected=None):
    query = packet(name, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as connection:
        connection.settimeout(8)
        connection.connect((ip, 53))
        if tcp:
            connection.sendall(struct.pack('!H', len(query)) + query)
            response = receive_exact(connection, struct.unpack('!H', receive_exact(connection, 2))[0])
        else:
            connection.send(query)
            response = connection.recv(4096)
    if len(response) < 12 or response[:2] != query[:2] or not response[2] & 0x80 or response[3] & 15:
        raise RuntimeError(f'Invalid DNS response for {name}: {response[:12].hex()}')
    if struct.unpack('!H', response[6:8])[0] < 1:
        raise RuntimeError(f'Missing answer for {name}')
    if expected is not None and response[-len(expected):] != expected:
        raise RuntimeError(f'Unexpected sinkhole address for {name}')
    return {'name': name, 'type': qtype, 'transport': 'TCP' if tcp else 'UDP', 'bytes': len(response), 'ok': True}


def smoke(ip, token):
    base = f'http://{ip}'
    request = urllib.request.Request(base + '/api/stats', headers={})
    with urllib.request.urlopen(base, timeout=8) as response:
        html = response.read()
        if response.status != 200 or b'YetDNS' not in html:
            raise RuntimeError('Dashboard unavailable')
    checks = [dns(ip, 'pagead2.googlesyndication.com', expected=b'\0' * 4),
              dns(ip, 'pagead2.googlesyndication.com', 28, expected=b'\0' * 16),
              dns(ip, 'pagead2.googlesyndication.com', tcp=True, expected=b'\0' * 4),
              dns(ip, 'example.com'), dns(ip, 'example.com')]
    with urllib.request.urlopen(request, timeout=8) as response:
        stats = json.load(response)
    if stats['blocked'] < 3 or stats['cached'] < 1:
        raise RuntimeError('Block/cache counters do not reflect smoke queries')
    return {'ip': ip, 'dashboard': True, 'checks': checks, 'stats': stats}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', default='COM4')
    parser.add_argument('--seconds', type=int, default=40)
    parser.add_argument('--directory', type=Path, default=Path('build-device'))
    parser.add_argument('--ip')
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=True)
    if args.ip:
        ip = args.ip
        token = None
    else:
        ip, token = capture(args.port, args.seconds, args.directory)
    if not ip:
        raise SystemExit('No Wi-Fi address captured. See the redacted boot.log.')
    (args.directory / 'connection.json').write_text(json.dumps({'ip': ip, 'dashboard': f'http://{ip}'}, indent=2), encoding='utf-8')
    result = smoke(ip, token)
    (args.directory / 'smoke-results.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
