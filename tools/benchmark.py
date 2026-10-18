"""Measure DNS UDP latency/throughput from a LAN computer. Python stdlib only."""
import argparse
import asyncio
import json
import math
import secrets
import statistics
import struct
import time


def make_question(name, qtype):
    labels = name.rstrip('.').encode('idna').split(b'.')
    if not labels or any(not label or len(label) > 63 for label in labels):
        raise ValueError('Invalid DNS name')
    wire = b''.join(bytes([len(label)]) + label for label in labels) + b'\0'
    if len(wire) > 255:
        raise ValueError('DNS name too long')
    return wire + struct.pack('!HH', qtype, 1)


class Client(asyncio.DatagramProtocol):
    def __init__(self, question):
        self.question = question
        self.pending = {}
        self.invalid = 0
        self.errors = 0
        self.next_id = secrets.randbelow(65536)

    def datagram_received(self, data, _):
        if len(data) < 12:
            self.invalid += 1
            return
        ident, flags, qd = struct.unpack('!HHH', data[:6])
        future = self.pending.get(ident)
        if not future or future.done():
            return
        if not flags & 0x8000 or qd != 1 or data[12:12 + len(self.question)].lower() != self.question.lower():
            self.invalid += 1
            return
        future.set_result(flags)

    def error_received(self, _):
        self.errors += 1

    def reserve(self, future):
        while self.next_id in self.pending:
            self.next_id = (self.next_id + 1) & 65535
        ident = self.next_id
        self.next_id = (self.next_id + 1) & 65535
        self.pending[ident] = future
        return ident


async def benchmark(args):
    question = make_question(args.name, 28 if args.aaaa else 1)
    loop = asyncio.get_running_loop()
    client = Client(question)
    transport, _ = await loop.create_datagram_endpoint(lambda: client, remote_addr=(args.server, 53))
    latencies, rcodes = [], {}
    counts = {'sent': 0, 'timeouts': 0, 'truncated': 0}

    async def worker():
        while counts['sent'] < args.queries:
            counts['sent'] += 1
            future = loop.create_future()
            ident = client.reserve(future)
            packet = struct.pack('!6H', ident, 0x100, 1, 0, 0, 0) + question
            start = time.perf_counter()
            transport.sendto(packet)
            try:
                flags = await asyncio.wait_for(future, args.timeout)
                latencies.append((time.perf_counter() - start) * 1000)
                rcode = flags & 15
                rcodes[rcode] = rcodes.get(rcode, 0) + 1
                counts['truncated'] += bool(flags & 0x200)
            except asyncio.TimeoutError:
                counts['timeouts'] += 1
            finally:
                client.pending.pop(ident, None)

    start = time.perf_counter()
    try:
        await asyncio.gather(*(worker() for _ in range(args.concurrency)))
    finally:
        transport.close()
    elapsed = time.perf_counter() - start
    latencies.sort()

    def percentile(p):
        return round(latencies[max(0, math.ceil(len(latencies) * p) - 1)], 3) if latencies else None

    return {'server': args.server, 'name': args.name, 'concurrency': args.concurrency,
            **counts, 'received': len(latencies), 'rcodes': rcodes,
            'invalid': client.invalid, 'socket_errors': client.errors,
            'elapsed_s': round(elapsed, 3), 'responses_per_second': round(len(latencies) / elapsed, 1),
            'mean_ms': round(statistics.mean(latencies), 3) if latencies else None,
            'p50_ms': percentile(.5), 'p95_ms': percentile(.95), 'p99_ms': percentile(.99)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', required=True)
    parser.add_argument('--name', default='ads.example')
    parser.add_argument('--queries', type=int, default=1000)
    parser.add_argument('--concurrency', type=int, default=4)
    parser.add_argument('--timeout', type=float, default=2)
    parser.add_argument('--aaaa', action='store_true')
    args = parser.parse_args()
    if args.queries < 1 or not 1 <= args.concurrency <= 1024 or args.timeout <= 0:
        parser.error('queries/timeout must be positive; concurrency must be 1..1024')
    print(json.dumps(asyncio.run(benchmark(args)), indent=2))


if __name__ == '__main__':
    main()
