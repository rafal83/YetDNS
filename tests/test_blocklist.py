import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
import zlib

spec = importlib.util.spec_from_file_location('builder', Path(__file__).parents[1] / 'tools/build_blocklist.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class BlocklistTests(unittest.TestCase):
    def parse(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'list.txt'
            path.write_text(text, encoding='utf-8')
            return builder.parse_file(path)

    def test_formats_and_normalization(self):
        self.assertEqual(self.parse('# comment\n0.0.0.0 Ads.Example. ads2.example # test\n||tracker.example^\n'),
                         {'ads.example', 'ads2.example', 'tracker.example'})
        self.assertEqual(builder.normalize('café.example'), 'xn--caf-dma.example')

    def test_adblock_plus_header_is_ignored(self):
        self.assertEqual(self.parse('[Adblock Plus]\n! Title: oisd big\n||tracker.example^\n'), {'tracker.example'})
        with self.assertRaises(ValueError):
            self.parse('[not a header|^]')

    def test_unsupported_rules_fail(self):
        for text in ('@@||example.com^', '||example.com^$third-party', '*.example.com', 'bad..example', '1.2.3.4'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.parse(text)

    def test_front_coded_layout_crc_and_dedup(self):
        domains = self.parse('b.example\na.example\nb.example\n')
        blob = builder.compile_domains(domains)
        magic, version, count, size, crc = struct.unpack('<4sIIII', blob[:20])
        self.assertEqual((magic, version, count, size), (b'YDNS', 2, 2, 14))
        self.assertEqual(crc, zlib.crc32(blob[20:]))
        self.assertEqual(struct.unpack('<2I', blob[20:28]), (0, 14))
        self.assertEqual(blob[28:], b'\x00\x09elpmaxe.a\x08\x01b')

    def test_covered_subdomains_are_pruned(self):
        domains = {'ads.example', 'x.ads.example', 'y.x.ads.example', 'notads.example', 'other.test'}
        self.assertEqual(builder.prune(domains), {'ads.example', 'notads.example', 'other.test'})
        blob = builder.compile_domains(domains)
        self.assertEqual(struct.unpack('<I', blob[8:12])[0], 3)

    def test_blocks_decode_to_the_pruned_sorted_set(self):
        domains = {f'd{i}.zone{i % 7}.test' for i in range(200)} | {'zone3.test', 'a-b.example', 'ab.example', 'b.example'}
        blob = builder.compile_domains(domains)
        count, size = struct.unpack('<II', blob[8:16])
        blocks = (count + builder.BLOCK_ENTRIES - 1) // builder.BLOCK_ENTRIES
        offsets = struct.unpack(f'<{blocks + 1}I', blob[20:24 + blocks * 4])
        body = blob[24 + blocks * 4:]
        self.assertEqual((offsets[0], offsets[-1], len(body)), (0, size, size))
        entries, position, previous = [], 0, b''
        for i in range(count):
            if i % builder.BLOCK_ENTRIES == 0:
                self.assertEqual(position, offsets[i // builder.BLOCK_ENTRIES])
                previous = b''
            shared, length = body[position], body[position + 1]
            previous = previous[:shared] + body[position + 2:position + 2 + length]
            entries.append(previous.decode()[::-1])
            position += 2 + length
        self.assertEqual(sorted(entries, key=lambda name: name[::-1]), entries)
        self.assertEqual(set(entries), builder.prune(domains))
        self.assertNotIn('d3.zone3.test', entries)

    def test_empty_and_long_labels(self):
        self.assertEqual(len(builder.compile_domains(set())), 24)
        with self.assertRaises(ValueError):
            builder.normalize('a' * 64 + '.example')

    def test_standard_hosts_local_headers(self):
        self.assertEqual(self.parse('fe80::1%lo0 localhost\nff02::1 ip6-allnodes\n0.0.0.0 0.0.0.0\n127.0.0.1 local\n0.0.0.0 ads.example\n'), {'ads.example'})


if __name__ == '__main__':
    unittest.main()
