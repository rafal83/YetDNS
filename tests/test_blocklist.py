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

    def test_unsupported_rules_fail(self):
        for text in ('@@||example.com^', '||example.com^$third-party', '*.example.com', 'bad..example', '1.2.3.4'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.parse(text)

    def test_binary_offsets_crc_and_dedup(self):
        domains = self.parse('b.example\na.example\nb.example\n')
        blob = builder.compile_domains(domains)
        magic, version, count, size, crc = struct.unpack('<4sIIII', blob[:20])
        self.assertEqual((magic, version, count, size), (b'YDNS', 1, 2, 18))
        self.assertEqual(crc, zlib.crc32(blob[20:]))
        self.assertEqual(struct.unpack('<3I', blob[20:32]), (0, 9, 18))
        self.assertEqual(blob[32:], b'a.exampleb.example')

    def test_empty_and_long_labels(self):
        self.assertEqual(len(builder.compile_domains(set())), 24)
        with self.assertRaises(ValueError):
            builder.normalize('a' * 64 + '.example')

    def test_standard_hosts_local_headers(self):
        self.assertEqual(self.parse('fe80::1%lo0 localhost\nff02::1 ip6-allnodes\n0.0.0.0 0.0.0.0\n127.0.0.1 local\n0.0.0.0 ads.example\n'), {'ads.example'})


if __name__ == '__main__':
    unittest.main()
