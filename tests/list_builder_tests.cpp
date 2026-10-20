#include "list_builder.hpp"
#include "dns_core.hpp"
#include <cassert>
#include <cstring>
#include <fstream>
#include <iterator>
#include <random>
#include <set>
#include <string>
#include <vector>
using namespace yetdns;
static bool writer(size_t offset, const uint8_t *p, size_t n, void *ctx) {
    auto &out = *static_cast<std::vector<uint8_t> *>(ctx);
    if (out.size() < offset + n) out.resize(offset + n);
    std::memcpy(out.data() + offset, p, n); return true;
}
int main(int argc, char **argv) {
    assert(argc == 2);
    assert(list_update_delay(100, 100, 24, true) == 86400);
    assert(list_update_delay(100, 86500, 24, true) == 0);
    assert(list_update_delay(100, 200, 24, false) == 0);
    assert(list_update_delay(0, 200, 24, true) == 0);
    assert(list_update_delay(10000, 100, 1, true) == 3600);
    char pool[4096]; uint32_t table[128]; ListBuilder builder(pool, sizeof(pool), table, 128);
    const std::string text = "\xef\xbb\xbf! Title: test\r\n# comment\r\n0.0.0.0 DOUBLECLICK.NET. googlesyndication.com\n||googleadservices.com^\n127.0.0.1 localhost ads.example\nfe80::1%lo0 localhost\nff02::1 ip6-allnodes\n0.0.0.0 0.0.0.0\n127.0.0.1 local\nads.example";
    for (uint8_t c : text) assert(builder.feed(&c, 1));
    assert(builder.finish_source() && builder.count() == 4);
    std::vector<uint8_t> bytes; assert(builder.write(writer, &bytes));
    Blocklist list; assert(list.load(bytes.data(), bytes.size()) && list.contains("a.ads.example"));
    std::ifstream file(argv[1], std::ios::binary);
    std::vector<uint8_t> expected((std::istreambuf_iterator<char>(file)), {});
    assert(bytes == expected); // independent Python compiler must produce identical wire image
    for (const char *invalid : {"@@||safe.example^", "||ads.example^$third-party", "<html>error</html>", "[not a header|^]", "1.2.3.4", "bad..example"}) {
        ListBuilder bad(pool, sizeof(pool), table, 128);
        bool valid = bad.feed(reinterpret_cast<const uint8_t *>(invalid), std::strlen(invalid)) && bad.finish_source();
        assert(!valid && bad.error()[0]);
    }
    ListBuilder huge(pool, sizeof(pool), table, 128);
    std::string line(1100, 'a'); assert(!huge.feed(reinterpret_cast<const uint8_t *>(line.data()), line.size()));
    char tiny_pool[16]; uint32_t tiny_table[4]; ListBuilder small(tiny_pool, 16, tiny_table, 4);
    const char *two = "first.example\nsecond.example\n";
    assert(!small.feed(reinterpret_cast<const uint8_t *>(two), std::strlen(two)));
    std::vector<char> large_pool(1024 * 1024); std::vector<uint32_t> large_table(65536);
    ListBuilder large(large_pool.data(), large_pool.size(), large_table.data(), large_table.size());
    for (int i = 0; i < 20000; ++i) {
        std::string domain = "d" + std::to_string(i) + ".test\n";
        assert(large.feed(reinterpret_cast<const uint8_t *>(domain.data()), domain.size()));
        assert(large.feed(reinterpret_cast<const uint8_t *>(domain.data()), domain.size()));
    }
    assert(large.count() == 20000); bytes.clear(); assert(large.write(writer, &bytes));
    assert(list.load(bytes.data(), bytes.size()) && list.count() == 20000);
    assert(list.contains("d19999.test") && list.contains("a.d0.test") && !list.contains("d20000.test"));
    // Adblock Plus lists: DNS-expressible rules are kept, everything else is skipped, parents absorb subdomains.
    {
        const std::string abp = "[Adblock Plus 1.1]\r\n! Title: test\r\n||tracker.example^\r\n||third.example^$third-party\r\n"
            "||Cap.Example^$3p\r\n||img.example^$image\r\n@@||tracker.example^$xmlhttprequest\r\n||path.example/ads^\r\n"
            "news.example##.banner\r\n##.ad\r\n/banner[0-9]+/\r\n||wild.*.example^\r\n||sub.tracker.example^\r\n&param=1\r\n" +
            std::string(3000, 'x') + "\r\n||last.example^";
        ListBuilder b(pool, sizeof(pool), table, 128);
        assert(b.feed(reinterpret_cast<const uint8_t *>(abp.data()), abp.size()) && b.finish_source());
        assert(b.image_size() && b.count() == 4);
        std::vector<uint8_t> image; assert(b.write(writer, &image));
        Blocklist l; assert(l.load(image.data(), image.size()));
        for (const char *blocked : {"tracker.example", "x.sub.tracker.example", "third.example", "cap.example", "last.example"}) assert(l.contains(blocked));
        for (const char *allowed : {"img.example", "path.example", "news.example", "example", "wild.example", "banner.example"}) assert(!l.contains(allowed));
        ListBuilder strict(pool, sizeof(pool), table, 128);
        const char *mixed = "[Adblock Plus]\n@@||skipped.example^\n", *plain = "@@||rejected.example^\n";
        assert(strict.feed(reinterpret_cast<const uint8_t *>(mixed), std::strlen(mixed)) && strict.finish_source());
        assert(!strict.feed(reinterpret_cast<const uint8_t *>(plain), std::strlen(plain))); // next source is strict again
        ListBuilder only_skipped(pool, sizeof(pool), table, 128);
        assert(only_skipped.feed(reinterpret_cast<const uint8_t *>(mixed), std::strlen(mixed)) && only_skipped.finish_source() && only_skipped.accepted() == 0);
    }
    // Reversed front-coded index versus a naive suffix match, with many parent/child pairs.
    {
        std::mt19937 rng(7); const char *labels[] = {"a", "b", "c", "ab", "ba", "x-y", "z1"};
        auto name = [&](unsigned most) {
            std::string value;
            for (unsigned i = 0, n = 1 + rng() % most; i < n; ++i) value += (i ? "." : "") + std::string(labels[rng() % 7]);
            return value;
        };
        std::set<std::string> listed; std::string text;
        for (int i = 0; i < 3000; ++i) { std::string value = name(4); listed.insert(value); text += value + "\n"; }
        auto naive = [&](const std::string &query) {
            for (size_t i = 0; i <= query.size(); ++i) if ((!i || query[i - 1] == '.') && i < query.size() && listed.count(query.substr(i))) return true;
            return false;
        };
        std::set<std::string> kept;
        for (const auto &value : listed) { std::string rest = value; bool covered = false; for (size_t dot = rest.find('.'); dot != std::string::npos; dot = rest.find('.', dot + 1)) covered |= listed.count(rest.substr(dot + 1)) != 0; if (!covered) kept.insert(value); }
        ListBuilder b(large_pool.data(), large_pool.size(), large_table.data(), large_table.size());
        assert(b.feed(reinterpret_cast<const uint8_t *>(text.data()), text.size()) && b.finish_source() && b.image_size());
        assert(b.count() == kept.size());
        bytes.clear(); assert(b.write(writer, &bytes));
        Blocklist l; assert(l.load(bytes.data(), bytes.size()) && l.count() == kept.size());
        for (int i = 0; i < 20000; ++i) { std::string query = name(5); assert(l.contains(query.c_str()) == naive(query)); }
        for (const auto &value : listed) assert(l.contains(value.c_str()));
        bytes[bytes.size() / 2] ^= 0x10; assert(!l.load(bytes.data(), bytes.size())); // CRC protects the front-coded body
        bytes[bytes.size() / 2] ^= 0x10; assert(l.load(bytes.data(), bytes.size()));
        // Corrupt the structure and repair the CRC: the loader must reject it or stay inside the image (ASan/UBSan).
        unsigned accepted_images = 0;
        for (int i = 0; i < 4000; ++i) {
            auto copy = bytes;
            for (unsigned j = 0, changes = 1 + rng() % 3; j < changes; ++j) copy[8 + rng() % (copy.size() - 8)] = rng();
            uint32_t crc = list_crc32(0, copy.data() + 20, copy.size() - 20);
            for (int k = 0; k < 4; ++k) copy[16 + k] = crc >> (8 * k);
            Blocklist fuzzed;
            if (!fuzzed.load(copy.data(), copy.size())) continue;
            ++accepted_images;
            for (int k = 0; k < 50; ++k) { std::string query = name(5); fuzzed.contains(query.c_str()); }
        }
        assert(accepted_images > 0 && accepted_images < 4000);
    }
    puts("Streaming lists: formats, exact deduplication, capacity failures, 20000-domain index and Python compatibility passed");
}
