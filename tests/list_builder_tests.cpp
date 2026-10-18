#include "list_builder.hpp"
#include "dns_core.hpp"
#include <cassert>
#include <cstring>
#include <fstream>
#include <iterator>
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
    const std::string text = "\xef\xbb\xbf# comment\r\n0.0.0.0 DOUBLECLICK.NET. googlesyndication.com\n||googleadservices.com^\n127.0.0.1 localhost ads.example\nfe80::1%lo0 localhost\nff02::1 ip6-allnodes\n0.0.0.0 0.0.0.0\n127.0.0.1 local\nads.example";
    for (uint8_t c : text) assert(builder.feed(&c, 1));
    assert(builder.finish_source() && builder.count() == 4);
    std::vector<uint8_t> bytes; assert(builder.write(writer, &bytes));
    Blocklist list; assert(list.load(bytes.data(), bytes.size()) && list.contains("a.ads.example"));
    std::ifstream file(argv[1], std::ios::binary);
    std::vector<uint8_t> expected((std::istreambuf_iterator<char>(file)), {});
    assert(bytes == expected); // independent Python compiler must produce identical wire image
    for (const char *invalid : {"@@||safe.example^", "||ads.example^$third-party", "<html>error</html>", "1.2.3.4", "bad..example"}) {
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
    puts("Streaming lists: formats, exact deduplication, capacity failures, 20000-domain index and Python compatibility passed");
}
