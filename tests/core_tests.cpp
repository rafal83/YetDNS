#include "dns_core.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <random>
#include <vector>
using namespace yetdns;

static std::vector<uint8_t> query(const char *name, uint16_t type = 1, bool edns = false) {
    std::vector<uint8_t> p(12);
    write16(p.data(), 0x1234); write16(p.data() + 2, 0x0100); write16(p.data() + 4, 1);
    const char *s = name;
    while (*s) {
        const char *dot = std::strchr(s, '.'); size_t len = dot ? size_t(dot - s) : std::strlen(s);
        p.push_back(len); p.insert(p.end(), s, s + len); s += len; if (*s == '.') ++s;
    }
    p.insert(p.end(), {0, uint8_t(type >> 8), uint8_t(type), 0, 1});
    if (edns) { p[11] = 1; p.insert(p.end(), {0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 0}); }
    return p;
}
int main(int argc, char **argv) {
    assert(argc == 2);
    uint8_t response[packet_max]{}, cached[packet_max]{}; Question q;
    auto a = query("Ads.Example", 1, true);
    assert(parse_query(a.data(), a.size(), q));
    assert(!std::strcmp(q.name, "ads.example") && q.type == 1 && q.udp_size == 1232 && q.cacheable);
    size_t n = reply(a.data(), a.size(), response, 0, nullptr, true);
    assert(read16(response + 6) == 1 && read16(response + 10) == 0);
    assert(n == size_t(q.end) + 16 && matching_response(response, n, a.data(), a.size()));
    assert(!(read16(response + 2) & 0x0020)); // local answers never claim DNSSEC authentication
    uint32_t ttl;
    assert(cache_ttl(response, n, ttl) && ttl == 60);
    CacheEntry entries[2]{}; Cache cache(entries, 2);
    cache.put(a.data(), a.size(), response, n, 100);
    a[0] = 0x99;
    assert(cache.get(a.data(), a.size(), cached, 110) == n);
    assert(cached[0] == 0x99 && read32(cached + q.end + 6) == 50);
    assert(!cache.get(a.data(), a.size(), cached, 160));
    auto cd = a; cd[3] |= 0x10;
    assert(!cache.get(cd.data(), cd.size(), cached, 111));
    auto no_do = a; no_do[no_do.size() - 4] = 0;
    assert(!cache.get(no_do.data(), no_do.size(), cached, 111));
    cache.clear(); assert(!cache.get(a.data(), a.size(), cached, 111));
    auto aaaa = query("ads.example", 28);
    assert(parse_query(aaaa.data(), aaaa.size(), q));
    n = reply(aaaa.data(), aaaa.size(), response, 0, nullptr, true);
    assert(n == size_t(q.end) + 28 && read16(response + q.end + 10) == 16);
    auto mx = query("ads.example", 15);
    n = reply(mx.data(), mx.size(), response, 0, nullptr, true);
    assert(!read16(response + 6));
    n = reply(a.data(), a.size(), response, 0, nullptr, false, true);
    assert(response[2] & 2); assert(!cache_ttl(response, n, ttl));
    auto malformed = a; malformed[12] = 0xc0;
    assert(!parse_query(malformed.data(), malformed.size(), q));
    n = reply(malformed.data(), malformed.size(), response, 1);
    assert(n == 12 && !read16(response + 4) && (response[3] & 15) == 1);
    malformed = a; malformed[5] = 2; assert(!parse_query(malformed.data(), malformed.size(), q));
    malformed = a; malformed.pop_back(); assert(!parse_query(malformed.data(), malformed.size(), q));
    auto opt = a; opt.back() = 4; opt.insert(opt.end(), {0, 10, 0, 0});
    assert(parse_query(opt.data(), opt.size(), q) && !q.cacheable);
    n = reply(a.data(), a.size(), response, 0, nullptr, true);
    response[0] ^= 1; assert(!matching_response(response, n, a.data(), a.size())); response[0] ^= 1;
    response[13] = 'x'; assert(!matching_response(response, n, a.data(), a.size()));
    n = reply(a.data(), a.size(), response, 0, nullptr, true);
    assert(parse_query(a.data(), a.size(), q));
    response[q.end] = 0xc0; response[q.end + 1] = uint8_t(q.end); // self-pointer
    assert(!cache_ttl(response, n, ttl));
    n = reply(a.data(), a.size(), response, 0, nullptr, true);
    write32(response + q.end + 6, 0); assert(!cache_ttl(response, n, ttl));
    n = reply(a.data(), a.size(), response, 3); assert(!cache_ttl(response, n, ttl));
    // CNAME target in RDATA, with compression allowed. A blocked target triggers filtering.
    auto alias = query("www.example");
    n = reply(alias.data(), alias.size(), response, 0, nullptr, true);
    assert(parse_query(alias.data(), alias.size(), q));
    write16(response + q.end + 2, 5); // CNAME rather than A
    auto target = query("ads.example");
    size_t target_len = target.size() - 12 - 4;
    write16(response + q.end + 10, target_len);
    std::memcpy(response + q.end + 12, target.data() + 12, target_len);
    n = q.end + 12 + target_len;
    bool blocked = false;
    auto denied = [](const char *name, void *) { return !std::strcmp(name, "ads.example"); };
    assert(inspect_aliases(response, n, denied, nullptr, blocked) && blocked);
    response[q.end + 12] = 0xc0; response[q.end + 13] = 0x0c;
    write16(response + q.end + 10, 2); n = q.end + 14;
    assert(inspect_aliases(response, n, denied, nullptr, blocked) && !blocked);
    write16(response + q.end + 10, 1);
    assert(!inspect_aliases(response, n, denied, nullptr, blocked));
    assert(suffix_match("a.ads.example", "ads.example"));
    assert(!suffix_match("badads.example", "ads.example"));
    assert(!domain_valid("bad..example") && !domain_valid("Bad.example") && domain_valid("_dns.example"));
    Rules rules{}; rules.count = 3;
    std::strcpy(rules.items[0].domain, "example"); rules.items[0].action = Action::deny;
    std::strcpy(rules.items[1].domain, "safe.example"); rules.items[1].action = Action::allow;
    std::strcpy(rules.items[2].domain, "example"); rules.items[2].client = 42; rules.items[2].action = Action::rewrite;
    rules.items[2].address[0] = 10;
    Action action{}; uint8_t address[4]{};
    assert(evaluate_rules(rules, "ads.example", 1, action, address) && action == Action::deny);
    assert(evaluate_rules(rules, "a.safe.example", 1, action, address) && action == Action::allow);
    assert(evaluate_rules(rules, "a.safe.example", 42, action, address) && action == Action::rewrite && address[0] == 10);
    assert(!evaluate_rules(rules, "other.test", 42, action, address));
    std::ifstream file(argv[1], std::ios::binary);
    std::vector<uint8_t> blob((std::istreambuf_iterator<char>(file)), {});
    Blocklist list; assert(list.load(blob.data(), blob.size())); assert(list.count() == 4);
    assert(list.contains("doubleclick.net") && list.contains("x.ads.example"));
    assert(!list.contains("example") && !list.contains("notads.example") && !list.contains("example.net"));
    blob.back() ^= 1; assert(!list.load(blob.data(), blob.size()));
    // Deterministic malformed-wire corpus, executed under ASan/UBSan in CI.
    std::mt19937 random(42);
    for (unsigned i = 0; i < 100000; ++i) {
        size_t len = random() % 512;
        std::vector<uint8_t> bytes(len);
        for (auto &v : bytes) v = random();
        parse_query(bytes.data(), bytes.size(), q);
        cache_ttl(bytes.data(), bytes.size(), ttl);
        matching_response(bytes.data(), bytes.size(), a.data(), a.size());
        inspect_aliases(bytes.data(), bytes.size(), denied, nullptr, blocked);
        reply(bytes.data(), bytes.size(), response, 1);
        list.load(bytes.data(), bytes.size());
    }
    n = reply(a.data(), a.size(), response, 0, nullptr, true);
    std::vector<uint8_t> valid_response(response, response + n);
    for (unsigned i = 0; i < 20000; ++i) {
        auto bytes = i % 2 ? a : valid_response;
        for (unsigned j = 0, changes = 1 + random() % 4; j < changes; ++j) bytes[random() % bytes.size()] = random();
        if (i % 3 == 0) bytes.resize(random() % 512);
        parse_query(bytes.data(), bytes.size(), q);
        cache_ttl(bytes.data(), bytes.size(), ttl);
        inspect_aliases(bytes.data(), bytes.size(), denied, nullptr, blocked);
        matching_response(bytes.data(), bytes.size(), a.data(), a.size());
        reply(bytes.data(), bytes.size(), response, 1);
    }
    std::puts("DNS core: parser, EDNS, aliases, client rules, TTL cache, exact index, 100000 random packets and 20000 structured mutations passed");
}
