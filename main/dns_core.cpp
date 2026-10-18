#include "dns_core.hpp"
#include <algorithm>
#include <cstring>

namespace yetdns {
uint16_t read16(const uint8_t *p) { return (uint16_t(p[0]) << 8) | p[1]; }
uint32_t read32(const uint8_t *p) { return (uint32_t(read16(p)) << 16) | read16(p + 2); }
void write16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v; }
void write32(uint8_t *p, uint32_t v) { write16(p, v >> 16); write16(p + 2, v); }
static uint32_t le32(const uint8_t *p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
static bool name_at(const uint8_t *p, size_t n, size_t &pos, char *out = nullptr) {
    size_t cursor = pos, end = 0, used = 0;
    for (unsigned jumps = 0; jumps < 128; ++jumps) {
        if (cursor >= n) return false;
        uint8_t len = p[cursor++];
        if ((len & 0xc0) == 0xc0) {
            if (cursor >= n) return false;
            size_t target = ((len & 63) << 8) | p[cursor++];
            if (target >= cursor - 2) return false; // only backwards compression
            if (!end) end = cursor;
            cursor = target;
            continue;
        }
        if (len & 0xc0) return false;
        if (!len) {
            if (out) out[used] = 0;
            pos = end ? end : cursor;
            return true;
        }
        if (cursor + len > n || used + len + (used ? 1 : 0) > 253) return false;
        if (used) { if (out) out[used] = '.'; ++used; }
        for (size_t i = 0; i < len; ++i) {
            uint8_t c = p[cursor++];
            if (out) {
                // Hostname labels only; binary DNS names are outside this forwarder's scope.
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
                out[used] = c >= 'A' && c <= 'Z' ? c + 32 : c;
            }
            ++used;
        }
    }
    return false;
}
bool domain_valid(const char *s) {
    size_t total = std::strlen(s), label = 0;
    if (!total || total > 253) return false;
    for (size_t i = 0; i < total; ++i) {
        unsigned char c = s[i];
        if (c == '.') { if (!label || label > 63) return false; label = 0; }
        else { if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return false; ++label; }
    }
    return label && label <= 63;
}
bool suffix_match(const char *name, const char *rule) {
    size_t a = std::strlen(name), b = std::strlen(rule);
    return a >= b && !std::strcmp(name + a - b, rule) && (a == b || name[a - b - 1] == '.');
}
bool evaluate_rules(const Rules &rules, const char *name, uint32_t client, Action &action, uint8_t *address) {
    bool found = false; size_t best = 0; bool best_client = false;
    for (size_t i = 0; i < rules.count && i < rule_max; ++i) {
        const auto &r = rules.items[i];
        if (r.client && r.client != client) continue;
        size_t len = std::strlen(r.domain);
        if (suffix_match(name, r.domain) && (!found || (r.client && !best_client) ||
            ((bool(r.client) == best_client) && len > best))) {
            found = true; best = len; best_client = r.client != 0;
            action = r.action; std::memcpy(address, r.address, 4);
        }
    }
    return found;
}
bool parse_query(const uint8_t *p, size_t n, Question &q) {
    q = {};
    q.udp_size = 512;
    if (n < 17 || n > packet_max || (read16(p + 2) & 0xfecf) || read16(p + 4) != 1 ||
        read16(p + 6) || read16(p + 8) || read16(p + 10) > 1) return false;
    // Questions are uncompressed so local replies can safely copy their wire form.
    size_t off = 12;
    while (off < n && p[off]) {
        uint8_t len = p[off];
        if (len > 63 || off + 1 + len >= n) return false;
        off += 1 + len;
    }
    size_t pos = 12;
    if (!name_at(p, n, pos, q.name) || pos + 4 > n) return false;
    q.type = read16(p + pos); q.klass = read16(p + pos + 2); q.end = pos + 4;
    if (q.klass != 1) return false;
    pos += 4;
    q.cacheable = n <= cache_key_max;
    if (read16(p + 10)) {
        // One EDNS0 OPT; options pass upstream but are not cached (cookies/ECS).
        if (pos + 11 > n || p[pos] != 0 || read16(p + pos + 1) != 41 || p[pos + 6] != 0 ||
            p[pos + 5] != 0 || (read16(p + pos + 7) & ~0x8000)) return false;
        q.udp_size = std::min<uint16_t>(cache_packet_max, std::max<uint16_t>(512, read16(p + pos + 3)));
        uint16_t len = read16(p + pos + 9);
        q.cacheable = q.cacheable && len == 0;
        pos += 11 + len;
    }
    return pos == n;
}
bool matching_response(const uint8_t *p, size_t n, const uint8_t *query, size_t qn) {
    Question q;
    if (!parse_query(query, qn, q) || n < 12 || n > packet_max || read16(p) != read16(query) ||
        !(p[2] & 0x80) || (p[2] & 0x78) || read16(p + 4) != 1) return false;
    size_t pos = 12; char name[254];
    return name_at(p, n, pos, name) && pos + 4 <= n && !std::strcmp(name, q.name) &&
        read16(p + pos) == q.type && read16(p + pos + 2) == q.klass;
}
size_t reply(const uint8_t *query, size_t n, uint8_t *out, uint8_t rcode,
             const uint8_t *ipv4, bool sinkhole, bool truncated) {
    if (n < 12) return 0;
    Question q;
    bool valid = parse_query(query, n, q);
    size_t end = valid ? q.end : 12;
    std::memmove(out, query, end);
    uint16_t flags = 0x8080 | (read16(query + 2) & 0x0110) | (rcode & 15);
    if (truncated) flags |= 0x0200;
    write16(out + 2, flags); write16(out + 4, valid ? 1 : 0);
    write16(out + 6, 0); write16(out + 8, 0); write16(out + 10, 0);
    bool answer = valid && !rcode && !truncated && ((ipv4 && q.type == 1) || (sinkhole && (q.type == 1 || q.type == 28)));
    if (answer) {
        write16(out + 6, 1);
        write16(out + end, 0xc00c); write16(out + end + 2, q.type);
        write16(out + end + 4, 1); write32(out + end + 6, 60);
        uint16_t len = q.type == 1 ? 4 : 16;
        write16(out + end + 10, len);
        std::memset(out + end + 12, 0, len);
        if (ipv4 && q.type == 1) std::memcpy(out + end + 12, ipv4, 4);
        end += 12 + len;
    }
    return end;
}
static bool walk_ttls(uint8_t *p, const uint8_t *cp, size_t n, uint32_t age, uint32_t &minimum) {
    if (n < 12 || read16(cp + 4) != 1) return false;
    size_t pos = 12;
    if (!name_at(cp, n, pos) || pos + 4 > n) return false;
    pos += 4;
    uint32_t records = uint32_t(read16(cp + 6)) + read16(cp + 8) + read16(cp + 10);
    if (records > 256) return false;
    for (uint32_t i = 0; i < records; ++i) {
        if (!name_at(cp, n, pos) || pos + 10 > n) return false;
        uint16_t type = read16(cp + pos), len = read16(cp + pos + 8);
        if (type == 250 || type == 24) return false; // authenticated messages cannot be aged
        if (type != 41) {
            uint32_t ttl = read32(cp + pos + 4);
            minimum = std::min(minimum, ttl);
            if (p) write32(p + pos + 4, ttl > age ? ttl - age : 0);
        }
        pos += 10 + len;
        if (pos > n) return false;
    }
    return pos == n;
}
bool cache_ttl(const uint8_t *p, size_t n, uint32_t &ttl) {
    ttl = 3600;
    if (n < 12 || (read16(p + 2) & 0x020f) || !read16(p + 6)) return false;
    return walk_ttls(nullptr, p, n, 0, ttl) && ttl;
}
bool age_ttls(uint8_t *p, size_t n, uint32_t age) {
    uint32_t unused = UINT32_MAX;
    return walk_ttls(p, p, n, age, unused);
}
bool inspect_aliases(const uint8_t *p, size_t n, bool (*denied)(const char *, void *), void *context, bool &blocked) {
    blocked = false;
    if (n < 12 || read16(p + 4) != 1) return false;
    size_t pos = 12;
    if (!name_at(p, n, pos) || pos + 4 > n) return false;
    pos += 4;
    uint32_t count = uint32_t(read16(p + 6)) + read16(p + 8) + read16(p + 10);
    if (count > 256) return false;
    for (uint32_t i = 0; i < count; ++i) {
        if (!name_at(p, n, pos) || pos + 10 > n) return false;
        uint16_t type = read16(p + pos), len = read16(p + pos + 8);
        pos += 10;
        if (pos + len > n) return false;
        if (type == 5 || type == 39) {
            size_t target_pos = pos; char name[254];
            if (!name_at(p, n, target_pos, name) || target_pos != pos + len) return false;
            if (denied(name, context)) blocked = true;
        }
        pos += len;
    }
    return pos == n;
}
bool Blocklist::load(const uint8_t *data, size_t size) {
    count_ = 0; offsets_ = pool_ = nullptr;
    if (size < 24 || std::memcmp(data, "YDNS", 4) || le32(data + 4) != 1) return false;
    uint32_t count = le32(data + 8), pool = le32(data + 12);
    if (count > (size - 24) / 4 || size != 20ull + (uint64_t(count) + 1) * 4 + pool) return false;
    uint32_t crc = ~0u;
    for (size_t i = 20; i < size; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1)));
    }
    if (~crc != le32(data + 16)) return false;
    const uint8_t *offsets = data + 20;
    if (le32(offsets) || le32(offsets + count * 4) != pool) return false;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t a = le32(offsets + i * 4), b = le32(offsets + (i + 1) * 4);
        if (b <= a || b - a > 253 || b > pool) return false;
    }
    count_ = count; offsets_ = offsets; pool_ = offsets + (size_t(count) + 1) * 4;
    // Buckets use the first byte; the source compiler guarantees lexical ordering.
    uint32_t cursor = 0;
    for (unsigned c = 0; c <= 256; ++c) {
        while (cursor < count_ && pool_[le32(offsets_ + cursor * 4)] < c) ++cursor;
        prefix_[c] = cursor;
    }
    return true;
}
bool Blocklist::contains(const char *domain) const {
    const char *suffix = domain;
    do {
        size_t len = std::strlen(suffix);
        unsigned first = static_cast<unsigned char>(suffix[0]);
        uint32_t lo = count_ ? prefix_[first] : 0, hi = count_ ? prefix_[first + 1] : 0;
        while (lo < hi) {
            uint32_t mid = lo + (hi - lo) / 2;
            uint32_t a = le32(offsets_ + mid * 4), b = le32(offsets_ + (mid + 1) * 4);
            int cmp = std::memcmp(suffix, pool_ + a, std::min<size_t>(len, b - a));
            if (!cmp) cmp = len < b - a ? -1 : len > b - a ? 1 : 0;
            if (!cmp) return true;
            if (cmp < 0) hi = mid; else lo = mid + 1;
        }
        const char *dot = std::strchr(suffix, '.');
        suffix = dot ? dot + 1 : nullptr;
    } while (suffix);
    return false;
}
size_t Cache::get(const uint8_t *query, size_t n, uint8_t *out, uint32_t now) {
    Question q;
    if (!parse_query(query, n, q) || !q.cacheable) return 0;
    for (size_t i = 0; i < count_; ++i) {
        auto &e = entries_[i];
        uint32_t age = now - e.inserted;
        if (!e.response_n || age >= e.lifetime || e.query_n != n || std::memcmp(e.key + 2, query + 2, n - 2)) continue;
        std::memcpy(out, e.response, e.response_n);
        std::memcpy(out, query, 2);
        return age_ttls(out, e.response_n, age) ? e.response_n : 0;
    }
    return 0;
}
void Cache::put(const uint8_t *query, size_t n, const uint8_t *response, size_t rn, uint32_t now) {
    Question q; uint32_t ttl;
    if (rn > cache_packet_max || !parse_query(query, n, q) || !q.cacheable ||
        !matching_response(response, rn, query, n) || !cache_ttl(response, rn, ttl) || !count_) return;
    auto &e = entries_[next_++ % count_];
    e.inserted = now; e.lifetime = ttl; e.query_n = n; e.response_n = rn;
    std::memcpy(e.key, query, n); std::memcpy(e.response, response, rn);
}
void Cache::clear() { for (size_t i = 0; i < count_; ++i) entries_[i].response_n = 0; }
} // namespace yetdns
