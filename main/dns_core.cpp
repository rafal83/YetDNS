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
// A SOA also bounds the lifetime with its MINIMUM field (RFC 2308 negative TTL); `soa` reports that one was seen.
static bool walk_ttls(uint8_t *p, const uint8_t *cp, size_t n, uint32_t age, uint32_t &minimum, bool *soa = nullptr) {
    if (n < 12 || read16(cp + 4) != 1) return false;
    size_t pos = 12;
    if (!name_at(cp, n, pos) || pos + 4 > n) return false;
    pos += 4;
    uint32_t records = uint32_t(read16(cp + 6)) + read16(cp + 8) + read16(cp + 10);
    if (records > 256) return false;
    for (uint32_t i = 0; i < records; ++i) {
        if (!name_at(cp, n, pos) || pos + 10 > n) return false;
        uint16_t type = read16(cp + pos), len = read16(cp + pos + 8);
        if (pos + 10 + len > n) return false;
        if (type == 250 || type == 24) return false; // authenticated messages cannot be aged
        if (type != 41) {
            uint32_t ttl = read32(cp + pos + 4);
            minimum = std::min(minimum, ttl);
            if (p) write32(p + pos + 4, ttl > age ? ttl - age : 0);
        }
        if (type == 6) {
            size_t cursor = pos + 10;
            if (!name_at(cp, n, cursor) || !name_at(cp, n, cursor) || cursor + 20 != pos + 10 + len) return false;
            minimum = std::min(minimum, read32(cp + cursor + 16));
            if (soa) *soa = true;
        }
        pos += 10 + len;
    }
    return pos == n;
}
constexpr uint32_t positive_ttl_max = 3600, negative_ttl_max = 300;
// Positive answers and negative ones (NODATA, NXDOMAIN) are cacheable; a negative answer needs a SOA to say for how long.
bool cache_ttl(const uint8_t *p, size_t n, uint32_t &ttl) {
    ttl = positive_ttl_max;
    if (n < 12 || (read16(p + 2) & 0x0200)) return false;
    uint8_t rcode = p[3] & 15;
    if (rcode != 0 && rcode != 3) return false;
    bool negative = rcode == 3 || !read16(p + 6), soa = false;
    if (negative) ttl = negative_ttl_max;
    return walk_ttls(nullptr, p, n, 0, ttl, &soa) && ttl && (!negative || soa);
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
    count_ = blocks_ = 0; index_ = data_ = nullptr;
    if (size < 24 || std::memcmp(data, "YDNS", 4) || le32(data + 4) != 2) return false;
    uint32_t count = le32(data + 8), pool = le32(data + 12);
    uint64_t blocks = (uint64_t(count) + list_block_entries - 1) / list_block_entries;
    if (size != 20ull + (blocks + 1) * 4 + pool) return false;
    uint32_t crc = ~0u;
    for (size_t i = 20; i < size; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1)));
    }
    if (~crc != le32(data + 16)) return false;
    const uint8_t *index = data + 20, *body = index + (blocks + 1) * 4;
    if (le32(index) || le32(index + blocks * 4) != pool) return false;
    // Walk every entry so that lookups never read outside the image.
    uint32_t position = 0;
    for (uint64_t block = 0; block < blocks; ++block) {
        if (le32(index + block * 4) != position) return false;
        uint32_t entries = std::min<uint64_t>(list_block_entries, count - block * list_block_entries), previous = 0;
        for (uint32_t k = 0; k < entries; ++k) {
            if (position + 2 > pool) return false;
            uint32_t shared = body[position], suffix = body[position + 1];
            if (shared > previous || (!k && shared) || !suffix || shared + suffix > 253 || position + 2 + suffix > pool) return false;
            position += 2 + suffix; previous = shared + suffix;
        }
    }
    if (position != pool) return false;
    count_ = count; blocks_ = uint32_t(blocks); index_ = index; data_ = body;
    return true;
}
static int compare_keys(const uint8_t *a, size_t a_len, const char *b, size_t b_len) {
    int cmp = std::memcmp(a, b, std::min(a_len, b_len));
    return cmp ? cmp : a_len < b_len ? -1 : a_len > b_len ? 1 : 0;
}
// Exact lookup of a reversed name: binary search on block heads, then a short sequential decode.
bool Blocklist::find(const char *key, size_t length) const {
    uint32_t lo = 0, hi = blocks_;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        const uint8_t *head = data_ + le32(index_ + mid * 4);
        if (compare_keys(head + 2, head[1], key, length) <= 0) lo = mid + 1; else hi = mid;
    }
    if (!lo) return false;
    uint32_t block = lo - 1, entries = std::min<uint32_t>(list_block_entries, count_ - block * list_block_entries);
    const uint8_t *p = data_ + le32(index_ + block * 4);
    uint8_t entry[256];
    for (uint32_t k = 0; k < entries; ++k) {
        size_t shared = p[0], suffix = p[1]; p += 2;
        std::memcpy(entry + shared, p, suffix); p += suffix;
        int cmp = compare_keys(entry, shared + suffix, key, length);
        if (!cmp) return true;
        if (cmp > 0) return false;
    }
    return false;
}
bool Blocklist::contains(const char *domain) const {
    size_t length = std::strlen(domain);
    if (!blocks_ || !length || length > 253) return false;
    char reversed[256];
    for (size_t i = 0; i < length; ++i) reversed[i] = domain[length - 1 - i];
    // A name is blocked when it, or any parent domain, is listed: exact lookup of each label-boundary prefix.
    for (size_t end = 1; end <= length; ++end)
        if ((end == length || reversed[end] == '.') && find(reversed, end)) return true;
    return false;
}
// FNV-1a over the key without the transaction ID, never 0 (0 marks an empty slot).
static uint32_t key_hash(const uint8_t *query, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 2; i < n; ++i) h = (h ^ query[i]) * 16777619u;
    return h ? h : 1;
}
size_t Cache::get(const uint8_t *query, size_t n, uint8_t *out, uint32_t now) {
    Question q;
    if (!parse_query(query, n, q) || !q.cacheable) return 0;
    uint32_t hash = hashes_ ? key_hash(query, n) : 0;
    for (size_t i = 0; i < count_; ++i) {
        if (hashes_ && hashes_[i] != hash) continue;
        auto &e = entries_[i];
        uint32_t age = now - e.inserted;
        if (!e.response_n || age >= e.lifetime || e.query_n != n || std::memcmp(e.key + 2, query + 2, n - 2)) continue;
        std::memcpy(out, e.response, e.response_n);
        std::memcpy(out, query, 2);
        return age_ttls(out, e.response_n, age) ? e.response_n : 0;
    }
    return 0;
}
bool Cache::put(const uint8_t *query, size_t n, const uint8_t *response, size_t rn, uint32_t now) {
    Question q; uint32_t ttl;
    if (rn > cache_packet_max || !parse_query(query, n, q) || !q.cacheable ||
        !matching_response(response, rn, query, n) || !cache_ttl(response, rn, ttl) || !count_) return false;
    uint32_t hash = hashes_ ? key_hash(query, n) : 0;
    // Refresh the entry holding the same question (concurrent misses), else take a free slot, else evict the oldest.
    size_t slot = count_, free_slot = count_;
    for (size_t i = 0; i < count_; ++i) {
        if (hashes_ && hashes_[i] != hash) { if (!hashes_[i] && free_slot == count_) free_slot = i; continue; }
        auto &old = entries_[i];
        if (!old.response_n) { if (free_slot == count_) free_slot = i; continue; }
        if (old.query_n == n && !std::memcmp(old.key + 2, query + 2, n - 2)) { slot = i; break; }
    }
    if (slot == count_) slot = free_slot != count_ ? free_slot : next_++ % count_;
    auto &e = entries_[slot];
    e.inserted = now; e.lifetime = ttl; e.query_n = n; e.response_n = rn;
    std::memcpy(e.key, query, n); std::memcpy(e.response, response, rn);
    if (hashes_) hashes_[slot] = hash;
    return true;
}
void Cache::clear() {
    for (size_t i = 0; i < count_; ++i) { entries_[i].response_n = 0; if (hashes_) hashes_[i] = 0; }
}
} // namespace yetdns
