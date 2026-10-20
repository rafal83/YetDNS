#include "list_builder.hpp"
#include "dns_core.hpp"
#include <algorithm>
#include <cstring>
#include <strings.h>

namespace yetdns {
// Table entries hold pool offset + 1; the top bit marks a subdomain dropped by prune().
constexpr uint32_t removed = 0x80000000u;
uint32_t list_update_delay(uint32_t last, uint32_t now, uint32_t hours, bool matches) {
    if (!matches || !last) return 0;
    uint64_t interval = uint64_t(hours) * 3600, due = uint64_t(last) + interval;
    return due <= now ? 0 : uint32_t(std::min<uint64_t>(due - now, interval));
}
uint32_t list_crc32(uint32_t crc, const uint8_t *data, size_t size) {
    crc = ~crc;
    while (size--) {
        crc ^= *data++;
        for (int i = 0; i < 8; ++i) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1)));
    }
    return ~crc;
}
static void le_write(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; ++i) p[i] = v >> (i * 8); }
ListBuilder::ListBuilder(char *pool, size_t cap, uint32_t *table, size_t slots, ListYield yield, void *context)
    : pool_(pool), pool_cap_(cap), table_(table), table_cap_(slots), yield_(yield), context_(context) {
    if (!pool || !table || !slots || cap > removed - 2) error_ = "Invalid builder storage";
    else std::memset(table, 0, slots * sizeof(uint32_t));
}
static uint32_t hash_step(uint32_t hash, char c) { return (hash ^ uint8_t(c)) * 16777619u; }
// Slot holding the reversed domain [reversed, reversed + length), or the empty slot where it belongs.
size_t ListBuilder::slot(uint32_t hash, const char *reversed, size_t length) const {
    hash ^= hash >> 15; hash *= 0x2c1b3c6du; hash ^= hash >> 12; // FNV state -> well mixed, then scaled to the table size
    size_t index = (uint64_t(hash) * table_cap_) >> 32;
    while (table_[index]) {
        const char *entry = pool_ + (table_[index] & ~removed) - 1;
        if (!std::strncmp(entry, reversed, length) && !entry[length]) break;
        if (++index == table_cap_) index = 0;
    }
    return index;
}
bool ListBuilder::add(char *domain, bool lenient) {
    size_t len = std::strlen(domain);
    if (len && domain[len - 1] == '.') domain[--len] = 0;
    for (size_t i = 0; i < len; ++i) if (domain[i] >= 'A' && domain[i] <= 'Z') domain[i] += 32;
    if (!std::strcmp(domain, "localhost") || !std::strcmp(domain, "local") || !std::strcmp(domain, "localhost.localdomain") ||
        !std::strcmp(domain, "broadcasthost") || !std::strncmp(domain, "ip6-", 4)) return true;
    if (!domain_valid(domain)) {
        if (lenient) return true;
        error_ = "Invalid domain or unsupported filter syntax"; return false;
    }
    bool numeric = true;
    for (size_t i = 0; i < len; ++i) if ((domain[i] < '0' || domain[i] > '9') && domain[i] != '.') numeric = false;
    if (numeric) {
        if (lenient) return true;
        error_ = "IP address is not a domain"; return false;
    }
    ++accepted_;
    std::reverse(domain, domain + len);
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; ++i) {
        // A listed parent domain already blocks this one.
        if (domain[i] == '.' && table_[slot(hash, domain, i)]) return true;
        hash = hash_step(hash, domain[i]);
    }
    size_t index = slot(hash, domain, len);
    if (table_[index]) return true;
    if (count_ >= table_cap_ * 3 / 4 || used_ + len + 1 > pool_cap_) {
        error_ = "List capacity exceeded; previous list retained"; return false;
    }
    std::memcpy(pool_ + used_, domain, len + 1);
    table_[index] = used_ + 1; used_ += len + 1; ++count_;
    return true;
}
// Only "||domain^" and "||domain^$third-party" translate to a DNS block. Exceptions, URL patterns, cosmetic
// filters and rules restricted by other options are skipped: they cannot be applied without seeing the URL.
bool ListBuilder::abp_rule(char *rule) {
    if (rule[0] != '|' || rule[1] != '|') return true;
    char *caret = std::strchr(rule + 2, '^');
    if (!caret) return true;
    const char *options = caret + 1;
    if (*options && std::strcmp(options, "$third-party") && std::strcmp(options, "$3p")) return true;
    *caret = 0;
    return add(rule + 2, true);
}
bool ListBuilder::line() {
    line_[line_n_] = 0;
    char *s = line_;
    if (line_n_ >= 3 && uint8_t(s[0]) == 0xef && uint8_t(s[1]) == 0xbb && uint8_t(s[2]) == 0xbf) s += 3;
    while (*s == ' ' || *s == '\t' || *s == '\r') ++s;
    if (!*s || *s == '#' || *s == '!') return true;
    if (*s == '[') { // Adblock Plus header such as "[Adblock Plus]"
        size_t header = std::strlen(s);
        while (header && (s[header - 1] == ' ' || s[header - 1] == '\t' || s[header - 1] == '\r')) --header;
        if (header > 2 && s[header - 1] == ']' && !std::strpbrk(s + 1, "[|^/$")) {
            abp_ = !strncasecmp(s, "[Adblock", 8);
            return true;
        }
    }
    if (abp_) { // Adblock Plus list: keep what DNS can express, skip every other rule
        size_t n = std::strlen(s);
        while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r')) s[--n] = 0;
        return abp_rule(s);
    }
    char *comment = std::strchr(s, '#'); if (comment) *comment = 0;
    size_t len = std::strlen(s);
    while (len && (s[len - 1] == ' ' || s[len - 1] == '\t' || s[len - 1] == '\r')) s[--len] = 0;
    if (!len) return true;
    if (len > 3 && s[0] == '|' && s[1] == '|' && s[len - 1] == '^') {
        s[len - 1] = 0; return add(s + 2);
    }
    char *end = s;
    while (*end && *end != ' ' && *end != '\t') ++end;
    bool hosts = false;
    if (*end) {
        *end++ = 0;
        hosts = !std::strcmp(s, "0.0.0.0") || !std::strcmp(s, "127.0.0.1") ||
                !std::strcmp(s, "::") || !std::strcmp(s, "::1") || !std::strcmp(s, "255.255.255.255");
        if (!hosts && std::strchr(s, ':')) {
            char *alias = end; while (*alias == ' ' || *alias == '\t') ++alias;
            if (!std::strcmp(alias, "localhost") || !std::strncmp(alias, "ip6-", 4)) return true;
        }
        if (!hosts) { error_ = "Unsupported line: use domains, hosts or ||domain^"; return false; }
        s = end;
    }
    if (!hosts) return add(s);
    while (*s) {
        while (*s == ' ' || *s == '\t') ++s;
        if (!*s) break;
        end = s; while (*end && *end != ' ' && *end != '\t') ++end;
        char separator = *end; *end = 0;
        if (std::strcmp(s, "0.0.0.0") && std::strcmp(s, "127.0.0.1") && !add(s)) return false;
        if (!separator) break;
        s = end + 1;
    }
    return true;
}
bool ListBuilder::feed(const uint8_t *data, size_t size) {
    if (error_ || sorted_) return false;
    while (size--) {
        uint8_t c = *data++;
        if (skipping_) { skipping_ = c != '\n'; continue; }
        if (c == '\n') { if (!line()) return false; line_n_ = 0; }
        else if (c && line_n_ + 1 >= sizeof(line_) && abp_) { skipping_ = true; line_n_ = 0; } // oversized rule: not a domain
        else {
            if (!c || line_n_ + 1 >= sizeof(line_)) { error_ = "Invalid or oversized list line"; return false; }
            line_[line_n_++] = c;
        }
    }
    return true;
}
bool ListBuilder::finish_source() {
    if (error_) return false;
    if (line_n_ && !line()) return false;
    line_n_ = 0; abp_ = skipping_ = false; return true;
}
// Drops entries whose parent domain is also listed (blocking the parent blocks the child, so the result is identical).
void ListBuilder::prune() {
    if (pruned_) return;
    pruned_ = true;
    for (size_t i = 0; i < table_cap_; ++i) {
        uint32_t entry = table_[i];
        if (!entry) continue;
        const char *s = pool_ + entry - 1; uint32_t hash = 2166136261u;
        for (size_t j = 0; s[j]; ++j) {
            if (s[j] == '.' && table_[slot(hash, s, j)]) { table_[i] = entry | removed; --count_; break; }
            hash = hash_step(hash, s[j]);
        }
        if (yield_ && (i & 8191) == 0) yield_(context_);
    }
}
size_t ListBuilder::shared_with_previous(size_t index) const {
    if (index % list_block_entries == 0) return 0;
    const char *a = pool_ + table_[index - 1], *b = pool_ + table_[index];
    size_t shared = 0;
    while (a[shared] && a[shared] == b[shared]) ++shared;
    return shared;
}
bool ListBuilder::prepare() {
    if (sorted_) return count_ != 0;
    if (!finish_source() || !count_) return false;
    prune();
    size_t out = 0;
    for (size_t i = 0; i < table_cap_; ++i) if (table_[i] && !(table_[i] & removed)) table_[out++] = table_[i] - 1;
    count_ = out;
    size_t comparisons = 0;
    std::sort(table_, table_ + count_, [&](uint32_t a, uint32_t b) {
        if (yield_ && (++comparisons & 32767) == 0) yield_(context_);
        return std::strcmp(pool_ + a, pool_ + b) < 0;
    });
    sorted_ = true; encoded_ = 0;
    for (size_t i = 0; i < count_; ++i) encoded_ += 2 + std::strlen(pool_ + table_[i]) - shared_with_previous(i);
    return true;
}
size_t ListBuilder::image_size() { return prepare() ? 24 + (count_ + list_block_entries - 1) / list_block_entries * 4 + encoded_ : 0; }
bool ListBuilder::write(ListWrite writer, void *context) {
    if (!writer || !prepare()) return false;
    uint8_t buffer[4096]; size_t buffered = 0, offset = 20; uint32_t crc = 0;
    auto flush = [&]() {
        if (!buffered) return true;
        crc = list_crc32(crc, buffer, buffered);
        if (!writer(offset, buffer, buffered, context)) return false;
        offset += buffered; buffered = 0;
        if (yield_) yield_(context_);
        return true;
    };
    auto emit = [&](const uint8_t *data, size_t size) {
        while (size) {
            size_t amount = std::min(size, sizeof(buffer) - buffered);
            std::memcpy(buffer + buffered, data, amount); buffered += amount; data += amount; size -= amount;
            if (buffered == sizeof(buffer) && !flush()) return false;
        }
        return true;
    };
    // Block index (start offset of each block, then the total), then the front-coded entries.
    uint32_t position = 0; uint8_t value[4];
    for (size_t i = 0; i < count_; ++i) {
        if (i % list_block_entries == 0) { le_write(value, position); if (!emit(value, 4)) return false; }
        position += 2 + std::strlen(pool_ + table_[i]) - shared_with_previous(i);
    }
    le_write(value, position); if (!emit(value, 4)) return false;
    for (size_t i = 0; i < count_; ++i) {
        const char *s = pool_ + table_[i]; size_t shared = shared_with_previous(i), rest = std::strlen(s + shared);
        const uint8_t head[2] = {uint8_t(shared), uint8_t(rest)};
        if (!emit(head, 2) || !emit(reinterpret_cast<const uint8_t *>(s + shared), rest)) return false;
    }
    if (!flush()) return false;
    uint8_t header[20]; std::memcpy(header, "YDNS", 4);
    le_write(header + 4, 2); le_write(header + 8, count_); le_write(header + 12, position); le_write(header + 16, crc);
    return writer(0, header, sizeof(header), context);
}
} // namespace yetdns
