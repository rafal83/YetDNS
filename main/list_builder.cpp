#include "list_builder.hpp"
#include "dns_core.hpp"
#include <algorithm>
#include <cstring>

namespace yetdns {
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
    if (!pool || !table || !slots || (slots & (slots - 1))) error_ = "Invalid builder storage";
    else std::memset(table, 0, slots * sizeof(uint32_t));
}
bool ListBuilder::add(char *domain) {
    size_t len = std::strlen(domain);
    if (len && domain[len - 1] == '.') domain[--len] = 0;
    for (size_t i = 0; i < len; ++i) if (domain[i] >= 'A' && domain[i] <= 'Z') domain[i] += 32;
    if (!std::strcmp(domain, "localhost") || !std::strcmp(domain, "local") || !std::strcmp(domain, "localhost.localdomain") ||
        !std::strcmp(domain, "broadcasthost") || !std::strncmp(domain, "ip6-", 4)) return true;
    if (!domain_valid(domain)) { error_ = "Invalid domain or unsupported filter syntax"; return false; }
    bool numeric = true;
    for (size_t i = 0; i < len; ++i) if ((domain[i] < '0' || domain[i] > '9') && domain[i] != '.') numeric = false;
    if (numeric) { error_ = "IP address is not a domain"; return false; }
    ++accepted_;
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; ++i) { hash ^= uint8_t(domain[i]); hash *= 16777619u; }
    size_t index = hash & (table_cap_ - 1);
    while (table_[index]) {
        if (!std::strcmp(pool_ + table_[index] - 1, domain)) return true;
        index = (index + 1) & (table_cap_ - 1);
    }
    if (count_ >= table_cap_ * 2 / 3 || used_ + len + 1 > pool_cap_) {
        error_ = "List capacity exceeded; previous list retained"; return false;
    }
    std::memcpy(pool_ + used_, domain, len + 1);
    table_[index] = used_ + 1; used_ += len + 1; packed_ += len; ++count_;
    return true;
}
bool ListBuilder::line() {
    line_[line_n_] = 0;
    char *s = line_;
    if (line_n_ >= 3 && uint8_t(s[0]) == 0xef && uint8_t(s[1]) == 0xbb && uint8_t(s[2]) == 0xbf) s += 3;
    while (*s == ' ' || *s == '\t' || *s == '\r') ++s;
    if (!*s || *s == '#' || *s == '!') return true;
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
        if (c == '\n') { if (!line()) return false; line_n_ = 0; }
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
    line_n_ = 0; return true;
}
bool ListBuilder::write(ListWrite writer, void *context) {
    if (!finish_source() || !writer || !count_ || sorted_) return false;
    size_t out = 0;
    for (size_t i = 0; i < table_cap_; ++i) if (table_[i]) table_[out++] = table_[i] - 1;
    size_t comparisons = 0;
    std::sort(table_, table_ + count_, [&](uint32_t a, uint32_t b) {
        if (yield_ && (++comparisons & 32767) == 0) yield_(context_);
        return std::strcmp(pool_ + a, pool_ + b) < 0;
    });
    sorted_ = true;
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
    uint32_t position = 0; uint8_t value[4];
    for (size_t i = 0; i <= count_; ++i) {
        le_write(value, position); if (!emit(value, 4)) return false;
        if (i < count_) position += std::strlen(pool_ + table_[i]);
    }
    for (size_t i = 0; i < count_; ++i) {
        const auto *s = reinterpret_cast<const uint8_t *>(pool_ + table_[i]);
        if (!emit(s, std::strlen(reinterpret_cast<const char *>(s)))) return false;
    }
    if (!flush()) return false;
    uint8_t header[20]; std::memcpy(header, "YDNS", 4);
    le_write(header + 4, 1); le_write(header + 8, count_); le_write(header + 12, packed_); le_write(header + 16, crc);
    return writer(0, header, sizeof(header), context);
}
} // namespace yetdns
