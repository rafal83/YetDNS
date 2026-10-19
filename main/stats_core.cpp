#include "stats_core.hpp"
#include "dns_core.hpp"
#include <algorithm>
#include <cstdio>
#include <cstring>

namespace yetdns {
uint32_t top_hash(const char *text) {
    uint32_t hash = 2166136261u;
    for (; *text; ++text) hash = (hash ^ uint8_t(*text)) * 16777619u;
    return hash;
}
void TopTable::clear() {
    used_ = 0; evicted_ = false;
    for (size_t i = 0; i < capacity_; ++i) slots_[i] = {};
}
void TopTable::hit(uint32_t id, const char *name, uint32_t amount) {
    if (!amount) return;
    TopEntry *minimum = nullptr;
    for (size_t i = 0; i < used_; ++i) {
        auto &e = slots_[i];
        if (e.id == id && (!name || !std::strncmp(e.name, name, top_name_max - 1))) { e.count += amount; return; }
        if (!minimum || e.count < minimum->count) minimum = &e;
    }
    TopEntry *slot;
    if (used_ < capacity_) { slot = &slots_[used_++]; slot->count = 0; }
    else {
        // Evict the smallest counter; the newcomer inherits its count, so counts only overestimate.
        slot = minimum; evicted_ = true;
    }
    slot->id = id; slot->count += amount;
    std::memset(slot->name, 0, sizeof(slot->name));
    if (name) std::strncpy(slot->name, name, top_name_max - 1);
}
size_t TopTable::top(TopRow *out, size_t limit) const {
    bool taken[top_domain_slots > top_client_slots ? top_domain_slots : top_client_slots]{};
    size_t count = 0;
    for (; count < limit; ++count) {
        const TopEntry *best = nullptr; size_t index = 0;
        for (size_t i = 0; i < used_ && i < sizeof(taken); ++i) {
            if (taken[i] || !slots_[i].count) continue;
            const auto &e = slots_[i];
            if (!best || e.count > best->count || (e.count == best->count && std::strcmp(e.name, best->name) < 0)) { best = &e; index = i; }
        }
        if (!best) break;
        taken[index] = true;
        out[count].id = best->id; out[count].count = best->count;
        std::memcpy(out[count].name, best->name, sizeof(out[count].name));
    }
    return count;
}
bool day_record_valid(const DayRecord &r) {
    if (r.version != 1 || r.day <= 0 || r.domain_count > top_n || r.client_count > top_n) return false;
    for (size_t i = 0; i < r.domain_count; ++i) if (!std::memchr(r.domains[i].name, 0, top_name_max)) return false;
    return true;
}
int32_t civil_to_days(int year, unsigned month, unsigned day) {
    year -= month <= 2;
    int era = (year >= 0 ? year : year - 399) / 400;
    unsigned yoe = unsigned(year - era * 400);
    unsigned doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + int(doe) - 719468;
}
void days_to_civil(int32_t days, int &year, unsigned &month, unsigned &day) {
    days += 719468;
    int era = (days >= 0 ? days : days - 146096) / 146097;
    unsigned doe = unsigned(days - era * 146097);
    unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    unsigned mp = (5 * doy + 2) / 153;
    day = doy - (153 * mp + 2) / 5 + 1;
    month = mp < 10 ? mp + 3 : mp - 9;
    year = int(yoe) + era * 400 + (month <= 2);
}
size_t mdns_ptr_query(uint32_t ip, uint16_t id, uint8_t *out, size_t capacity) {
    char name[40];
    const uint8_t *b = reinterpret_cast<const uint8_t *>(&ip);
    int len = std::snprintf(name, sizeof(name), "%u.%u.%u.%u.in-addr.arpa", b[3], b[2], b[1], b[0]);
    if (len <= 0 || size_t(len) + 18 > capacity) return 0;
    std::memset(out, 0, 12);
    out[0] = id >> 8; out[1] = uint8_t(id); out[5] = 1;
    size_t pos = 12;
    for (const char *label = name; *label;) {
        const char *dot = std::strchr(label, '.');
        size_t n = dot ? size_t(dot - label) : std::strlen(label);
        out[pos++] = uint8_t(n); std::memcpy(out + pos, label, n); pos += n;
        label += n + (dot ? 1 : 0);
    }
    out[pos++] = 0;
    out[pos++] = 0; out[pos++] = 12; // PTR
    out[pos++] = 0; out[pos++] = 1;  // IN
    return pos;
}
static bool local_suffix(const char *text) {
    static const char local[] = ".local";
    for (size_t i = 0; i < 6; ++i) if ((text[i] | 0x20) != local[i]) return false;
    return true;
}
// Reads a possibly compressed name; `next` receives the position after the name field.
static bool read_name(const uint8_t *p, size_t n, size_t pos, char *out, size_t capacity, size_t &next) {
    size_t length = 0, hops = 0; bool jumped = false;
    next = pos;
    for (;;) {
        if (pos >= n) return false;
        uint8_t c = p[pos];
        if ((c & 0xc0) == 0xc0) {
            if (pos + 1 >= n || ++hops > 8) return false;
            if (!jumped) next = pos + 2;
            jumped = true; pos = size_t(c & 0x3f) << 8 | p[pos + 1]; continue;
        }
        if (c & 0xc0) return false;
        ++pos;
        if (!c) { if (!jumped) next = pos; break; }
        if (pos + c > n || length + c + 2 > capacity) return false;
        if (length) out[length++] = '.';
        std::memcpy(out + length, p + pos, c); length += c; pos += c;
    }
    out[length] = 0; return true;
}
bool mdns_ptr_answer(const uint8_t *p, size_t n, uint16_t id, char *name, size_t capacity) {
    if (n < 12 || capacity < 2 || read16(p) != id || !(p[2] & 0x80) || (p[3] & 0x0f)) return false;
    uint32_t questions = read16(p + 4), answers = read16(p + 6);
    size_t pos = 12; char scratch[130]; size_t next;
    for (uint32_t i = 0; i < questions && i < 4; ++i) {
        if (!read_name(p, n, pos, scratch, sizeof(scratch), next) || next + 4 > n) return false;
        pos = next + 4;
    }
    for (uint32_t i = 0; i < answers && i < 8; ++i) {
        if (!read_name(p, n, pos, scratch, sizeof(scratch), next) || next + 10 > n) return false;
        uint16_t type = read16(p + next), rdlength = read16(p + next + 8);
        size_t data = next + 10;
        if (data + rdlength > n) return false;
        if (type == 12 && read_name(p, n, data, scratch, sizeof(scratch), next)) {
            size_t length = std::strlen(scratch);
            if (length > 6 && local_suffix(scratch + length - 6)) scratch[length -= 6] = 0;
            if (!length) return false;
            size_t out = 0;
            for (size_t k = 0; k < length && out + 1 < capacity; ++k)
                name[out++] = (scratch[k] >= 0x20 && scratch[k] < 0x7f) ? scratch[k] : '?';
            name[out] = 0; return true;
        }
        pos = data + rdlength;
    }
    return false;
}
} // namespace yetdns
