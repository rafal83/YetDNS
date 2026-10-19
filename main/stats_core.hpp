#pragma once
#include <cstddef>
#include <cstdint>

namespace yetdns {
constexpr size_t top_name_max = 48, top_n = 10, history_days = 14;
constexpr size_t top_domain_slots = 128, top_client_slots = 32;
struct TopEntry { uint32_t id{}, count{}; char name[top_name_max]{}; };
struct TopRow { uint32_t id{}, count{}; char name[top_name_max]{}; };
uint32_t top_hash(const char *text);
// Space-Saving counter: exact until the table is full, then the tail is approximate.
// No locking and no allocation; callers serialize access.
class TopTable {
public:
    TopTable(TopEntry *slots, size_t capacity) : slots_(slots), capacity_(capacity) {}
    void clear();
    void hit(uint32_t id, const char *name, uint32_t amount = 1);
    size_t top(TopRow *out, size_t limit) const;
    bool approximate() const { return evicted_; }
    void mark_approximate() { evicted_ = true; }
private:
    TopEntry *slots_; size_t capacity_, used_{}; bool evicted_{};
};
struct DayDomain { char name[top_name_max]; uint32_t count; };
struct DayClient { uint32_t ip, count; };
struct DayRecord {
    uint32_t version{1};
    int32_t day{};
    uint32_t queries{}, blocked{}, approximate{}, domain_count{}, client_count{};
    DayDomain domains[top_n]{};
    DayClient clients[top_n]{};
};
bool day_record_valid(const DayRecord &record);
// Days since 1970-01-01 for a civil date, and the inverse (proleptic Gregorian).
int32_t civil_to_days(int year, unsigned month, unsigned day);
void days_to_civil(int32_t days, int &year, unsigned &month, unsigned &day);
// Multicast DNS reverse lookup (PTR for a.b.c.d.in-addr.arpa) to learn a device's .local name.
// `ip` is in network byte order, as stored in sockaddr_in.
size_t mdns_ptr_query(uint32_t ip, uint16_t id, uint8_t *out, size_t capacity);
bool mdns_ptr_answer(const uint8_t *packet, size_t n, uint16_t id, char *name, size_t capacity);
} // namespace yetdns
