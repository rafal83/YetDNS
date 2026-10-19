#include "stats_core.hpp"
#include "dns_core.hpp"
#include <cassert>
#include <cstring>
#include <string>
using namespace yetdns;
int main() {
    TopEntry slots[4];
    TopTable table(slots, 4);
    for (int i = 0; i < 5; ++i) table.hit(top_hash("ads.example"), "ads.example");
    for (int i = 0; i < 3; ++i) table.hit(top_hash("track.example"), "track.example");
    table.hit(top_hash("b.example"), "b.example"); table.hit(top_hash("a.example"), "a.example");
    TopRow rows[10];
    size_t n = table.top(rows, 10);
    assert(n == 4 && !table.approximate());
    assert(!std::strcmp(rows[0].name, "ads.example") && rows[0].count == 5);
    assert(!std::strcmp(rows[1].name, "track.example") && rows[1].count == 3);
    assert(!std::strcmp(rows[2].name, "a.example") && !std::strcmp(rows[3].name, "b.example")); // ties sort by name
    // Table full: the smallest counter is evicted and the newcomer inherits its count.
    table.hit(top_hash("new.example"), "new.example");
    n = table.top(rows, 2);
    assert(table.approximate() && n == 2 && rows[0].count == 5 && rows[1].count == 3);
    n = table.top(rows, 10);
    assert(n == 4);
    bool seen = false;
    for (size_t i = 0; i < n; ++i) if (!std::strcmp(rows[i].name, "new.example")) { seen = true; assert(rows[i].count == 2); }
    assert(seen);
    // A heavy domain survives a flood of one-off names.
    TopEntry big[16]; TopTable heavy(big, 16);
    for (int i = 0; i < 200; ++i) {
        heavy.hit(top_hash("heavy.example"), "heavy.example");
        std::string once = "once" + std::to_string(i) + ".example";
        heavy.hit(top_hash(once.c_str()), once.c_str());
    }
    heavy.top(rows, 1);
    assert(!std::strcmp(rows[0].name, "heavy.example") && rows[0].count >= 200);
    // Clients are keyed by address only.
    TopEntry ips[3]; TopTable clients(ips, 3);
    clients.hit(0x0100a8c0, nullptr, 7); clients.hit(0x0200a8c0, nullptr); clients.hit(0x0100a8c0, nullptr);
    n = clients.top(rows, 3);
    assert(n == 2 && rows[0].id == 0x0100a8c0 && rows[0].count == 8);
    table.clear();
    assert(table.top(rows, 10) == 0 && !table.approximate());
    // Day record validation.
    DayRecord record; record.day = 20000; assert(day_record_valid(record));
    record.domain_count = top_n + 1; assert(!day_record_valid(record));
    record.domain_count = 1; std::memset(record.domains[0].name, 'x', top_name_max); assert(!day_record_valid(record));
    record = {}; assert(!day_record_valid(record));
    // Calendar conversion round trips and known dates.
    assert(civil_to_days(1970, 1, 1) == 0 && civil_to_days(2000, 3, 1) == 11017 && civil_to_days(2026, 10, 19) == 20745);
    for (int32_t d = -800; d < 30000; d += 7) {
        int y; unsigned m, day; days_to_civil(d, y, m, day);
        assert(civil_to_days(y, m, day) == d && m >= 1 && m <= 12 && day >= 1 && day <= 31);
    }
    int y; unsigned m, d; days_to_civil(11016, y, m, d); assert(y == 2000 && m == 2 && d == 29);
    // mDNS reverse query for 192.168.1.50 (network order bytes c0 a8 01 32).
    uint8_t octets[4] = {192, 168, 1, 50}; uint32_t ip; std::memcpy(&ip, octets, 4);
    uint8_t packet[128];
    size_t len = mdns_ptr_query(ip, 0x1234, packet, sizeof(packet));
    static const uint8_t expected[] = {0x12,0x34,0,0,0,1,0,0,0,0,0,0, 2,'5','0',1,'1',3,'1','6','8',3,'1','9','2',7,'i','n','-','a','d','d','r',4,'a','r','p','a',0, 0,12,0,1};
    assert(len == sizeof(expected) && !std::memcmp(packet, expected, len));
    assert(mdns_ptr_query(ip, 1, packet, 20) == 0);
    // Matching response with a compressed owner name and a .local target.
    uint8_t answer[128]; size_t pos = 0;
    auto put = [&](const uint8_t *data, size_t n) { std::memcpy(answer + pos, data, n); pos += n; };
    static const uint8_t header[] = {0x12,0x34,0x84,0,0,0,0,1,0,0,0,0};
    put(header, sizeof(header));
    put(expected + 12, len - 16);                       // owner name
    static const uint8_t meta[] = {0,12,0,1,0,0,0,10,0,0}; put(meta, sizeof(meta));
    size_t rdlength_at = pos - 2; static const uint8_t target[] = {11,'r','a','p','h','-','i','p','h','o','n','e',5,'l','o','c','a','l',0};
    put(target, sizeof(target)); answer[rdlength_at + 1] = sizeof(target);
    char name[40];
    assert(mdns_ptr_answer(answer, pos, 0x1234, name, sizeof(name)) && !std::strcmp(name, "raph-iphone"));
    assert(!mdns_ptr_answer(answer, pos, 0x1235, name, sizeof(name)));      // wrong id
    assert(!mdns_ptr_answer(answer, pos - 5, 0x1234, name, sizeof(name)));  // truncated
    answer[2] = 0; assert(!mdns_ptr_answer(answer, pos, 0x1234, name, sizeof(name))); // not a response
    uint8_t loop[] = {0x12,0x34,0x84,0,0,0,0,1,0,0,0,0,0xc0,12,0,12,0,1,0,0,0,10,0,2,0xc0,12};
    assert(!mdns_ptr_answer(loop, sizeof(loop), 0x1234, name, sizeof(name)));  // compression loop
    return 0;
}
