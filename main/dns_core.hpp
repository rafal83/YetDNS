#pragma once
#include <cstddef>
#include <cstdint>

namespace yetdns {
constexpr size_t packet_max = 4096;
constexpr size_t cache_packet_max = 1232;
constexpr size_t cache_key_max = 288;
uint16_t read16(const uint8_t *p);
uint32_t read32(const uint8_t *p);
void write16(uint8_t *p, uint16_t value);
void write32(uint8_t *p, uint32_t value);
struct Question {
    char name[254]{};
    uint16_t type{}, klass{}, end{}, udp_size{512};
    bool cacheable{};
};
bool parse_query(const uint8_t *p, size_t n, Question &q);
bool matching_response(const uint8_t *p, size_t n, const uint8_t *query, size_t query_n);
// Error/local responses discard additional data and never assert AD or AA.
size_t reply(const uint8_t *query, size_t n, uint8_t *out, uint8_t rcode,
             const uint8_t *ipv4 = nullptr, bool sinkhole = false, bool truncated = false);
bool cache_ttl(const uint8_t *p, size_t n, uint32_t &ttl);
bool age_ttls(uint8_t *p, size_t n, uint32_t age);
bool inspect_aliases(const uint8_t *p, size_t n, bool (*denied)(const char *, void *), void *context, bool &blocked);
bool domain_valid(const char *name);
bool suffix_match(const char *name, const char *rule);
enum class Action : uint8_t { allow, deny, rewrite };
struct Rule {
    char domain[254]{};
    uint32_t client{}; // zero = all clients; network byte order
    uint8_t address[4]{};
    Action action{Action::deny};
};
constexpr size_t rule_max = 32;
struct Rules { uint32_t version{1}, count{}; Rule items[rule_max]{}; };
bool evaluate_rules(const Rules &rules, const char *name, uint32_t client, Action &action, uint8_t *address);

// Image v2: sorted reversed domains ("com.example.ads"), front-coded in blocks of list_block_entries.
constexpr uint32_t list_block_entries = 16;
class Blocklist {
    const uint8_t *index_{}, *data_{}; // per-block start offsets, then the front-coded entries
    uint32_t count_{}, blocks_{};
    bool find(const char *key, size_t length) const;
public:
    bool load(const uint8_t *data, size_t size);
    bool contains(const char *domain) const;
    uint32_t count() const { return count_; }
};

struct CacheEntry {
    uint32_t inserted{}, lifetime{};
    uint16_t query_n{}, response_n{};
    uint8_t key[cache_key_max]{};
    uint8_t response[cache_packet_max]{};
};
// Single owner: the DNS event loop. No locks, heap allocation or background expiry.
class Cache {
    CacheEntry *entries_;
    size_t count_, next_{};
public:
    Cache(CacheEntry *entries, size_t count) : entries_(entries), count_(count) {}
    size_t get(const uint8_t *query, size_t n, uint8_t *out, uint32_t now);
    void put(const uint8_t *query, size_t n, const uint8_t *response, size_t rn, uint32_t now);
    void clear();
};
} // namespace yetdns
