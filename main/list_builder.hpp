#pragma once
#include <cstddef>
#include <cstdint>

namespace yetdns {
using ListWrite = bool (*)(size_t offset, const uint8_t *data, size_t size, void *context);
using ListYield = void (*)(void *context);
uint32_t list_crc32(uint32_t crc, const uint8_t *data, size_t size);
uint32_t list_update_delay(uint32_t last_success, uint32_t now, uint32_t hours, bool sources_match);
// Streaming parser and exact deduplicator. All bulk storage is supplied by caller.
// Domains are stored reversed ("com.example.ads") so that a parent domain is a label-boundary prefix of its
// subdomains: covered subdomains are dropped, and the sorted result front-codes into a compact image.
class ListBuilder {
    char *pool_;
    size_t pool_cap_, used_{};
    uint32_t *table_;
    size_t table_cap_, count_{}, encoded_{};
    size_t accepted_{};
    char line_[1024]{};
    size_t line_n_{};
    const char *error_{};
    bool sorted_{}, pruned_{}, abp_{}, skipping_{};
    ListYield yield_;
    void *context_;
    bool line();
    bool add(char *domain, bool lenient = false);
    bool abp_rule(char *rule);
    size_t slot(uint32_t hash, const char *reversed, size_t length) const;
    void prune();
    bool prepare();
    size_t shared_with_previous(size_t index) const;
public:
    ListBuilder(char *pool, size_t pool_cap, uint32_t *table, size_t table_cap,
                ListYield yield = nullptr, void *context = nullptr);
    bool feed(const uint8_t *data, size_t size);
    bool finish_source();
    bool write(ListWrite writer, void *context);
    const char *error() const { return error_ ? error_ : ""; }
    size_t count() const { return count_; }
    size_t accepted() const { return accepted_; }
    // Final flash image size; sorts and prunes the list on first use. Zero when nothing can be written.
    size_t image_size();
};
} // namespace yetdns
