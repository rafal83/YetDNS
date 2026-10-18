#pragma once
#include <cstddef>
#include <cstdint>

namespace yetdns {
using ListWrite = bool (*)(size_t offset, const uint8_t *data, size_t size, void *context);
using ListYield = void (*)(void *context);
uint32_t list_crc32(uint32_t crc, const uint8_t *data, size_t size);
uint32_t list_update_delay(uint32_t last_success, uint32_t now, uint32_t hours, bool sources_match);
// Streaming parser and exact deduplicator. All bulk storage is supplied by caller.
class ListBuilder {
    char *pool_;
    size_t pool_cap_, used_{};
    uint32_t *table_;
    size_t table_cap_, count_{}, packed_{};
    size_t accepted_{};
    char line_[1024]{};
    size_t line_n_{};
    const char *error_{};
    bool sorted_{};
    ListYield yield_;
    void *context_;
    bool line();
    bool add(char *domain);
public:
    ListBuilder(char *pool, size_t pool_cap, uint32_t *table, size_t table_cap,
                ListYield yield = nullptr, void *context = nullptr);
    bool feed(const uint8_t *data, size_t size);
    bool finish_source();
    bool write(ListWrite writer, void *context);
    const char *error() const { return error_ ? error_ : ""; }
    size_t count() const { return count_; }
    size_t accepted() const { return accepted_; }
    size_t image_size() const { return 24 + count_ * 4 + packed_; }
};
} // namespace yetdns
