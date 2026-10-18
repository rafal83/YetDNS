#pragma once
#include <atomic>
#include <cstdint>
#include "esp_err.h"

namespace yetdns {
struct RuntimeConfig {
    uint32_t version{2}, rate_limit{100}, timeout_ms{1500};
    bool doh{}, logging{true}, subnet_only{true};
    char primary[16]{}, secondary[16]{}, doh_url[384]{};
    bool block_page{};
};
extern std::atomic<uint32_t> query_limit;
extern std::atomic<bool> query_logging, subnet_only, doh_enabled, block_page_enabled;
void runtime_init();
RuntimeConfig runtime_snapshot();
bool runtime_valid(const RuntimeConfig &value);
esp_err_t runtime_save(const RuntimeConfig &value);
void clear_logs();
} // namespace yetdns
