#pragma once
#include "dns_core.hpp"
#include "runtime.hpp"
#include <atomic>
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

namespace yetdns {
struct Counters {
    std::atomic<uint32_t> queries{}, blocked{}, cached{}, forwarded{}, errors{}, limited{}, overload{};
    // Why forwarded answers miss the cache next time: the query carries EDNS options or is oversized, or the
    // response is refused (SERVFAIL, truncated, TTL 0, negative without SOA).
    std::atomic<uint32_t> uncacheable{}, unstored{};
};
struct LogEntry { char domain[254]; uint32_t client, elapsed_us; uint16_t type; char result[12]; };
extern Counters stats;
extern std::atomic<bool> blocking, flush_cache;
extern std::atomic<bool> log_blocked_only;
extern std::atomic<uint32_t> subnet_ip, subnet_mask;
extern Blocklist blocklist;
extern Rules rules;
extern SemaphoreHandle_t rules_mutex;
esp_err_t service_start();
// Sizes actually obtained at boot (they can be below the configured maxima) and the smallest stack margin seen.
struct ServiceCapacity { size_t workers, pending, cache_entries, stack_min_free; };
ServiceCapacity service_capacity();
esp_err_t admin_start();
void load_settings();
esp_err_t save_rules(const Rules &value);
esp_err_t save_blocking(bool value);
size_t copy_logs(LogEntry *out, size_t capacity);
void set_log_blocked_only(bool value);
} // namespace yetdns
