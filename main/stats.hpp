#pragma once
#include "stats_core.hpp"
#include "esp_err.h"

namespace yetdns {
struct DaySummary { int32_t day; uint32_t queries, blocked; };
// Call after the "listscfg" NVS partition is initialized.
void top_init();
esp_err_t top_start();
void top_query();
void top_block(const char *domain, uint32_t client);
// Local civil day number (see civil_to_days), or 0 while the clock is not synchronized.
int32_t top_today();
// offset 0 is the running day (RAM); 1..history_days-1 come from flash.
bool top_day(unsigned offset, DayRecord &record);
size_t top_history(DaySummary *out, size_t capacity);
bool top_client_name(uint32_t ip, char *name, size_t capacity);
} // namespace yetdns
