#pragma once
#include <cstdint>
#include "esp_err.h"

namespace yetdns {
struct UpdateInfo {
    char current[32], latest[32], message[96], repo[48], asset[48];
    const char *phase;       // idle, checking, downloading, restarting, error
    bool available, auto_check;
    uint32_t checked_at;     // Unix time of the last successful check, 0 if none
    uint32_t downloaded, total;
};
esp_err_t update_start();
void update_snapshot(UpdateInfo &info);
bool update_request_check();
bool update_request_install();
esp_err_t update_set_auto_check(bool value);
} // namespace yetdns
