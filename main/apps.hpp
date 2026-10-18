#pragma once
#include "apps_core.hpp"
#include "esp_err.h"

namespace yetdns {
esp_err_t apps_init();
AppsConfig apps_config();
esp_err_t apps_save_scope(uint32_t client, uint64_t blocked);
bool apps_denied(const char *domain, uint32_t client);
} // namespace yetdns
