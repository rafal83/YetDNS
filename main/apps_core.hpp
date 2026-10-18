#pragma once
#include <cstddef>
#include <cstdint>

namespace yetdns {
struct Application { const char *id, *name, *category; uint16_t domains; };
size_t application_count();
const Application &application_at(size_t index);
int application_index(const char *id);
uint64_t application_valid_mask();
// Exact suffix search in a sorted, immutable flash catalogue. No allocation.
bool application_denied(const char *domain, uint64_t blocked);
constexpr size_t app_client_max = 16;
struct AppClient { uint32_t address{}; uint64_t blocked{}; };
struct AppsConfig {
    uint32_t version{1}, count{};
    uint64_t blocked{};
    AppClient clients[app_client_max]{};
};
bool apps_config_valid(const AppsConfig &cfg);
uint64_t apps_client_mask(const AppsConfig &cfg, uint32_t client);
bool apps_set_scope(AppsConfig &cfg, uint32_t client, uint64_t blocked);
} // namespace yetdns
