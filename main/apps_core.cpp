#include "apps_core.hpp"
#include <cstring>

namespace yetdns {
#include "app_catalog.inc"
size_t application_count() { return sizeof(catalog) / sizeof(catalog[0]); }
const Application &application_at(size_t index) { return catalog[index]; }
int application_index(const char *id) {
    if (!id) return -1;
    for (size_t i = 0; i < application_count(); ++i) if (!std::strcmp(id, catalog[i].id)) return int(i);
    return -1;
}
uint64_t application_valid_mask() { return UINT64_MAX >> (64 - application_count()); }
bool application_denied(const char *name, uint64_t blocked) {
    if (!blocked || !name || !*name) return false;
    do {
        size_t lo = 0, hi = sizeof(app_domains) / sizeof(app_domains[0]);
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            int cmp = std::strcmp(name, app_domains[mid].name);
            if (!cmp) { if (blocked & app_domains[mid].mask) return true; break; }
            if (cmp < 0) hi = mid; else lo = mid + 1;
        }
        const char *dot = std::strchr(name, '.');
        if (!dot) break;
        name = dot + 1;
    } while (*name);
    return false;
}
bool apps_config_valid(const AppsConfig &cfg) {
    if (cfg.version != 1 || cfg.count > app_client_max || (cfg.blocked & ~application_valid_mask())) return false;
    for (size_t i = 0; i < cfg.count; ++i) {
        const auto &item = cfg.clients[i];
        if (!item.address || !item.blocked || (item.blocked & ~application_valid_mask())) return false;
        for (size_t j = 0; j < i; ++j) if (cfg.clients[j].address == item.address) return false;
    }
    return true;
}
uint64_t apps_client_mask(const AppsConfig &cfg, uint32_t client) {
    uint64_t result = cfg.blocked;
    for (size_t i = 0; i < cfg.count; ++i) if (cfg.clients[i].address == client) result |= cfg.clients[i].blocked;
    return result;
}
bool apps_set_scope(AppsConfig &cfg, uint32_t client, uint64_t blocked) {
    if (blocked & ~application_valid_mask()) return false;
    if (!client) { cfg.blocked = blocked; return true; }
    for (size_t i = 0; i < cfg.count; ++i) if (cfg.clients[i].address == client) {
        if (blocked) cfg.clients[i].blocked = blocked;
        else { cfg.clients[i] = cfg.clients[--cfg.count]; cfg.clients[cfg.count] = {}; }
        return true;
    }
    if (!blocked) return true;
    if (cfg.count == app_client_max) return false;
    cfg.clients[cfg.count++] = {client, blocked}; return true;
}
} // namespace yetdns
