#include "service.hpp"
#include "apps.hpp"
#include "esp_app_desc.h"
#include "lists.hpp"
#include "ha_mqtt.hpp"
#include "stats.hpp"
#include "update.hpp"
#include <cstdlib>
#include <cstring>
#include <memory>
#include <cmath>
#include <ctime>
#include <cstddef>
#include "cJSON.h"
#include "esp_http_server.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "lwip/sockets.h"
#include "nvs.h"
#include "nvs_flash.h"

namespace yetdns {
static bool valid_rules(const Rules &value) {
    if (value.version != 1 || value.count > rule_max) return false;
    for (size_t i = 0; i < value.count; ++i) {
        const auto &r = value.items[i];
        if (!std::memchr(r.domain, 0, sizeof(r.domain)) || !domain_valid(r.domain) ||
            r.action > Action::rewrite) return false;
    }
    return true;
}
static esp_err_t persist_rules(const Rules &value) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open_from_partition("listscfg", "policy", NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    size_t size = offsetof(Rules, items) + value.count * sizeof(Rule);
    err = nvs_set_blob(handle, "rules", &value, size);
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle); return err;
}
void load_settings() {
    rules_mutex = xSemaphoreCreateMutex();
    configASSERT(rules_mutex);
    ESP_ERROR_CHECK(nvs_flash_init_partition("listscfg"));
    nvs_handle_t nvs;
    ESP_ERROR_CHECK(nvs_open("yetdns", NVS_READWRITE, &nvs));
    auto loaded = std::unique_ptr<Rules>(new (std::nothrow) Rules{});
    configASSERT(loaded);
    size_t len = sizeof(Rules);
    nvs_handle_t policy;
    if (nvs_open_from_partition("listscfg", "policy", NVS_READONLY, &policy) == ESP_OK) {
        if (nvs_get_blob(policy, "rules", loaded.get(), &len) == ESP_OK &&
            len == offsetof(Rules, items) + loaded->count * sizeof(Rule) && valid_rules(*loaded)) {
            rules = *loaded;
        }
        nvs_close(policy);
    }
    uint8_t enabled = 1;
    nvs_get_u8(nvs, "blocking", &enabled); blocking = enabled != 0;
    uint8_t only_blocks = 1;
    nvs_get_u8(nvs, "log_only", &only_blocks); set_log_blocked_only(only_blocks != 0);
    nvs_close(nvs);
    runtime_init();
    ESP_ERROR_CHECK(apps_init());
    top_init();
}
esp_err_t save_rules(const Rules &value) {
    if (!valid_rules(value)) return ESP_ERR_INVALID_ARG;
    esp_err_t err = persist_rules(value);
    if (err == ESP_OK) {
        xSemaphoreTake(rules_mutex, portMAX_DELAY); rules = value; xSemaphoreGive(rules_mutex);
        flush_cache = true;
    }
    return err;
}
esp_err_t save_blocking(bool value) {
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("yetdns", NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    err = nvs_set_u8(nvs, "blocking", value);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    if (err == ESP_OK) { blocking = value; flush_cache = true; }
    return err;
}
static esp_err_t error(httpd_req_t *req, const char *status, const char *message) {
    httpd_resp_set_status(req, status); httpd_resp_set_type(req, "text/plain");
    return httpd_resp_send(req, message, HTTPD_RESP_USE_STRLEN);
}
static bool authorized(httpd_req_t *req) {
    // No login or secret. Browser mutations require a same-origin custom header.
    if (req->method == HTTP_GET) return true;
    char header[8]{};
    if (httpd_req_get_hdr_value_str(req, "X-YetDNS", header, sizeof(header)) != ESP_OK || std::strcmp(header, "1")) {
        error(req, "400 Bad Request", "X-YetDNS: 1 required"); return false;
    }
    return true;
}
static esp_err_t json_send(httpd_req_t *req, cJSON *json) {
    if (!json) return error(req, "503 Service Unavailable", "Out of memory");
    char *body = cJSON_PrintUnformatted(json); cJSON_Delete(json);
    if (!body) return error(req, "503 Service Unavailable", "Out of memory");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    esp_err_t err = httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN); cJSON_free(body); return err;
}
static cJSON *read_json(httpd_req_t *req, size_t limit) {
    if (!req->content_len || req->content_len > limit) { error(req, "413 Content Too Large", "Invalid body size"); return nullptr; }
    auto buffer = std::unique_ptr<char[]>(new (std::nothrow) char[req->content_len + 1]);
    if (!buffer) { error(req, "503 Service Unavailable", "Out of memory"); return nullptr; }
    size_t pos = 0;
    while (pos < req->content_len) {
        int got = httpd_req_recv(req, buffer.get() + pos, req->content_len - pos);
        if (got <= 0) { error(req, "408 Request Timeout", "Incomplete body"); return nullptr; }
        pos += got;
    }
    buffer[pos] = 0;
    cJSON *json = cJSON_ParseWithLengthOpts(buffer.get(), pos + 1, nullptr, true);
    if (!json) error(req, "400 Bad Request", "Invalid JSON");
    return json;
}
static esp_err_t dashboard(httpd_req_t *req) {
    extern const uint8_t html_start[] asm("_binary_dashboard_html_start");
    extern const uint8_t html_end[] asm("_binary_dashboard_html_end");
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(req, "Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-src 'self'; frame-ancestors 'none'; base-uri 'none'");
    return httpd_resp_send(req, reinterpret_cast<const char *>(html_start), html_end - html_start);
}
static esp_err_t get_stats(httpd_req_t *req) {
    if (!authorized(req)) return ESP_OK;
    auto *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "version", esp_app_get_description()->version);
    cJSON_AddStringToObject(json, "transport", doh_enabled.load() ? "DoH" : "UDP + TCP fallback");
    cJSON_AddBoolToObject(json, "blocking", blocking.load());
    cJSON_AddNumberToObject(json, "domains", filter_count());
    cJSON_AddNumberToObject(json, "queries", stats.queries.load());
    cJSON_AddNumberToObject(json, "blocked", stats.blocked.load());
    cJSON_AddNumberToObject(json, "cached", stats.cached.load());
    cJSON_AddNumberToObject(json, "forwarded", stats.forwarded.load());
    cJSON_AddNumberToObject(json, "errors", stats.errors.load());
    cJSON_AddNumberToObject(json, "rate_limited", stats.limited.load());
    cJSON_AddNumberToObject(json, "overload", stats.overload.load());
    cJSON_AddNumberToObject(json, "heap_free", esp_get_free_heap_size());
    cJSON_AddNumberToObject(json, "heap_min", esp_get_minimum_free_heap_size());
    cJSON_AddNumberToObject(json, "internal_heap_free", heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
    cJSON_AddNumberToObject(json, "psram_total", heap_caps_get_total_size(MALLOC_CAP_SPIRAM));
    cJSON_AddNumberToObject(json, "psram_free", heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    cJSON_AddNumberToObject(json, "uptime_s", esp_timer_get_time() / 1000000);
    cJSON_AddBoolToObject(json, "clock_synced", time(nullptr) > 1735689600);
    cJSON_AddNumberToObject(json, "cache_capacity", CONFIG_YETDNS_CACHE_ENTRIES);
    cJSON_AddNumberToObject(json, "pending_capacity", CONFIG_YETDNS_PENDING);
    cJSON_AddBoolToObject(json, "query_logging", query_logging.load());
    cJSON_AddBoolToObject(json, "log_blocked_only", log_blocked_only.load());
    return json_send(req, json);
}
static esp_err_t settings(httpd_req_t *req) {
    if (!authorized(req)) return ESP_OK;
    cJSON *json = read_json(req, 128);
    if (!json) return ESP_OK;
    cJSON *enabled = cJSON_GetObjectItemCaseSensitive(json, "blocking");
    if (!cJSON_IsBool(enabled)) { cJSON_Delete(json); return error(req, "400 Bad Request", "blocking must be boolean"); }
    esp_err_t err = save_blocking(cJSON_IsTrue(enabled)); cJSON_Delete(json);
    if (err != ESP_OK) return error(req, "500 Internal Server Error", "NVS write failed");
    return httpd_resp_sendstr(req, "{}");
}
static esp_err_t clear_cache(httpd_req_t *req) {
    if (!authorized(req)) return ESP_OK;
    flush_cache = true; return httpd_resp_sendstr(req, "{}");
}
static esp_err_t get_rules(httpd_req_t *req) {
    if (!authorized(req)) return ESP_OK;
    auto snapshot = std::unique_ptr<Rules>(new (std::nothrow) Rules{});
    if (!snapshot) return error(req, "503 Service Unavailable", "Out of memory");
    xSemaphoreTake(rules_mutex, portMAX_DELAY); *snapshot = rules; xSemaphoreGive(rules_mutex);
    auto *array = cJSON_CreateArray();
    for (size_t i = 0; i < snapshot->count; ++i) {
        auto &r = snapshot->items[i]; auto *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "domain", r.domain);
        cJSON_AddStringToObject(item, "action", r.action == Action::allow ? "allow" : r.action == Action::deny ? "deny" : "rewrite");
        in_addr addr{}; char address[16];
        addr.s_addr = r.client; inet_ntop(AF_INET, &addr, address, sizeof(address));
        if (r.client) cJSON_AddStringToObject(item, "client", address);
        if (r.action == Action::rewrite) { inet_ntop(AF_INET, r.address, address, sizeof(address)); cJSON_AddStringToObject(item, "address", address); }
        cJSON_AddItemToArray(array, item);
    }
    return json_send(req, array);
}
static esp_err_t put_rules(httpd_req_t *req) {
    if (!authorized(req)) return ESP_OK;
    cJSON *json = read_json(req, 14000);
    if (!json) return ESP_OK;
    auto next = std::unique_ptr<Rules>(new (std::nothrow) Rules{});
    bool valid = next && cJSON_IsArray(json) && cJSON_GetArraySize(json) <= int(rule_max);
    cJSON *item;
    cJSON_ArrayForEach(item, json) {
        if (!valid) break;
        auto *domain = cJSON_GetObjectItemCaseSensitive(item, "domain");
        auto *action = cJSON_GetObjectItemCaseSensitive(item, "action");
        auto *client = cJSON_GetObjectItemCaseSensitive(item, "client");
        auto *address = cJSON_GetObjectItemCaseSensitive(item, "address");
        if (!cJSON_IsString(domain) || !cJSON_IsString(action) || !domain_valid(domain->valuestring)) { valid = false; break; }
        auto &r = next->items[next->count++]; strlcpy(r.domain, domain->valuestring, sizeof(r.domain));
        if (!std::strcmp(action->valuestring, "allow")) r.action = Action::allow;
        else if (!std::strcmp(action->valuestring, "deny")) r.action = Action::deny;
        else if (!std::strcmp(action->valuestring, "rewrite")) r.action = Action::rewrite;
        else { valid = false; break; }
        if (client && (!cJSON_IsString(client) || inet_pton(AF_INET, client->valuestring, &r.client) != 1 || !r.client)) valid = false;
        if (r.action == Action::rewrite && (!cJSON_IsString(address) || inet_pton(AF_INET, address->valuestring, r.address) != 1)) valid = false;
        for (size_t i = 0; i + 1 < next->count; ++i) if (r.client == next->items[i].client && !std::strcmp(r.domain, next->items[i].domain)) valid = false;
    }
    cJSON_Delete(json);
    if (!valid) return error(req, "400 Bad Request", "Expected <=32 unique rules: domain, action allow/deny/rewrite, optional client IPv4, address IPv4 for rewrite");
    esp_err_t err = save_rules(*next);
    if (err != ESP_OK) return error(req, "500 Internal Server Error", esp_err_to_name(err));
    return httpd_resp_sendstr(req, "{}");
}
static esp_err_t get_logs(httpd_req_t *req) {
    if (!authorized(req)) return ESP_OK;
    auto snapshot = std::unique_ptr<LogEntry[]>(new (std::nothrow) LogEntry[32]);
    if (!snapshot) return error(req, "503 Service Unavailable", "Out of memory");
    size_t count = copy_logs(snapshot.get(), 32);
    auto *array = cJSON_CreateArray();
    for (size_t i = 0; i < count; ++i) {
        auto &entry = snapshot[i]; auto *item = cJSON_CreateObject(); char address[16];
        inet_ntop(AF_INET, &entry.client, address, sizeof(address));
        cJSON_AddStringToObject(item, "domain", entry.domain); cJSON_AddStringToObject(item, "client", address);
        cJSON_AddStringToObject(item, "result", entry.result); cJSON_AddNumberToObject(item, "type", entry.type);
        cJSON_AddNumberToObject(item, "elapsed_us", entry.elapsed_us); cJSON_AddItemToArray(array, item);
    }
    return json_send(req, array);
}
static void add_date(cJSON *json, int32_t day) {
    if (day <= 0) return;
    int year; unsigned month, date; char text[16];
    days_to_civil(day, year, month, date);
    std::snprintf(text, sizeof(text), "%04d-%02u-%02u", year, month, date);
    cJSON_AddStringToObject(json, "date", text);
}
static esp_err_t get_top(httpd_req_t *req) {
    if (!authorized(req)) return ESP_OK;
    unsigned offset = 0;
    char query[24], value[8];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK &&
        httpd_query_key_value(query, "day", value, sizeof(value)) == ESP_OK) {
        char *end; unsigned long parsed = std::strtoul(value, &end, 10);
        if (!*value || *end || parsed >= history_days) return error(req, "400 Bad Request", "day must be 0 to 13");
        offset = parsed;
    }
    auto record = std::unique_ptr<DayRecord>(new (std::nothrow) DayRecord{});
    if (!record) return error(req, "503 Service Unavailable", "Out of memory");
    if (!top_day(offset, *record)) return error(req, "404 Not Found", "No statistics for this day");
    auto *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "offset", offset);
    add_date(json, record->day);
    cJSON_AddNumberToObject(json, "queries", record->queries);
    cJSON_AddNumberToObject(json, "blocked", record->blocked);
    cJSON_AddBoolToObject(json, "approximate", record->approximate != 0);
    auto *domains = cJSON_AddArrayToObject(json, "domains");
    for (uint32_t i = 0; i < record->domain_count; ++i) {
        auto *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "domain", record->domains[i].name);
        cJSON_AddNumberToObject(item, "count", record->domains[i].count);
        cJSON_AddItemToArray(domains, item);
    }
    auto *clients = cJSON_AddArrayToObject(json, "clients");
    for (uint32_t i = 0; i < record->client_count; ++i) {
        auto *item = cJSON_CreateObject(); char address[16], name[40];
        inet_ntop(AF_INET, &record->clients[i].ip, address, sizeof(address));
        cJSON_AddStringToObject(item, "ip", address);
        if (top_client_name(record->clients[i].ip, name, sizeof(name))) cJSON_AddStringToObject(item, "name", name);
        cJSON_AddNumberToObject(item, "count", record->clients[i].count);
        cJSON_AddItemToArray(clients, item);
    }
    return json_send(req, json);
}
static esp_err_t get_update(httpd_req_t *req) {
    if (!authorized(req)) return ESP_OK;
    UpdateInfo info; update_snapshot(info);
    auto *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "current", info.current); cJSON_AddStringToObject(json, "latest", info.latest);
    cJSON_AddStringToObject(json, "repo", info.repo); cJSON_AddStringToObject(json, "asset", info.asset);
    cJSON_AddStringToObject(json, "phase", info.phase); cJSON_AddStringToObject(json, "message", info.message);
    cJSON_AddBoolToObject(json, "available", info.available); cJSON_AddBoolToObject(json, "auto_check", info.auto_check);
    cJSON_AddNumberToObject(json, "checked_at", info.checked_at);
    cJSON_AddNumberToObject(json, "downloaded", info.downloaded); cJSON_AddNumberToObject(json, "total", info.total);
    return json_send(req, json);
}
static esp_err_t put_update(httpd_req_t *req) {
    if (!authorized(req)) return ESP_OK;
    cJSON *json = read_json(req, 128);
    if (!json) return ESP_OK;
    cJSON *value = cJSON_GetObjectItemCaseSensitive(json, "auto_check");
    bool valid = cJSON_IsBool(value), enabled = cJSON_IsTrue(value);
    cJSON_Delete(json);
    if (!valid) return error(req, "400 Bad Request", "auto_check must be boolean");
    if (update_set_auto_check(enabled) != ESP_OK) return error(req, "500 Internal Server Error", "NVS write failed");
    return httpd_resp_sendstr(req, "{}");
}
static esp_err_t check_update(httpd_req_t *req) {
    if (!authorized(req)) return ESP_OK;
    if (!update_request_check()) return error(req, "409 Conflict", "An update operation is already running");
    httpd_resp_set_status(req, "202 Accepted"); return httpd_resp_sendstr(req, "{}");
}
static esp_err_t install_update(httpd_req_t *req) {
    if (!authorized(req)) return ESP_OK;
    if (!update_request_install()) return error(req, "409 Conflict", "No verified update is ready to install");
    httpd_resp_set_status(req, "202 Accepted"); return httpd_resp_sendstr(req, "{}");
}
static esp_err_t get_history(httpd_req_t *req) {
    if (!authorized(req)) return ESP_OK;
    auto days = std::unique_ptr<DaySummary[]>(new (std::nothrow) DaySummary[history_days]);
    if (!days) return error(req, "503 Service Unavailable", "Out of memory");
    size_t count = top_history(days.get(), history_days);
    int32_t today = top_today();
    auto *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "clock_synced", today != 0);
    auto *array = cJSON_AddArrayToObject(json, "days");
    for (size_t i = 0; i < count; ++i) {
        auto *item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, "offset", today ? today - days[i].day : 0);
        add_date(item, days[i].day);
        cJSON_AddNumberToObject(item, "queries", days[i].queries);
        cJSON_AddNumberToObject(item, "blocked", days[i].blocked);
        cJSON_AddItemToArray(array, item);
    }
    return json_send(req, json);
}
static bool read_uint(cJSON *json, const char *key, uint32_t &value, uint32_t low, uint32_t high) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, key);
    if (!item) return true;
    if (!cJSON_IsNumber(item) || !std::isfinite(item->valuedouble) || item->valuedouble < low ||
        item->valuedouble > high || std::floor(item->valuedouble) != item->valuedouble) return false;
    value = item->valuedouble; return true;
}
static bool read_bool(cJSON *json, const char *key, bool &value) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, key);
    if (!item) return true;
    if (!cJSON_IsBool(item)) return false;
    value = cJSON_IsTrue(item); return true;
}
static bool read_string(cJSON *json, const char *key, char *value, size_t capacity) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, key);
    if (!item) return true;
    if (!cJSON_IsString(item) || std::strlen(item->valuestring) >= capacity) return false;
    strlcpy(value, item->valuestring, capacity); return true;
}
static esp_err_t get_config(httpd_req_t *req) {
    RuntimeConfig cfg = runtime_snapshot(); auto *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "primary", cfg.primary); cJSON_AddStringToObject(json, "secondary", cfg.secondary);
    cJSON_AddStringToObject(json, "doh_url", cfg.doh_url); cJSON_AddBoolToObject(json, "doh", cfg.doh);
    cJSON_AddBoolToObject(json, "logging", cfg.logging); cJSON_AddBoolToObject(json, "subnet_only", cfg.subnet_only);
    cJSON_AddBoolToObject(json, "block_page", cfg.block_page);
    cJSON_AddNumberToObject(json, "rate_limit", cfg.rate_limit); cJSON_AddNumberToObject(json, "timeout_ms", cfg.timeout_ms);
    return json_send(req, json);
}
static esp_err_t put_config(httpd_req_t *req) {
    if (!authorized(req)) return ESP_OK;
    cJSON *json = read_json(req, 2048); if (!json) return ESP_OK;
    RuntimeConfig cfg = runtime_snapshot();
    bool valid = cJSON_IsObject(json) && read_uint(json, "rate_limit", cfg.rate_limit, 0, 1000) &&
        read_uint(json, "timeout_ms", cfg.timeout_ms, 500, 10000) && read_bool(json, "doh", cfg.doh) &&
        read_bool(json, "logging", cfg.logging) && read_bool(json, "subnet_only", cfg.subnet_only) && read_bool(json, "block_page", cfg.block_page) &&
        read_string(json, "primary", cfg.primary, sizeof(cfg.primary)) && read_string(json, "secondary", cfg.secondary, sizeof(cfg.secondary)) &&
        read_string(json, "doh_url", cfg.doh_url, sizeof(cfg.doh_url)) && runtime_valid(cfg);
    cJSON_Delete(json);
    if (!valid) return error(req, "400 Bad Request", "Invalid advanced DNS settings");
    if (runtime_save(cfg) != ESP_OK) return error(req, "500 Internal Server Error", "NVS write failed");
    flush_cache = true; return httpd_resp_sendstr(req, "{}");
}
static esp_err_t get_lists(httpd_req_t *req) {
    ListsConfig cfg = lists_config(); ListsStatus state = lists_status(); auto *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "automatic", cfg.automatic); cJSON_AddNumberToObject(json, "interval_hours", cfg.interval_hours);
    auto *sources = cJSON_AddArrayToObject(json, "sources");
    for (size_t i = 0; i < cfg.count; ++i) {
        const auto &s = cfg.sources[i]; auto *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "name", s.name); cJSON_AddStringToObject(item, "url", s.url);
        cJSON_AddBoolToObject(item, "enabled", s.enabled); cJSON_AddItemToArray(sources, item);
    }
    auto *status = cJSON_AddObjectToObject(json, "status");
    cJSON_AddBoolToObject(status, "storage", state.storage); cJSON_AddBoolToObject(status, "busy", state.busy);
    cJSON_AddBoolToObject(status, "pending", state.pending); cJSON_AddBoolToObject(status, "outdated", state.outdated);
    cJSON_AddNumberToObject(status, "domains", state.domains); cJSON_AddNumberToObject(status, "generation", state.generation);
    cJSON_AddNumberToObject(status, "last_success", state.last_success); cJSON_AddNumberToObject(status, "next_attempt_s", state.next_attempt_s);
    cJSON_AddNumberToObject(status, "downloaded_bytes", state.downloaded_bytes); cJSON_AddNumberToObject(status, "completed_sources", state.completed_sources);
    cJSON_AddStringToObject(status, "message", state.message);
    return json_send(req, json);
}
static esp_err_t put_lists(httpd_req_t *req) {
    if (!authorized(req)) return ESP_OK;
    cJSON *json = read_json(req, 4096); if (!json) return ESP_OK;
    auto cfg = std::unique_ptr<ListsConfig>(new (std::nothrow) ListsConfig{});
    cJSON *sources = cJSON_GetObjectItemCaseSensitive(json, "sources");
    bool valid = cfg && cJSON_IsObject(json) && cJSON_IsArray(sources) && cJSON_GetArraySize(sources) <= int(list_source_max) &&
        read_uint(json, "interval_hours", cfg->interval_hours, 1, 720) && read_bool(json, "automatic", cfg->automatic);
    cJSON *item;
    cJSON_ArrayForEach(item, sources) {
        if (!valid) break;
        auto &s = cfg->sources[cfg->count++];
        valid = cJSON_IsObject(item) && read_string(item, "name", s.name, sizeof(s.name)) &&
            read_string(item, "url", s.url, sizeof(s.url)) && read_bool(item, "enabled", s.enabled);
    }
    cJSON_Delete(json);
    if (!valid || !lists_valid(*cfg)) return error(req, "400 Bad Request", "Use <=6 distinct HTTPS sources, a name and an interval of 1..720 hours");
    esp_err_t err = lists_save(*cfg);
    if (err != ESP_OK) return error(req, "500 Internal Server Error", "Cannot save list settings; check storage status");
    return httpd_resp_sendstr(req, "{}");
}
static esp_err_t update_lists(httpd_req_t *req) {
    if (!authorized(req)) return ESP_OK;
    lists_request_update(); httpd_resp_set_status(req, "202 Accepted"); return httpd_resp_sendstr(req, "{}");
}
static esp_err_t erase_logs(httpd_req_t *req) {
    if (!authorized(req)) return ESP_OK;
    clear_logs(); return httpd_resp_sendstr(req, "{}");
}
static esp_err_t configure_logs(httpd_req_t *req) {
    if (!authorized(req)) return ESP_OK;
    cJSON *json = read_json(req, 128); if (!json) return ESP_OK;
    auto *value = cJSON_GetObjectItemCaseSensitive(json, "blocked_only");
    if (!cJSON_IsObject(json) || !cJSON_IsBool(value)) {
        cJSON_Delete(json); return error(req, "400 Bad Request", "blocked_only must be boolean");
    }
    bool only_blocks = cJSON_IsTrue(value); cJSON_Delete(json);
    nvs_handle_t handle;
    esp_err_t err = nvs_open("yetdns", NVS_READWRITE, &handle);
    if (err == ESP_OK) {
        err = nvs_set_u8(handle, "log_only", only_blocks);
        if (err == ESP_OK) err = nvs_commit(handle);
        nvs_close(handle);
    }
    if (err != ESP_OK) return error(req, "500 Internal Server Error", esp_err_to_name(err));
    set_log_blocked_only(only_blocks); return httpd_resp_sendstr(req, "{}");
}
static esp_err_t get_mqtt(httpd_req_t *req) {
    auto cfg = mqtt_config(); auto *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "enabled", cfg.enabled); cJSON_AddBoolToObject(json, "connected", mqtt_connected());
    cJSON_AddStringToObject(json, "uri", cfg.uri); cJSON_AddStringToObject(json, "username", cfg.username);
    cJSON_AddBoolToObject(json, "password_set", cfg.password[0] != 0);
    cJSON_AddStringToObject(json, "discovery_prefix", cfg.discovery_prefix); cJSON_AddNumberToObject(json, "interval_s", cfg.interval_s);
    cJSON_AddStringToObject(json, "device_id", mqtt_device_id()); return json_send(req, json);
}
static esp_err_t put_mqtt(httpd_req_t *req) {
    if (!authorized(req)) return ESP_OK;
    cJSON *json = read_json(req, 2048); if (!json) return ESP_OK;
    auto cfg = mqtt_config(); bool clear = false;
    bool valid = cJSON_IsObject(json) && read_bool(json, "enabled", cfg.enabled) && read_bool(json, "clear_password", clear) &&
        read_uint(json, "interval_s", cfg.interval_s, 5, 300) && read_string(json, "uri", cfg.uri, sizeof(cfg.uri)) &&
        read_string(json, "username", cfg.username, sizeof(cfg.username)) &&
        read_string(json, "discovery_prefix", cfg.discovery_prefix, sizeof(cfg.discovery_prefix));
    auto *password = cJSON_GetObjectItemCaseSensitive(json, "password");
    if (password) {
        if (!cJSON_IsString(password) || std::strlen(password->valuestring) >= sizeof(cfg.password)) valid = false;
        else if (password->valuestring[0]) strlcpy(cfg.password, password->valuestring, sizeof(cfg.password));
    }
    if (clear) cfg.password[0] = 0;
    cJSON_Delete(json);
    if (!valid || !mqtt_valid(cfg)) return error(req, "400 Bad Request", "Invalid MQTT settings; use mqtt:// or mqtts:// and separate credentials");
    if (mqtt_save(cfg) != ESP_OK) return error(req, "500 Internal Server Error", "Cannot save MQTT settings");
    return httpd_resp_sendstr(req, "{}");
}
static void add_app_ids(cJSON *array, uint64_t mask) {
    for (size_t i = 0; i < application_count(); ++i) if (mask & (UINT64_C(1) << i))
        cJSON_AddItemToArray(array, cJSON_CreateString(application_at(i).id));
}
static esp_err_t get_apps(httpd_req_t *req) {
    auto cfg = apps_config(); auto *json = cJSON_CreateObject();
    auto *catalog = cJSON_AddArrayToObject(json, "catalog");
    for (size_t i = 0; i < application_count(); ++i) {
        const auto &app = application_at(i); auto *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "id", app.id); cJSON_AddStringToObject(item, "name", app.name);
        cJSON_AddStringToObject(item, "category", app.category); cJSON_AddNumberToObject(item, "domains", app.domains);
        cJSON_AddItemToArray(catalog, item);
    }
    add_app_ids(cJSON_AddArrayToObject(json, "blocked"), cfg.blocked);
    auto *clients = cJSON_AddArrayToObject(json, "clients");
    for (size_t i = 0; i < cfg.count; ++i) {
        auto *item = cJSON_CreateObject(); char address[16]; in_addr addr{}; addr.s_addr = cfg.clients[i].address;
        inet_ntop(AF_INET, &addr, address, sizeof(address)); cJSON_AddStringToObject(item, "client", address);
        add_app_ids(cJSON_AddArrayToObject(item, "blocked"), cfg.clients[i].blocked);
        cJSON_AddItemToArray(clients, item);
    }
    cJSON_AddNumberToObject(json, "client_limit", app_client_max);
    cJSON_AddStringToObject(json, "source", "https://github.com/nextdns/services");
    return json_send(req, json);
}
static esp_err_t put_apps(httpd_req_t *req) {
    if (!authorized(req)) return ESP_OK;
    cJSON *json = read_json(req, 4096); if (!json) return ESP_OK;
    auto *ids = cJSON_GetObjectItemCaseSensitive(json, "blocked");
    auto *client = cJSON_GetObjectItemCaseSensitive(json, "client");
    uint32_t address = 0; uint64_t mask = 0;
    bool valid = cJSON_IsObject(json) && cJSON_IsArray(ids) && cJSON_GetArraySize(ids) <= int(application_count());
    if (client) {
        if (!cJSON_IsString(client)) valid = false;
        else if (client->valuestring[0] && (inet_pton(AF_INET, client->valuestring, &address) != 1 || !address || address == INADDR_NONE)) valid = false;
    }
    cJSON *item;
    cJSON_ArrayForEach(item, ids) {
        int index = cJSON_IsString(item) ? application_index(item->valuestring) : -1;
        if (index < 0 || (mask & (UINT64_C(1) << index))) { valid = false; break; }
        mask |= UINT64_C(1) << index;
    }
    cJSON_Delete(json);
    if (!valid) return error(req, "400 Bad Request", "Expected known unique application IDs in blocked and optional client IPv4");
    esp_err_t err = apps_save_scope(address, mask);
    if (err == ESP_ERR_INVALID_ARG) return error(req, "400 Bad Request", "At most 16 per-device application profiles");
    if (err != ESP_OK) return error(req, "500 Internal Server Error", "Cannot save application settings");
    return httpd_resp_sendstr(req, "{}");
}
static bool local_admin_host(httpd_req_t *req) {
    char host[256]{};
    if (httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host)) != ESP_OK) return false;
    char *port = std::strchr(host, ':');
    if (port) *port = 0;
    if (!strcasecmp(host, "yetdns") || !strcasecmp(host, "yetdns.local")) return true;
    in_addr address{};
    return inet_pton(AF_INET, host, &address) == 1 && address.s_addr == subnet_ip.load();
}
static esp_err_t blocked_page(httpd_req_t *req) {
    extern const uint8_t page_start[] asm("_binary_blocked_html_start");
    extern const uint8_t page_end[] asm("_binary_blocked_html_end");
    httpd_resp_set_status(req, "403 Forbidden");
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(req, "Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'");
    return httpd_resp_send(req, reinterpret_cast<const char *>(page_start), page_end - page_start);
}
struct Route { const char *path; httpd_method_t method; esp_err_t (*handler)(httpd_req_t *); };
static esp_err_t diagnostic_page(httpd_req_t *req) {
    extern const uint8_t diagnostic_html_start[] asm("_binary_diagnostic_html_start");
    extern const uint8_t diagnostic_html_end[] asm("_binary_diagnostic_html_end");
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(req, "Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self' https:; frame-ancestors 'self'; base-uri 'none'");
    return httpd_resp_send(req, reinterpret_cast<const char *>(diagnostic_html_start), diagnostic_html_end - diagnostic_html_start);
}
static esp_err_t diagnostic_script(httpd_req_t *req) {
    extern const uint8_t diagnostic_js_start[] asm("_binary_diagnostic_js_start");
    extern const uint8_t diagnostic_js_end[] asm("_binary_diagnostic_js_end");
    httpd_resp_set_type(req, "application/javascript; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    return httpd_resp_send(req, reinterpret_cast<const char *>(diagnostic_js_start), diagnostic_js_end - diagnostic_js_start);
}
static esp_err_t dispatch(httpd_req_t *req) {
    // Old DNS answers may still point here after the option is disabled.
    if (!local_admin_host(req)) return blocked_page(req);
    return static_cast<const Route *>(req->user_ctx)->handler(req);
}
static esp_err_t not_found(httpd_req_t *req, httpd_err_code_t) {
    if (!local_admin_host(req)) return blocked_page(req);
    return error(req, "404 Not Found", "Not found");
}
esp_err_t admin_start() {
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG(); cfg.max_uri_handlers = 32;
    cfg.stack_size = 8192; cfg.lru_purge_enable = true; cfg.max_open_sockets = 3;
    cfg.recv_wait_timeout = 3; cfg.send_wait_timeout = 3;
    httpd_handle_t server;
    esp_err_t err = httpd_start(&server, &cfg);
    if (err != ESP_OK) return err;
    static const Route routes[] = {
        {"/", HTTP_GET, dashboard},
        {"/diagnostic", HTTP_GET, diagnostic_page},
        {"/diagnostic.js", HTTP_GET, diagnostic_script},
        {"/api/stats", HTTP_GET, get_stats},
        {"/api/settings", HTTP_POST, settings},
        {"/api/cache/flush", HTTP_POST, clear_cache},
        {"/api/rules", HTTP_GET, get_rules},
        {"/api/rules", HTTP_PUT, put_rules},
        {"/api/update", HTTP_GET, get_update},
        {"/api/update", HTTP_PUT, put_update},
        {"/api/update/check", HTTP_POST, check_update},
        {"/api/update/install", HTTP_POST, install_update},
        {"/api/top", HTTP_GET, get_top},
        {"/api/history", HTTP_GET, get_history},
        {"/api/logs", HTTP_GET, get_logs},
        {"/api/logs/clear", HTTP_POST, erase_logs},
        {"/api/logs/config", HTTP_PUT, configure_logs},
        {"/api/config", HTTP_GET, get_config},
        {"/api/config", HTTP_PUT, put_config},
        {"/api/lists", HTTP_GET, get_lists},
        {"/api/lists", HTTP_PUT, put_lists},
        {"/api/lists/update", HTTP_POST, update_lists},
        {"/api/mqtt", HTTP_GET, get_mqtt},
        {"/api/mqtt", HTTP_PUT, put_mqtt},
        {"/api/apps", HTTP_GET, get_apps},
        {"/api/apps", HTTP_PUT, put_apps},
    };
    for (const auto &route : routes) {
        httpd_uri_t uri{}; uri.uri = route.path; uri.method = route.method; uri.handler = dispatch; uri.user_ctx = const_cast<Route *>(&route);
        err = httpd_register_uri_handler(server, &uri); if (err != ESP_OK) return err;
    }
    return httpd_register_err_handler(server, HTTPD_404_NOT_FOUND, not_found);
}
} // namespace yetdns
