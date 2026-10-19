#include "stats.hpp"
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <memory>
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "nvs.h"

namespace yetdns {
namespace {
constexpr uint32_t valid_time = 1735689600; // same "clock is synchronized" threshold as the rest of the firmware
constexpr uint32_t save_interval_s = 600, name_retry_s = 600, name_refresh_s = 3600;
constexpr size_t name_slots = 32, name_max = 40;
struct NameEntry { uint32_t ip{}, tried_s{}; char name[name_max]{}; };

TopEntry domain_slots[top_domain_slots], client_slots[top_client_slots];
TopTable domains(domain_slots, top_domain_slots), clients(client_slots, top_client_slots);
NameEntry names[name_slots];
size_t name_next;
SemaphoreHandle_t lock;
std::atomic<uint32_t> day_queries{}, day_blocked{};
int32_t live_day;             // 0 until the clock first becomes valid
DayRecord *pending;           // newest record found in flash at boot, applied once the day is known
uint32_t uptime() { return esp_timer_get_time() / 1000000; }
void key_for(int32_t day, char *key) { std::snprintf(key, 8, "d%u", unsigned(day) % unsigned(history_days)); }

bool persist(const DayRecord &record) {
    nvs_handle_t handle; char key[8];
    if (nvs_open_from_partition("listscfg", "topstats", NVS_READWRITE, &handle) != ESP_OK) return false;
    key_for(record.day, key);
    esp_err_t err = nvs_set_blob(handle, key, &record, sizeof(record));
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    if (err != ESP_OK) ESP_LOGW("yetdns", "Statistics write failed: %s", esp_err_to_name(err));
    return err == ESP_OK;
}
bool load(int32_t day, DayRecord &record) {
    nvs_handle_t handle; char key[8];
    if (nvs_open_from_partition("listscfg", "topstats", NVS_READONLY, &handle) != ESP_OK) return false;
    key_for(day, key);
    size_t size = sizeof(record);
    bool ok = nvs_get_blob(handle, key, &record, &size) == ESP_OK && size == sizeof(record) &&
        day_record_valid(record) && record.day == day;
    nvs_close(handle); return ok;
}
// Caller holds `lock`.
void build_live(DayRecord &record) {
    record = {};
    record.day = live_day; record.queries = day_queries.load(); record.blocked = day_blocked.load();
    record.approximate = domains.approximate() || clients.approximate();
    TopRow rows[top_n];
    size_t n = domains.top(rows, top_n);
    for (size_t i = 0; i < n; ++i) { std::memcpy(record.domains[i].name, rows[i].name, top_name_max); record.domains[i].count = rows[i].count; }
    record.domain_count = n;
    n = clients.top(rows, top_n);
    for (size_t i = 0; i < n; ++i) { record.clients[i] = {rows[i].id, rows[i].count}; }
    record.client_count = n;
}
void maintain_day() {
    int32_t today = top_today();
    if (!today) return;
    auto record = std::unique_ptr<DayRecord>(new (std::nothrow) DayRecord{});
    if (!record) return;
    static uint32_t last_save_s;
    bool save = false;
    xSemaphoreTake(lock, portMAX_DELAY);
    if (!live_day) {
        // First valid clock: the counters collected so far belong to today, plus whatever survived a reboot.
        live_day = today;
        if (pending && pending->day == today) {
            for (uint32_t i = 0; i < pending->domain_count; ++i)
                domains.hit(top_hash(pending->domains[i].name), pending->domains[i].name, pending->domains[i].count);
            for (uint32_t i = 0; i < pending->client_count; ++i) clients.hit(pending->clients[i].ip, nullptr, pending->clients[i].count);
            day_queries += pending->queries; day_blocked += pending->blocked;
            domains.mark_approximate();
        }
        delete pending; pending = nullptr; last_save_s = uptime();
    } else if (today != live_day) {
        build_live(*record);
        domains.clear(); clients.clear(); day_queries = 0; day_blocked = 0; live_day = today;
        save = true;
    } else if (uptime() - last_save_s >= save_interval_s) {
        build_live(*record); save = true;
    }
    xSemaphoreGive(lock);
    if (save) { persist(*record); last_save_s = uptime(); }
}
bool lookup_mdns(uint32_t ip, char *name, size_t capacity) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    timeval timeout{0, 100000}; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    int ttl = 255; setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    uint16_t id = esp_random(); if (!id) id = 1;
    uint8_t query[64], answer[512];
    size_t query_n = mdns_ptr_query(ip, id, query, sizeof(query));
    bool found = false;
    // First the multicast group, then the device itself: both are accepted by common responders.
    for (int attempt = 0; attempt < 2 && query_n && !found; ++attempt) {
        sockaddr_in dest{}; dest.sin_family = AF_INET; dest.sin_port = htons(5353);
        dest.sin_addr.s_addr = attempt ? ip : htonl(0xe00000fb);
        sendto(fd, query, query_n, 0, reinterpret_cast<sockaddr *>(&dest), sizeof(dest));
        for (int64_t end = esp_timer_get_time() + 300000; !found && esp_timer_get_time() < end;) {
            sockaddr_in from{}; socklen_t from_n = sizeof(from);
            int got = recvfrom(fd, answer, sizeof(answer), 0, reinterpret_cast<sockaddr *>(&from), &from_n);
            if (got > 0 && from.sin_addr.s_addr == ip) found = mdns_ptr_answer(answer, got, id, name, capacity);
        }
    }
    close(fd); return found;
}
void resolve_names() {
    uint32_t candidates[2]; size_t count = 0;
    TopRow rows[top_n]; size_t n;
    xSemaphoreTake(lock, portMAX_DELAY);
    n = clients.top(rows, top_n);
    for (size_t i = 0; i < n && count < 2; ++i) {
        uint32_t ip = rows[i].id;
        if (!ip) continue;
        const NameEntry *entry = nullptr;
        for (const auto &e : names) if (e.ip == ip) entry = &e;
        uint32_t wait = !entry ? 0 : entry->name[0] ? name_refresh_s : name_retry_s;
        if (!entry || uptime() - entry->tried_s >= wait) candidates[count++] = ip;
    }
    xSemaphoreGive(lock);
    for (size_t i = 0; i < count; ++i) {
        char name[name_max] = "";
        bool found = lookup_mdns(candidates[i], name, sizeof(name));
        xSemaphoreTake(lock, portMAX_DELAY);
        NameEntry *entry = nullptr;
        for (auto &e : names) if (e.ip == candidates[i]) entry = &e;
        if (!entry) { entry = &names[name_next++ % name_slots]; *entry = {}; entry->ip = candidates[i]; }
        entry->tried_s = uptime();
        if (found) std::strncpy(entry->name, name, name_max - 1);
        xSemaphoreGive(lock);
    }
}
void housekeeping(void *) {
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(5000));
        maintain_day();
        resolve_names();
    }
}
} // namespace

int32_t top_today() {
    time_t now = time(nullptr);
    if (now < valid_time) return 0;
    tm local{}; localtime_r(&now, &local);
    return civil_to_days(local.tm_year + 1900, local.tm_mon + 1, local.tm_mday);
}
void top_init() {
    lock = xSemaphoreCreateMutex();
    configASSERT(lock);
    auto newest = std::unique_ptr<DayRecord>(new (std::nothrow) DayRecord{});
    auto candidate = std::unique_ptr<DayRecord>(new (std::nothrow) DayRecord{});
    if (!newest || !candidate) return;
    nvs_handle_t handle;
    if (nvs_open_from_partition("listscfg", "topstats", NVS_READONLY, &handle) != ESP_OK) return;
    for (size_t i = 0; i < history_days; ++i) {
        char key[8]; std::snprintf(key, sizeof(key), "d%u", unsigned(i));
        size_t size = sizeof(DayRecord);
        if (nvs_get_blob(handle, key, candidate.get(), &size) == ESP_OK && size == sizeof(DayRecord) &&
            day_record_valid(*candidate) && candidate->day > newest->day) *newest = *candidate;
    }
    nvs_close(handle);
    if (newest->day) pending = newest.release();
}
esp_err_t top_start() {
    return xTaskCreate(housekeeping, "stats", 5120, nullptr, 2, nullptr) == pdPASS ? ESP_OK : ESP_ERR_NO_MEM;
}
void top_query() { ++day_queries; }
void top_block(const char *domain, uint32_t client) {
    ++day_blocked;
    char key[top_name_max];
    strlcpy(key, domain, sizeof(key));
    xSemaphoreTake(lock, portMAX_DELAY);
    domains.hit(top_hash(key), key);
    clients.hit(client, nullptr);
    xSemaphoreGive(lock);
}
bool top_day(unsigned offset, DayRecord &record) {
    if (offset >= history_days) return false;
    if (!offset) {
        xSemaphoreTake(lock, portMAX_DELAY); build_live(record); xSemaphoreGive(lock);
        return true;
    }
    int32_t today = top_today();
    return today && load(today - int32_t(offset), record);
}
size_t top_history(DaySummary *out, size_t capacity) {
    auto record = std::unique_ptr<DayRecord>(new (std::nothrow) DayRecord{});
    if (!record || !capacity) return 0;
    size_t count = 0;
    top_day(0, *record);
    out[count++] = {record->day, record->queries, record->blocked};
    int32_t today = top_today();
    for (unsigned offset = 1; today && offset < history_days && count < capacity; ++offset)
        if (load(today - int32_t(offset), *record)) out[count++] = {record->day, record->queries, record->blocked};
    return count;
}
bool top_client_name(uint32_t ip, char *name, size_t capacity) {
    bool found = false;
    xSemaphoreTake(lock, portMAX_DELAY);
    for (const auto &e : names) if (e.ip == ip && e.name[0]) { strlcpy(name, e.name, capacity); found = true; }
    xSemaphoreGive(lock);
    return found;
}
} // namespace yetdns
