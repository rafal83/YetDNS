#include "lists.hpp"
#include "list_builder.hpp"
#include "service.hpp"
#include <algorithm>
#include <cstring>
#include <ctime>
#include <memory>
#include "esp_crt_bundle.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_timer.h"
#include "freertos/task.h"
#include "nvs_flash.h"

namespace yetdns {
static SemaphoreHandle_t mutex, filter_mutex;
static ListsConfig config;
static ListsStatus status;
static Blocklist remote;
static bool use_remote{};
static const esp_partition_t *slots[2]{};
static int active_slot = -1;
static esp_partition_mmap_handle_t active_map{};
static uint32_t active_signature{};
static TaskHandle_t updater;
static std::atomic<bool> requested{false};
static std::atomic<uint32_t> next_attempt{};
constexpr uint32_t slot_magic = 0x594c5354;
constexpr size_t image_offset = 64;
struct SlotHeader { uint32_t magic, version, generation, size, signature, updated, crc, reserved; };
static uint32_t uptime() { return esp_timer_get_time() / 1000000; }
static uint32_t signature(const ListsConfig &cfg) {
    uint32_t crc = 0;
    for (size_t i = 0; i < cfg.count; ++i) if (cfg.sources[i].enabled)
        crc = list_crc32(crc, reinterpret_cast<const uint8_t *>(cfg.sources[i].url), std::strlen(cfg.sources[i].url) + 1);
    return crc;
}
static size_t enabled_count(const ListsConfig &cfg) {
    size_t count = 0; for (size_t i = 0; i < cfg.count; ++i) count += cfg.sources[i].enabled; return count;
}
static void message(const char *text) {
    xSemaphoreTake(mutex, portMAX_DELAY); strlcpy(status.message, text, sizeof(status.message)); xSemaphoreGive(mutex);
    ESP_LOGW("lists", "%s", text);
}
ListsConfig lists_config() {
    xSemaphoreTake(mutex, portMAX_DELAY); ListsConfig value = config; xSemaphoreGive(mutex); return value;
}
ListsStatus lists_status() {
    xSemaphoreTake(mutex, portMAX_DELAY); ListsStatus value = status;
    value.pending = requested.load(); value.next_attempt_s = next_attempt > uptime() ? next_attempt - uptime() : 0;
    value.outdated = enabled_count(config) && active_signature != signature(config);
    xSemaphoreGive(mutex); value.domains = filter_count(); return value;
}
bool filter_contains(const char *name) {
    if (!filter_mutex) return blocklist.contains(name);
    xSemaphoreTake(filter_mutex, portMAX_DELAY);
    bool found = use_remote ? remote.contains(name) : blocklist.contains(name);
    xSemaphoreGive(filter_mutex); return found;
}
uint32_t filter_count() {
    if (!filter_mutex) return blocklist.count();
    xSemaphoreTake(filter_mutex, portMAX_DELAY); uint32_t count = use_remote ? remote.count() : blocklist.count();
    xSemaphoreGive(filter_mutex); return count;
}
bool lists_valid(const ListsConfig &cfg) {
    if (cfg.version != 1 || cfg.count > list_source_max || cfg.interval_hours < 1 || cfg.interval_hours > 720) return false;
    for (size_t i = 0; i < cfg.count; ++i) {
        const auto &s = cfg.sources[i];
        if (!std::memchr(s.name, 0, sizeof(s.name)) || !s.name[0] || !std::memchr(s.url, 0, sizeof(s.url)) ||
            std::strncmp(s.url, "https://", 8) || std::strlen(s.url) <= 8 || std::strpbrk(s.url, "\r\n\t ")) return false;
        for (size_t j = 0; j < i; ++j) if (!std::strcmp(s.url, cfg.sources[j].url)) return false;
    }
    return true;
}
void lists_request_update() { requested = true; if (updater) xTaskNotifyGive(updater); }
esp_err_t lists_save(const ListsConfig &value) {
    if (!lists_valid(value)) return ESP_ERR_INVALID_ARG;
    if (!status.storage) return ESP_ERR_NOT_SUPPORTED;
    nvs_handle_t handle;
    esp_err_t err = nvs_open_from_partition("listscfg", "lists", NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(handle, "config", &value, sizeof(value));
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    if (err == ESP_OK) {
        xSemaphoreTake(mutex, portMAX_DELAY); config = value; next_attempt = 0; xSemaphoreGive(mutex);
        lists_request_update();
    }
    return err;
}
static bool read_header(int index, SlotHeader &h) {
    return slots[index] && esp_partition_read(slots[index], 0, &h, sizeof(h)) == ESP_OK &&
        h.magic == slot_magic && h.version == 1 && h.generation && h.size >= 24 &&
        h.size <= slots[index]->size - image_offset &&
        h.crc == list_crc32(0, reinterpret_cast<const uint8_t *>(&h.version), 20);
}
static bool map_image(int index, size_t size, Blocklist &view, esp_partition_mmap_handle_t &handle) {
    const void *data = nullptr;
    if (esp_partition_mmap(slots[index], 0, image_offset + size, ESP_PARTITION_MMAP_DATA, &data, &handle) != ESP_OK) return false;
    if (!view.load(static_cast<const uint8_t *>(data) + image_offset, size)) { esp_partition_munmap(handle); return false; }
    return true;
}
esp_err_t lists_init() {
    mutex = xSemaphoreCreateMutex(); filter_mutex = xSemaphoreCreateMutex();
    if (!mutex || !filter_mutex) return ESP_ERR_NO_MEM;
    config.count = 3;
    const char *names[] = {"HaGeZi Light", "HaGeZi Normal", "StevenBlack"};
    const char *urls[] = {"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi-onlydomains.txt",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"};
    for (size_t i = 0; i < 3; ++i) { strlcpy(config.sources[i].name, names[i], sizeof(config.sources[i].name)); strlcpy(config.sources[i].url, urls[i], sizeof(config.sources[i].url)); }
    config.sources[0].enabled = true;
    slots[0] = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "list_a");
    slots[1] = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "list_b");
    if (!slots[0] || !slots[1] || nvs_flash_init_partition("listscfg") != ESP_OK) {
        message("List storage unavailable; use the new partition table"); return ESP_OK;
    }
    status.storage = true;
    nvs_handle_t handle;
    if (nvs_open_from_partition("listscfg", "lists", NVS_READONLY, &handle) == ESP_OK) {
        auto stored = std::unique_ptr<ListsConfig>(new (std::nothrow) ListsConfig{}); size_t len = sizeof(ListsConfig);
        if (stored && nvs_get_blob(handle, "config", stored.get(), &len) == ESP_OK && len == sizeof(ListsConfig) && lists_valid(*stored)) config = *stored;
        nvs_close(handle);
    }
    SlotHeader headers[2]; bool valid[2] = {read_header(0, headers[0]), read_header(1, headers[1])};
    int first = valid[1] && (!valid[0] || int32_t(headers[1].generation - headers[0].generation) > 0) ? 1 : 0;
    for (int attempt = 0; attempt < 2; ++attempt) {
        int index = attempt ? 1 - first : first;
        if (!valid[index]) continue;
        if (map_image(index, headers[index].size, remote, active_map)) {
            active_slot = index; active_signature = headers[index].signature;
            status.generation = headers[index].generation; status.last_success = headers[index].updated;
            use_remote = enabled_count(config) > 0;
            break;
        }
    }
    strlcpy(status.message, use_remote ? "Stored list loaded" : "Waiting for first list download", sizeof(status.message));
    return ESP_OK;
}
struct HttpHeaders { bool rejected{}; };
static esp_err_t header_event(esp_http_client_event_t *event) {
    if (event->event_id != HTTP_EVENT_ON_HEADER) return ESP_OK;
    auto *h = static_cast<HttpHeaders *>(event->user_data);
    if (!strcasecmp(event->header_key, "Content-Encoding") && strcasecmp(event->header_value, "identity")) h->rejected = true;
    if (!strcasecmp(event->header_key, "Content-Type") && (strstr(event->header_value, "text/html") || strstr(event->header_value, "application/json"))) h->rejected = true;
    return ESP_OK;
}
static bool download(const ListSource &source, ListBuilder &builder) {
    HttpHeaders headers;
    esp_http_client_config_t cfg{}; cfg.url = source.url; cfg.timeout_ms = 15000;
    cfg.crt_bundle_attach = esp_crt_bundle_attach; cfg.disable_auto_redirect = true;
    cfg.event_handler = header_event; cfg.user_data = &headers;
    auto client = esp_http_client_init(&cfg);
    if (!client) { message("Not enough memory for HTTPS"); return false; }
    esp_http_client_set_header(client, "Accept-Encoding", "identity");
    esp_http_client_set_header(client, "Accept", "text/plain, application/octet-stream");
    esp_err_t err = esp_http_client_open(client, 0);
    int64_t declared = err == ESP_OK ? esp_http_client_fetch_headers(client) : -1;
    bool okay = err == ESP_OK && esp_http_client_get_status_code(client) == 200 && !headers.rejected && declared <= 12 * 1024 * 1024;
    size_t received = 0, before = builder.accepted(); uint8_t buffer[2048];
    int64_t deadline = esp_timer_get_time() + 180000000;
    while (okay) {
        int n = esp_http_client_read(client, reinterpret_cast<char *>(buffer), sizeof(buffer));
        if (n < 0) { okay = false; break; }
        if (!n) break;
        received += n;
        if (received > 12 * 1024 * 1024 || esp_timer_get_time() > deadline || !builder.feed(buffer, n)) { okay = false; break; }
        xSemaphoreTake(mutex, portMAX_DELAY); status.downloaded_bytes += n; xSemaphoreGive(mutex);
        if ((received & 65535) < sizeof(buffer)) vTaskDelay(1);
    }
    okay = okay && received && esp_http_client_is_complete_data_received(client) && builder.finish_source() && builder.accepted() > before;
    esp_http_client_cleanup(client);
    if (!okay) {
        char text[192]; snprintf(text, sizeof(text), "%s: %s", source.name, builder.error()[0] ? builder.error() : "HTTPS download failed, empty or incomplete list"); message(text);
    }
    return okay;
}
static void yield_work(void *) { vTaskDelay(1); }
struct Writer { const esp_partition_t *partition; };
static bool write_image(size_t offset, const uint8_t *data, size_t size, void *context) {
    auto *writer = static_cast<Writer *>(context);
    size_t aligned = size & ~size_t(3);
    if (aligned && esp_partition_write(writer->partition, image_offset + offset, data, aligned) != ESP_OK) return false;
    if (size != aligned) {
        uint8_t tail[4] = {255, 255, 255, 255}; std::memcpy(tail, data + aligned, size - aligned);
        if (esp_partition_write(writer->partition, image_offset + offset + aligned, tail, 4) != ESP_OK) return false;
    }
    return true;
}
static bool update(const ListsConfig &cfg) {
    if (!enabled_count(cfg)) {
        xSemaphoreTake(filter_mutex, portMAX_DELAY); use_remote = false; xSemaphoreGive(filter_mutex);
        flush_cache = true; message("No remote list selected; built-in list active"); return true;
    }
    size_t available = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    uint32_t caps = MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT;
    if (!available) { available = std::min<size_t>(65536, heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT) / 3); caps = MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT; }
    size_t budget = available > 1024 * 1024 ? std::min<size_t>(available - 512 * 1024, 7168 * 1024) : available;
    size_t table_slots = 64;
    while (table_slots < 524288 && table_slots * 2 * 4 <= budget / 3) table_slots *= 2;
    size_t pool_size = budget > table_slots * 4 ? budget - table_slots * 4 : 0;
    if (pool_size < 1024) { message("Not enough memory to prepare lists"); return false; }
    auto pool = std::unique_ptr<char, decltype(&heap_caps_free)>(static_cast<char *>(heap_caps_malloc(pool_size, caps)), heap_caps_free);
    auto table = std::unique_ptr<uint32_t, decltype(&heap_caps_free)>(static_cast<uint32_t *>(heap_caps_malloc(table_slots * 4, caps)), heap_caps_free);
    if (!pool || !table) { message("Cannot reserve list workspace; previous list retained"); return false; }
    auto builder = std::unique_ptr<ListBuilder>(new (std::nothrow) ListBuilder(pool.get(), pool_size, table.get(), table_slots, yield_work));
    if (!builder) { message("Not enough memory for list parser"); return false; }
    for (size_t i = 0; i < cfg.count; ++i) if (cfg.sources[i].enabled) {
        char text[192]; snprintf(text, sizeof(text), "Downloading %s", cfg.sources[i].name); message(text);
        if (!download(cfg.sources[i], *builder)) return false;
        xSemaphoreTake(mutex, portMAX_DELAY); ++status.completed_sources; xSemaphoreGive(mutex);
    }
    int target = active_slot == 0 ? 1 : 0;
    size_t size = builder->image_size();
    if (size > slots[target]->size - image_offset) { message("Merged list exceeds flash capacity; previous list retained"); return false; }
    if (signature(lists_config()) != signature(cfg)) { message("Sources changed; update rescheduled"); return false; }
    message("Writing and verifying inactive list");
    size_t erase_size = (image_offset + size + 4095) & ~size_t(4095);
    for (size_t offset = 0; offset < erase_size; offset += 65536) {
        size_t amount = std::min<size_t>(65536, erase_size - offset);
        if (esp_partition_erase_range(slots[target], offset, amount) != ESP_OK) { message("Flash erase failed; previous list retained"); return false; }
        vTaskDelay(1);
    }
    Writer writer{slots[target]};
    if (!builder->write(write_image, &writer)) { message("Flash write failed; previous list retained"); return false; }
    // Free the preparation buffers before mapping and validating the result.
    builder.reset(); table.reset(); pool.reset();
    auto candidate = std::unique_ptr<Blocklist>(new (std::nothrow) Blocklist{}); esp_partition_mmap_handle_t map;
    if (!candidate || !map_image(target, size, *candidate, map)) { message("List CRC validation failed; previous list retained"); return false; }
    SlotHeader header{0xffffffffu, 1, status.generation + 1, uint32_t(size), signature(cfg), uint32_t(time(nullptr)), 0, 0};
    header.crc = list_crc32(0, reinterpret_cast<const uint8_t *>(&header.version), 20);
    xSemaphoreTake(mutex, portMAX_DELAY);
    bool unchanged = signature(config) == signature(cfg);
    // Metadata body first, commit word last: interrupted writes never replace the old slot.
    bool committed = unchanged && esp_partition_write(slots[target], 4, &header.version, sizeof(header) - 4) == ESP_OK &&
        esp_partition_write(slots[target], 0, &slot_magic, 4) == ESP_OK;
    if (committed) {
        status.generation = header.generation; status.last_success = header.updated; active_signature = header.signature;
    }
    xSemaphoreGive(mutex);
    if (!committed) { esp_partition_munmap(map); message("Commit failed or sources changed; previous list retained"); return false; }
    xSemaphoreTake(filter_mutex, portMAX_DELAY);
    int old_slot = active_slot; auto old_map = active_map;
    remote = *candidate; use_remote = true; active_slot = target; active_map = map;
    xSemaphoreGive(filter_mutex);
    if (old_slot >= 0) esp_partition_munmap(old_map);
    flush_cache = true; message("Lists updated successfully"); return true;
}
static void update_task(void *) {
    for (;;) {
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(1000));
        ListsConfig cfg = lists_config();
        if (!status.storage || !subnet_mask.load() || time(nullptr) < 1735689600) continue;
        uint32_t now = uptime();
        if (!requested.load()) {
            if (!cfg.automatic) continue;
            if (!next_attempt) {
                next_attempt = now + list_update_delay(status.last_success, time(nullptr), cfg.interval_hours, active_signature == signature(cfg));
            }
            if (now < next_attempt) continue;
        }
        requested = false;
        xSemaphoreTake(mutex, portMAX_DELAY); status.busy = true; status.downloaded_bytes = status.completed_sources = 0; xSemaphoreGive(mutex);
        bool okay = update(cfg);
        xSemaphoreTake(mutex, portMAX_DELAY);
        status.busy = false; next_attempt = uptime() + (okay ? config.interval_hours * 3600 : 300);
        xSemaphoreGive(mutex);
    }
}
esp_err_t lists_start() { return xTaskCreate(update_task, "list_update", 20480, nullptr, 2, &updater) == pdPASS ? ESP_OK : ESP_ERR_NO_MEM; }
} // namespace yetdns
