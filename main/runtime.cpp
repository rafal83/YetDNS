#include "runtime.hpp"
#include <cstring>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "lwip/sockets.h"
#include "nvs.h"
#include "sdkconfig.h"

namespace yetdns {
std::atomic<uint32_t> query_limit{CONFIG_YETDNS_RATE_LIMIT};
std::atomic<bool> query_logging{true}, subnet_only{true}, doh_enabled{false};
static RuntimeConfig current;
static SemaphoreHandle_t mutex;
bool runtime_valid(const RuntimeConfig &v) {
    in_addr addr;
    return v.version == 1 && v.rate_limit <= 1000 && v.timeout_ms >= 500 && v.timeout_ms <= 10000 &&
        std::memchr(v.primary, 0, sizeof(v.primary)) && std::memchr(v.secondary, 0, sizeof(v.secondary)) &&
        std::memchr(v.doh_url, 0, sizeof(v.doh_url)) && inet_pton(AF_INET, v.primary, &addr) == 1 &&
        inet_pton(AF_INET, v.secondary, &addr) == 1 && !std::strncmp(v.doh_url, "https://", 8) &&
        std::strlen(v.doh_url) > 8 && !std::strpbrk(v.doh_url, "\r\n\t ");
}
static void apply(const RuntimeConfig &v) {
    current = v; query_limit = v.rate_limit; query_logging = v.logging; subnet_only = v.subnet_only; doh_enabled = v.doh;
    if (!v.logging) clear_logs();
}
void runtime_init() {
    mutex = xSemaphoreCreateMutex(); configASSERT(mutex);
    RuntimeConfig value;
    value.rate_limit = CONFIG_YETDNS_RATE_LIMIT;
    strlcpy(value.primary, CONFIG_YETDNS_UPSTREAM_PRIMARY, sizeof(value.primary));
    strlcpy(value.secondary, CONFIG_YETDNS_UPSTREAM_SECONDARY, sizeof(value.secondary));
    strlcpy(value.doh_url, CONFIG_YETDNS_DOH_URL, sizeof(value.doh_url));
#ifdef CONFIG_YETDNS_DOH
    value.doh = true;
#endif
#ifndef CONFIG_YETDNS_CLIENT_SUBNET_ONLY
    value.subnet_only = false;
#endif
    nvs_handle_t handle;
    if (nvs_open("yetdns", NVS_READONLY, &handle) == ESP_OK) {
        RuntimeConfig stored; size_t len = sizeof(stored);
        if (nvs_get_blob(handle, "runtime", &stored, &len) == ESP_OK && len == sizeof(stored) && runtime_valid(stored)) value = stored;
        nvs_close(handle);
    }
    apply(value);
}
RuntimeConfig runtime_snapshot() {
    xSemaphoreTake(mutex, portMAX_DELAY); RuntimeConfig value = current; xSemaphoreGive(mutex); return value;
}
esp_err_t runtime_save(const RuntimeConfig &value) {
    if (!runtime_valid(value)) return ESP_ERR_INVALID_ARG;
    nvs_handle_t handle;
    esp_err_t err = nvs_open("yetdns", NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(handle, "runtime", &value, sizeof(value));
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    if (err == ESP_OK) { xSemaphoreTake(mutex, portMAX_DELAY); apply(value); xSemaphoreGive(mutex); }
    return err;
}
} // namespace yetdns
