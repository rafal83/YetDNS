#include "apps.hpp"
#include "service.hpp"
#include "nvs.h"

namespace yetdns {
static SemaphoreHandle_t mutex;
static AppsConfig config;
esp_err_t apps_init() {
    mutex = xSemaphoreCreateMutex();
    if (!mutex) return ESP_ERR_NO_MEM;
    nvs_handle_t handle;
    esp_err_t err = nvs_open("applications", NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    AppsConfig stored; size_t size = sizeof(stored);
    if (nvs_get_blob(handle, "config", &stored, &size) == ESP_OK && size == sizeof(stored) && apps_config_valid(stored)) config = stored;
    nvs_close(handle); return ESP_OK;
}
AppsConfig apps_config() {
    xSemaphoreTake(mutex, portMAX_DELAY); AppsConfig value = config; xSemaphoreGive(mutex); return value;
}
esp_err_t apps_save_scope(uint32_t client, uint64_t blocked) {
    xSemaphoreTake(mutex, portMAX_DELAY);
    AppsConfig next = config;
    if (!apps_set_scope(next, client, blocked)) { xSemaphoreGive(mutex); return ESP_ERR_INVALID_ARG; }
    nvs_handle_t handle;
    esp_err_t err = nvs_open("applications", NVS_READWRITE, &handle);
    if (err == ESP_OK) {
        err = nvs_set_blob(handle, "config", &next, sizeof(next));
        if (err == ESP_OK) err = nvs_commit(handle);
        nvs_close(handle);
    }
    if (err == ESP_OK) { config = next; flush_cache = true; }
    xSemaphoreGive(mutex); return err;
}
bool apps_denied(const char *domain, uint32_t client) {
    xSemaphoreTake(mutex, portMAX_DELAY); uint64_t mask = apps_client_mask(config, client); xSemaphoreGive(mutex);
    return application_denied(domain, mask);
}
} // namespace yetdns
