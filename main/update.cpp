#include "update.hpp"
#include "service.hpp"
#include "update_core.hpp"
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <memory>
#include "cJSON.h"
#include "esp_app_desc.h"
#include "esp_crt_bundle.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "mbedtls/sha256.h"
#include "nvs.h"

namespace yetdns {
namespace {
// The two release binaries differ by PSRAM support, so the running build tells which one fits this board.
#if CONFIG_SPIRAM
constexpr char update_asset[] = "yetdns-esp32s3-n16r8.bin";
#else
constexpr char update_asset[] = "yetdns-esp32s3-8mb.bin";
#endif
constexpr uint32_t valid_time = 1735689600;
constexpr uint32_t check_interval_s = 24 * 3600, retry_interval_s = 3600, first_check_s = 120, confirm_after_s = 60;
constexpr size_t release_json_max = 32 * 1024;
constexpr int64_t download_deadline_us = 600ll * 1000000;
enum class Phase { idle, checking, downloading, restarting, error };
const char *const phase_names[] = {"idle", "checking", "downloading", "restarting", "error"};

SemaphoreHandle_t mutex;
TaskHandle_t task;
UpdateInfo state;
Phase phase = Phase::idle;
char download_url[256];
uint8_t download_digest[32];
uint32_t download_size;
std::atomic<bool> want_check{}, want_install{};

void set_phase(Phase value, const char *text) {
    xSemaphoreTake(mutex, portMAX_DELAY);
    phase = value; state.phase = phase_names[int(value)]; strlcpy(state.message, text, sizeof(state.message));
    xSemaphoreGive(mutex);
}
bool network_ready() { return subnet_mask.load() && time(nullptr) > valid_time; }

bool redirect_status(int status) { return status == 301 || status == 302 || status == 303 || status == 307 || status == 308; }
// GET over verified HTTPS, following redirects; every body byte goes through `sink`, which can stop the transfer.
bool http_get(const char *url, const char *accept, bool (*sink)(const uint8_t *, size_t, void *), void *context, size_t &received) {
    received = 0;
    esp_http_client_config_t cfg{};
    cfg.url = url; cfg.timeout_ms = 20000; cfg.crt_bundle_attach = esp_crt_bundle_attach;
    cfg.user_agent = "YetDNS-updater"; cfg.disable_auto_redirect = true;
    // The release CDN redirect carries a long signed URL and large headers.
    cfg.buffer_size = 4096; cfg.buffer_size_tx = 2048;
    auto client = esp_http_client_init(&cfg);
    if (!client) return false;
    esp_http_client_set_header(client, "Accept", accept);
    esp_http_client_set_header(client, "Accept-Encoding", "identity");
    esp_http_client_set_header(client, "X-GitHub-Api-Version", "2022-11-28");
    int64_t deadline = esp_timer_get_time() + download_deadline_us;
    bool ok = false;
    for (int hop = 0; hop < 6; ++hop) {
        if (esp_http_client_open(client, 0) != ESP_OK || esp_http_client_fetch_headers(client) < 0) break;
        int status = esp_http_client_get_status_code(client);
        if (redirect_status(status)) {
            char drain[128];
            if (esp_http_client_set_redirection(client) != ESP_OK) break;
            while (esp_http_client_read(client, drain, sizeof(drain)) > 0) {}
            continue;
        }
        if (status != 200) break;
        uint8_t buffer[2048];
        for (;;) {
            int n = esp_http_client_read(client, reinterpret_cast<char *>(buffer), sizeof(buffer));
            if (n < 0) break;
            if (!n) { ok = esp_http_client_is_complete_data_received(client); break; }
            received += n;
            if (esp_timer_get_time() > deadline || !sink(buffer, n, context)) break;
            if ((received & 0xffff) < sizeof(buffer)) vTaskDelay(1); // let lower-priority tasks run during long downloads
        }
        break;
    }
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return ok;
}

struct Buffer { char *data; size_t size, capacity; };
bool collect(const uint8_t *data, size_t n, void *context) {
    auto *buffer = static_cast<Buffer *>(context);
    if (buffer->size + n + 1 > buffer->capacity) return false;
    std::memcpy(buffer->data + buffer->size, data, n); buffer->size += n; buffer->data[buffer->size] = 0;
    return true;
}
void finish_check(bool available, const char *latest, const char *text, bool success) {
    xSemaphoreTake(mutex, portMAX_DELAY);
    strlcpy(state.latest, latest, sizeof(state.latest)); state.available = available;
    if (success) state.checked_at = time(nullptr);
    phase = success ? Phase::idle : Phase::error; state.phase = phase_names[int(phase)];
    strlcpy(state.message, text, sizeof(state.message));
    xSemaphoreGive(mutex);
}
void check_release() {
    set_phase(Phase::checking, "Recherche de la dernière version…");
    char url[128];
    std::snprintf(url, sizeof(url), "https://api.github.com/repos/%s/releases/latest", CONFIG_YETDNS_UPDATE_REPO);
    auto text = std::unique_ptr<char, decltype(&heap_caps_free)>(static_cast<char *>(heap_caps_malloc(release_json_max, MALLOC_CAP_8BIT)), heap_caps_free);
    if (!text) { finish_check(false, "", "Mémoire insuffisante", false); return; }
    Buffer buffer{text.get(), 0, release_json_max}; text.get()[0] = 0;
    size_t received;
    if (!http_get(url, "application/vnd.github+json", collect, &buffer, received) || !buffer.size) {
        finish_check(false, "", "GitHub injoignable ou réponse invalide (limite de requêtes ?)", false); return;
    }
    cJSON *json = cJSON_ParseWithLength(buffer.data, buffer.size);
    auto *tag = json ? cJSON_GetObjectItemCaseSensitive(json, "tag_name") : nullptr;
    if (!cJSON_IsString(tag)) { cJSON_Delete(json); finish_check(false, "", "Aucune publication trouvée", false); return; }
    const char *latest = tag->valuestring + (*tag->valuestring == 'v' ? 1 : 0);
    const char *current = esp_app_get_description()->version;
    const cJSON *asset = nullptr, *item;
    cJSON_ArrayForEach(item, cJSON_GetObjectItemCaseSensitive(json, "assets")) {
        auto *name = cJSON_GetObjectItemCaseSensitive(item, "name");
        if (cJSON_IsString(name) && !std::strcmp(name->valuestring, update_asset)) { asset = item; break; }
    }
    if (!version_newer(current, latest)) { finish_check(false, latest, "Le firmware est à jour", true); cJSON_Delete(json); return; }
    auto *href = asset ? cJSON_GetObjectItemCaseSensitive(asset, "browser_download_url") : nullptr;
    auto *digest = asset ? cJSON_GetObjectItemCaseSensitive(asset, "digest") : nullptr;
    uint8_t parsed[32];
    if (!cJSON_IsString(href) || !update_url_allowed(href->valuestring) || std::strlen(href->valuestring) >= sizeof(download_url)) {
        finish_check(false, latest, "Version disponible, mais le fichier de ce modèle est absent de la publication", true);
    } else if (!cJSON_IsString(digest) || !digest_parse(digest->valuestring, parsed)) {
        finish_check(false, latest, "Version disponible, mais GitHub ne fournit pas d’empreinte SHA-256 : installation refusée", true);
    } else {
        xSemaphoreTake(mutex, portMAX_DELAY);
        auto *size = cJSON_GetObjectItemCaseSensitive(asset, "size");
        strlcpy(download_url, href->valuestring, sizeof(download_url)); std::memcpy(download_digest, parsed, sizeof(parsed));
        download_size = cJSON_IsNumber(size) && size->valuedouble > 0 && size->valuedouble < 16777216 ? uint32_t(size->valuedouble) : 0;
        xSemaphoreGive(mutex);
        finish_check(true, latest, "Nouvelle version disponible", true);
    }
    cJSON_Delete(json);
}

struct Install {
    esp_ota_handle_t handle{};
    const esp_partition_t *target{};
    mbedtls_sha256_context sha;
    uint8_t head[image_header_min];
    size_t head_n{}, written{};
    bool started{}, failed{};
    char error[96]{};
    char version[32]{};
};
bool fail(Install &install, const char *text) { if (!install.error[0]) strlcpy(install.error, text, sizeof(install.error)); install.failed = true; return false; }
bool write_ota(Install &install, const uint8_t *data, size_t n) {
    if (esp_ota_write(install.handle, data, n) != ESP_OK) return fail(install, "Écriture en flash impossible");
    install.written += n;
    xSemaphoreTake(mutex, portMAX_DELAY); state.downloaded = install.written; xSemaphoreGive(mutex);
    return true;
}
bool install_sink(const uint8_t *data, size_t n, void *context) {
    auto &install = *static_cast<Install *>(context);
    if (install.failed) return false;
    mbedtls_sha256_update(&install.sha, data, n);
    if (!install.started) {
        size_t take = std::min(n, image_header_min - install.head_n);
        std::memcpy(install.head + install.head_n, data, take); install.head_n += take; data += take; n -= take;
        if (install.head_n < image_header_min) return true;
        // Refuse foreign or corrupt images before erasing the inactive slot.
        if (!image_describe(install.head, install.head_n, esp_app_get_description()->project_name, install.version, sizeof(install.version)))
            return fail(install, "Fichier reçu : ce n’est pas un firmware YetDNS");
        if (!version_newer(esp_app_get_description()->version, install.version)) return fail(install, "Le fichier ne contient pas une version plus récente");
        if (esp_ota_begin(install.target, OTA_WITH_SEQUENTIAL_WRITES, &install.handle) != ESP_OK) return fail(install, "Emplacement de mise à jour inaccessible");
        install.started = true;
        if (!write_ota(install, install.head, install.head_n)) return false;
    }
    if (n && !write_ota(install, data, n)) return false;
    if (install.written > install.target->size) return fail(install, "Firmware trop grand pour l’emplacement");
    return true;
}
void install_release() {
    char url[sizeof(download_url)]; uint8_t expected[32];
    xSemaphoreTake(mutex, portMAX_DELAY);
    strlcpy(url, download_url, sizeof(url)); std::memcpy(expected, download_digest, sizeof(expected));
    state.downloaded = 0; state.total = download_size;
    xSemaphoreGive(mutex);
    set_phase(Phase::downloading, "Téléchargement du firmware…");
    auto install = std::unique_ptr<Install>(new (std::nothrow) Install{});
    if (!install) { set_phase(Phase::error, "Mémoire insuffisante"); return; }
    install->target = esp_ota_get_next_update_partition(nullptr);
    if (!install->target) { set_phase(Phase::error, "Aucun emplacement de mise à jour dans la table de partitions"); return; }
    mbedtls_sha256_init(&install->sha); mbedtls_sha256_starts(&install->sha, 0);
    size_t received;
    bool ok = http_get(url, "application/octet-stream", install_sink, install.get(), received);
    uint8_t actual[32];
    mbedtls_sha256_finish(&install->sha, actual); mbedtls_sha256_free(&install->sha);
    if (!ok || install->failed || !install->started) {
        if (install->started) esp_ota_abort(install->handle);
        set_phase(Phase::error, install->error[0] ? install->error : "Téléchargement interrompu");
        return;
    }
    if (std::memcmp(actual, expected, sizeof(actual))) { esp_ota_abort(install->handle); set_phase(Phase::error, "Empreinte SHA-256 différente : firmware rejeté"); return; }
    if (esp_ota_end(install->handle) != ESP_OK) { set_phase(Phase::error, "Image firmware invalide : mise à jour annulée"); return; }
    if (esp_ota_set_boot_partition(install->target) != ESP_OK) { set_phase(Phase::error, "Impossible d’activer le nouveau firmware"); return; }
    set_phase(Phase::restarting, "Mise à jour installée, redémarrage…");
    ESP_LOGW("yetdns", "OTA installed (%u bytes, version %s); restarting", unsigned(install->written), install->version);
    vTaskDelay(pdMS_TO_TICKS(3000));
    esp_restart();
}
bool load_auto_check() {
    nvs_handle_t handle; uint8_t value = 1;
    if (nvs_open_from_partition("listscfg", "update", NVS_READONLY, &handle) == ESP_OK) { nvs_get_u8(handle, "auto", &value); nvs_close(handle); }
    return value != 0;
}
void updater(void *) {
    uint32_t next_check = first_check_s;
    bool confirmed = false;
    for (;;) {
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(10000));
        uint32_t now = esp_timer_get_time() / 1000000;
        // A new image stays on probation until it has the network up; otherwise the bootloader rolls back.
        if (!confirmed && now >= confirm_after_s && subnet_mask.load()) {
            confirmed = true;
            if (esp_ota_mark_app_valid_cancel_rollback() == ESP_OK) ESP_LOGW("yetdns", "New firmware confirmed");
        }
        if (want_install.exchange(false)) {
            if (network_ready()) install_release(); else set_phase(Phase::error, "Réseau ou heure indisponible");
            continue;
        }
        bool manual = want_check.exchange(false);
        xSemaphoreTake(mutex, portMAX_DELAY); bool automatic = state.auto_check; xSemaphoreGive(mutex);
        if (manual || (automatic && now >= next_check)) {
            if (network_ready()) { check_release(); xSemaphoreTake(mutex, portMAX_DELAY); bool good = phase == Phase::idle; xSemaphoreGive(mutex); next_check = now + (good ? check_interval_s : retry_interval_s); }
            else if (manual) set_phase(Phase::error, "Réseau ou heure indisponible");
        }
    }
}
bool busy() { xSemaphoreTake(mutex, portMAX_DELAY); bool value = phase == Phase::checking || phase == Phase::downloading || phase == Phase::restarting; xSemaphoreGive(mutex); return value; }
} // namespace

esp_err_t update_start() {
    mutex = xSemaphoreCreateMutex();
    if (!mutex) return ESP_ERR_NO_MEM;
    state = {};
    strlcpy(state.current, esp_app_get_description()->version, sizeof(state.current));
    strlcpy(state.repo, CONFIG_YETDNS_UPDATE_REPO, sizeof(state.repo));
    strlcpy(state.asset, update_asset, sizeof(state.asset));
    state.phase = phase_names[0]; state.auto_check = load_auto_check();
    return xTaskCreate(updater, "updater", 10240, nullptr, 2, &task) == pdPASS ? ESP_OK : ESP_ERR_NO_MEM;
}
void update_snapshot(UpdateInfo &info) {
    xSemaphoreTake(mutex, portMAX_DELAY); info = state; xSemaphoreGive(mutex);
}
bool update_request_check() {
    if (busy()) return false;
    want_check = true; xTaskNotifyGive(task); return true;
}
bool update_request_install() {
    xSemaphoreTake(mutex, portMAX_DELAY); bool ready = state.available && (phase == Phase::idle || phase == Phase::error); xSemaphoreGive(mutex);
    if (!ready) return false;
    want_install = true; xTaskNotifyGive(task); return true;
}
esp_err_t update_set_auto_check(bool value) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open_from_partition("listscfg", "update", NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    err = nvs_set_u8(handle, "auto", value ? 1 : 0);
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    if (err == ESP_OK) { xSemaphoreTake(mutex, portMAX_DELAY); state.auto_check = value; xSemaphoreGive(mutex); }
    return err;
}
} // namespace yetdns
