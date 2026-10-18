#include "ha_mqtt.hpp"
#include "esp_app_desc.h"
#include "service.hpp"
#include "lists.hpp"
#include <cstring>
#include <cstdlib>
#include <ctime>
#include "cJSON.h"
#include "esp_crt_bundle.h"
#include "esp_heap_caps.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "mqtt_client.h"
#include "nvs.h"
namespace yetdns {
static SemaphoreHandle_t mutex;
static MqttConfig config;
static std::atomic<uint32_t> revision{1};
static std::atomic<bool> connected{}, discover{};
static char device_id[48], base[64], availability[96];
static QueueHandle_t commands;
enum class Command : uint8_t { blocking, logging, update, flush, rate };
struct Message { Command command; uint32_t value; };
bool mqtt_connected() { return connected.load(); }
const char *mqtt_device_id() { return device_id; }
MqttConfig mqtt_config() { xSemaphoreTake(mutex, portMAX_DELAY); MqttConfig value = config; xSemaphoreGive(mutex); return value; }
bool mqtt_valid(const MqttConfig &v) {
    if (v.version != 1 || v.interval_s < 5 || v.interval_s > 300 ||
        !std::memchr(v.uri, 0, sizeof(v.uri)) || !std::memchr(v.username, 0, sizeof(v.username)) ||
        !std::memchr(v.password, 0, sizeof(v.password)) || !std::memchr(v.discovery_prefix, 0, sizeof(v.discovery_prefix)) ||
        !v.discovery_prefix[0] || std::strpbrk(v.discovery_prefix, "#+ \r\n\t")) return false;
    if (!v.enabled && !v.uri[0]) return true;
    return (!std::strncmp(v.uri, "mqtt://", 7) || !std::strncmp(v.uri, "mqtts://", 8)) &&
        std::strlen(v.uri) > 8 && !std::strpbrk(v.uri, "@ \r\n\t");
}
esp_err_t mqtt_save(const MqttConfig &value) {
    if (!mqtt_valid(value)) return ESP_ERR_INVALID_ARG;
    nvs_handle_t handle; esp_err_t err = nvs_open_from_partition("listscfg", "mqtt", NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(handle, "config", &value, sizeof(value)); if (err == ESP_OK) err = nvs_commit(handle); nvs_close(handle);
    if (err == ESP_OK) { xSemaphoreTake(mutex, portMAX_DELAY); config = value; ++revision; xSemaphoreGive(mutex); }
    return err;
}
static void send_json(esp_mqtt_client_handle_t client, const char *topic, cJSON *json, bool retained) {
    if (!json) return;
    char *payload = cJSON_PrintUnformatted(json); cJSON_Delete(json);
    if (payload) { esp_mqtt_client_publish(client, topic, payload, 0, 1, retained); cJSON_free(payload); }
}
struct Entity { const char *component, *key, *name, *unit, *command; bool total; };
static const Entity entities[] = {
    {"sensor", "queries", "Requêtes DNS", nullptr, nullptr, true},
    {"sensor", "blocked", "Requêtes bloquées", nullptr, nullptr, true},
    {"sensor", "cached", "Réponses du cache", nullptr, nullptr, true},
    {"sensor", "domains", "Domaines bloqués", nullptr, nullptr, false},
    {"sensor", "errors", "Erreurs DNS", nullptr, nullptr, true},
    {"sensor", "internal_heap_free", "RAM interne libre", "B", nullptr, false},
    {"sensor", "uptime_s", "Durée de fonctionnement", "s", nullptr, false},
    {"switch", "blocking", "Protection DNS", nullptr, "blocking", false},
    {"switch", "logging", "Journal DNS", nullptr, "logging", false},
    {"button", "update_lists", "Actualiser les listes", nullptr, "update", false},
    {"button", "flush_cache", "Vider le cache DNS", nullptr, "flush", false},
    {"number", "rate_limit", "Limite DNS par appareil", "req/s", "rate", false},
};
static void discovery(esp_mqtt_client_handle_t client, const MqttConfig &cfg) {
    char topic[192], state_topic[96]; snprintf(state_topic, sizeof(state_topic), "%s/state", base);
    for (const auto &entity : entities) {
        auto *json = cJSON_CreateObject(); char unique[96], value_template[160];
        snprintf(unique, sizeof(unique), "%s_%s", device_id, entity.key);
        cJSON_AddStringToObject(json, "name", entity.name); cJSON_AddStringToObject(json, "unique_id", unique);
        cJSON_AddStringToObject(json, "availability_topic", availability);
        cJSON_AddStringToObject(json, "payload_available", "online"); cJSON_AddStringToObject(json, "payload_not_available", "offline");
        auto *device = cJSON_AddObjectToObject(json, "device"); auto *ids = cJSON_AddArrayToObject(device, "identifiers");
        cJSON_AddItemToArray(ids, cJSON_CreateString(device_id)); cJSON_AddStringToObject(device, "name", "YetDNS");
        cJSON_AddStringToObject(device, "manufacturer", "YetDNS"); cJSON_AddStringToObject(device, "model", "ESP32-S3 Wi-Fi DNS");
        cJSON_AddStringToObject(device, "sw_version", esp_app_get_description()->version);
        if (std::strcmp(entity.component, "button")) {
            cJSON_AddStringToObject(json, "state_topic", state_topic);
            if (!std::strcmp(entity.component, "switch")) snprintf(value_template, sizeof(value_template), "{{ 'ON' if value_json.%s else 'OFF' }}", entity.key);
            else snprintf(value_template, sizeof(value_template), "{{ value_json.%s }}", entity.key);
            cJSON_AddStringToObject(json, "value_template", value_template);
        }
        if (entity.command) { char command[128]; snprintf(command, sizeof(command), "%s/set/%s", base, entity.command); cJSON_AddStringToObject(json, "command_topic", command); }
        if (entity.unit) cJSON_AddStringToObject(json, "unit_of_measurement", entity.unit);
        if (!std::strcmp(entity.component, "sensor")) cJSON_AddStringToObject(json, "state_class", entity.total ? "total_increasing" : "measurement");
        if (!std::strcmp(entity.component, "number")) { cJSON_AddNumberToObject(json, "min", 0); cJSON_AddNumberToObject(json, "max", 1000); cJSON_AddNumberToObject(json, "step", 1); cJSON_AddStringToObject(json, "mode", "box"); }
        snprintf(topic, sizeof(topic), "%s/%s/%s/%s/config", cfg.discovery_prefix, entity.component, device_id, entity.key);
        send_json(client, topic, json, true);
        vTaskDelay(1);
    }
}
static void state(esp_mqtt_client_handle_t client) {
    auto *json = cJSON_CreateObject(); char topic[96]; snprintf(topic, sizeof(topic), "%s/state", base);
    cJSON_AddNumberToObject(json, "queries", stats.queries.load()); cJSON_AddNumberToObject(json, "blocked", stats.blocked.load());
    cJSON_AddNumberToObject(json, "cached", stats.cached.load()); cJSON_AddNumberToObject(json, "errors", stats.errors.load());
    cJSON_AddNumberToObject(json, "domains", filter_count()); cJSON_AddNumberToObject(json, "internal_heap_free", heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
    cJSON_AddNumberToObject(json, "uptime_s", esp_timer_get_time() / 1000000); cJSON_AddNumberToObject(json, "rate_limit", query_limit.load());
    cJSON_AddBoolToObject(json, "blocking", blocking.load()); cJSON_AddBoolToObject(json, "logging", query_logging.load());
    send_json(client, topic, json, false);
}
static void event(void *, esp_event_base_t, int32_t id, void *data) {
    auto *e = static_cast<esp_mqtt_event_handle_t>(data);
    if (id == MQTT_EVENT_CONNECTED) {
        connected = true; discover = true;
        char topic[128]; snprintf(topic, sizeof(topic), "%s/set/#", base); esp_mqtt_client_subscribe(e->client, topic, 1);
        auto cfg = mqtt_config(); snprintf(topic, sizeof(topic), "%s/status", cfg.discovery_prefix); esp_mqtt_client_subscribe(e->client, topic, 1);
    } else if (id == MQTT_EVENT_DISCONNECTED) connected = false;
    else if (id == MQTT_EVENT_DATA && e->current_data_offset == 0 && e->data_len == e->total_data_len && e->data_len < 32 && e->topic_len < 128) {
        char topic[128]{}, payload[32]{}; std::memcpy(topic, e->topic, e->topic_len); std::memcpy(payload, e->data, e->data_len);
        auto cfg = mqtt_config(); char status_topic[128]; snprintf(status_topic, sizeof(status_topic), "%s/status", cfg.discovery_prefix);
        if (!std::strcmp(topic, status_topic)) { if (!std::strcmp(payload, "online")) discover = true; return; }
        if (e->retain) return; // never replay retained commands on reconnect
        char prefix[96]; snprintf(prefix, sizeof(prefix), "%s/set/", base);
        if (std::strncmp(topic, prefix, std::strlen(prefix))) return;
        const char *key = topic + std::strlen(prefix); Message msg{};
        if (!std::strcmp(key, "blocking") || !std::strcmp(key, "logging")) {
            if (std::strcmp(payload, "ON") && std::strcmp(payload, "OFF")) return;
            msg = {!std::strcmp(key, "blocking") ? Command::blocking : Command::logging, uint32_t(!std::strcmp(payload, "ON"))};
        } else if (!std::strcmp(key, "update")) msg.command = Command::update;
        else if (!std::strcmp(key, "flush")) msg.command = Command::flush;
        else if (!std::strcmp(key, "rate")) {
            char *end; long n = std::strtol(payload, &end, 10); if (!payload[0] || *end || n < 0 || n > 1000) return;
            msg = {Command::rate, uint32_t(n)};
        } else return;
        xQueueSend(commands, &msg, 0);
    }
}
static void worker(void *) {
    esp_mqtt_client_handle_t client = nullptr; uint32_t active_revision = 0, last_sent = 0;
    for (;;) {
        uint32_t rev = revision.load(); auto cfg = mqtt_config();
        if (rev != active_revision) {
            if (client) { if (connected) esp_mqtt_client_publish(client, availability, "offline", 0, 1, true); esp_mqtt_client_stop(client); esp_mqtt_client_destroy(client); client = nullptr; }
            connected = false; active_revision = rev;
            if (cfg.enabled) {
                esp_mqtt_client_config_t settings{};
                settings.broker.address.uri = cfg.uri; settings.broker.verification.crt_bundle_attach = esp_crt_bundle_attach;
                settings.credentials.client_id = device_id; settings.credentials.username = cfg.username[0] ? cfg.username : nullptr;
                settings.credentials.authentication.password = cfg.password[0] ? cfg.password : nullptr;
                settings.session.last_will.topic = availability; settings.session.last_will.msg = "offline";
                settings.session.last_will.qos = 1; settings.session.last_will.retain = true;
                settings.session.keepalive = 30; settings.network.reconnect_timeout_ms = 5000;
                settings.buffer.size = 2048; settings.task.stack_size = 6144;
                client = esp_mqtt_client_init(&settings);
                if (client) { esp_mqtt_client_register_event(client, MQTT_EVENT_ANY, event, nullptr); esp_mqtt_client_start(client); }
            }
        }
        Message msg;
        while (xQueueReceive(commands, &msg, 0) == pdTRUE) {
            if (msg.command == Command::blocking) save_blocking(msg.value);
            else if (msg.command == Command::flush) flush_cache = true;
            else if (msg.command == Command::update) lists_request_update();
            else { auto settings = runtime_snapshot(); if (msg.command == Command::logging) settings.logging = msg.value; else settings.rate_limit = msg.value; runtime_save(settings); }
            last_sent = 0;
        }
        if (client && connected) {
            if (discover.exchange(false)) { discovery(client, cfg); esp_mqtt_client_publish(client, availability, "online", 0, 1, true); last_sent = 0; }
            uint32_t now = esp_timer_get_time() / 1000000;
            if (!last_sent || now - last_sent >= cfg.interval_s) { state(client); last_sent = now; }
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}
esp_err_t mqtt_start() {
    mutex = xSemaphoreCreateMutex(); commands = xQueueCreate(8, sizeof(Message)); if (!mutex || !commands) return ESP_ERR_NO_MEM;
    uint8_t mac[6]; ESP_ERROR_CHECK(esp_read_mac(mac, ESP_MAC_WIFI_STA));
    snprintf(device_id, sizeof(device_id), "yetdns_%02x%02x%02x%02x%02x%02x", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    snprintf(base, sizeof(base), "yetdns/%s", device_id); snprintf(availability, sizeof(availability), "%s/availability", base);
    nvs_handle_t handle;
    if (nvs_open_from_partition("listscfg", "mqtt", NVS_READONLY, &handle) == ESP_OK) {
        MqttConfig stored; size_t size = sizeof(stored);
        if (nvs_get_blob(handle, "config", &stored, &size) == ESP_OK && size == sizeof(stored) && mqtt_valid(stored)) config = stored;
        nvs_close(handle);
    }
    return xTaskCreate(worker, "ha_mqtt", 8192, nullptr, 3, nullptr) == pdPASS ? ESP_OK : ESP_ERR_NO_MEM;
}
}
