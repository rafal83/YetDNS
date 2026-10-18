#pragma once
#include <cstdint>
#include "esp_err.h"
namespace yetdns {
struct MqttConfig {
    uint32_t version{1}, interval_s{10}; bool enabled{};
    char uri[256]{}, username[96]{}, password[128]{}, discovery_prefix[64]{"homeassistant"};
};
esp_err_t mqtt_start();
MqttConfig mqtt_config();
bool mqtt_valid(const MqttConfig &config);
esp_err_t mqtt_save(const MqttConfig &config);
bool mqtt_connected();
const char *mqtt_device_id();
}
