#include "service.hpp"
#include "lists.hpp"
#include "ha_mqtt.hpp"
#include <cstring>
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_sntp.h"
#include "esp_wifi.h"
#include "nvs_flash.h"

namespace {
void network_event(void *, esp_event_base_t base, int32_t event, void *data) {
    if (base == WIFI_EVENT && event == WIFI_EVENT_STA_START) esp_wifi_connect();
    if (base == WIFI_EVENT && event == WIFI_EVENT_STA_DISCONNECTED) {
        yetdns::subnet_mask = 0;
        auto *info = static_cast<wifi_event_sta_disconnected_t *>(data);
        ESP_LOGW("yetdns", "Wi-Fi disconnected (reason %u); reconnecting", unsigned(info->reason));
        // Driver connection attempts are asynchronous; no blocking event-loop delay.
        esp_wifi_connect();
    }
    if (base == IP_EVENT && event == IP_EVENT_STA_GOT_IP) {
        auto *info = static_cast<ip_event_got_ip_t *>(data);
        yetdns::subnet_ip = info->ip_info.ip.addr;
        yetdns::subnet_mask = info->ip_info.netmask.addr;
        esp_netif_dns_info_t bootstrap{};
        bootstrap.ip.type = ESP_IPADDR_TYPE_V4;
        if (esp_netif_str_to_ip4(CONFIG_YETDNS_BOOTSTRAP_DNS, &bootstrap.ip.u_addr.ip4) == ESP_OK)
            ESP_ERROR_CHECK(esp_netif_set_dns_info(info->esp_netif, ESP_NETIF_DNS_MAIN, &bootstrap));
        ESP_LOGW("yetdns", "DNS ready at " IPSTR ":53; dashboard http://" IPSTR,
                 IP2STR(&info->ip_info.ip), IP2STR(&info->ip_info.ip));
    }
}
}
extern "C" void app_main() {
    esp_err_t err = nvs_flash_init();
    // Never silently erase stored credentials/rules on an NVS error.
    ESP_ERROR_CHECK(err);
    yetdns::load_settings();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    auto *netif = esp_netif_create_default_wifi_sta();
    ESP_ERROR_CHECK(esp_netif_set_hostname(netif, CONFIG_YETDNS_HOSTNAME));
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, network_event, nullptr));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, network_event, nullptr));
    wifi_config_t wifi{};
    if (std::strlen(CONFIG_YETDNS_WIFI_SSID) > sizeof(wifi.sta.ssid) ||
        std::strlen(CONFIG_YETDNS_WIFI_PASSWORD) > sizeof(wifi.sta.password)) ESP_ERROR_CHECK(ESP_ERR_INVALID_ARG);
    std::memcpy(wifi.sta.ssid, CONFIG_YETDNS_WIFI_SSID, std::strlen(CONFIG_YETDNS_WIFI_SSID));
    std::memcpy(wifi.sta.password, CONFIG_YETDNS_WIFI_PASSWORD, std::strlen(CONFIG_YETDNS_WIFI_PASSWORD));
    wifi.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    wifi.sta.pmf_cfg.capable = true;
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    if (!std::strlen(CONFIG_YETDNS_WIFI_SSID)) ESP_LOGE("yetdns", "Configure Wi-Fi under idf.py menuconfig > YetDNS");
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "time.cloudflare.com");
    esp_sntp_init();
    ESP_ERROR_CHECK(yetdns::service_start());
    ESP_ERROR_CHECK(yetdns::mqtt_start());
    ESP_ERROR_CHECK(yetdns::admin_start());
    ESP_ERROR_CHECK(yetdns::lists_start());
}
