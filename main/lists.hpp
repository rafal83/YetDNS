#pragma once
#include <cstddef>
#include <cstdint>
#include "esp_err.h"
namespace yetdns {
constexpr size_t list_source_max = 6;
struct ListSource { char name[48]{}, url[384]{}; bool enabled{}; };
struct ListsConfig { uint32_t version{1}, interval_hours{24}; bool automatic{true}; uint32_t count{}; ListSource sources[list_source_max]{}; };
struct ListsStatus {
    bool storage{}, busy{}, pending{}, outdated{};
    uint32_t domains{}, generation{}, last_success{}, next_attempt_s{}, downloaded_bytes{}, completed_sources{};
    char message[192]{};
};
esp_err_t lists_init();
esp_err_t lists_start();
ListsConfig lists_config();
ListsStatus lists_status();
bool lists_valid(const ListsConfig &config);
esp_err_t lists_save(const ListsConfig &config);
void lists_request_update();
bool filter_contains(const char *domain);
uint32_t filter_count();
}
