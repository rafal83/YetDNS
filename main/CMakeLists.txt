find_package(Python3 REQUIRED COMPONENTS Interpreter)
execute_process(COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/../tools/build_blocklist.py
    --output ${CMAKE_CURRENT_SOURCE_DIR}/blocklist.bin ${CMAKE_CURRENT_SOURCE_DIR}/../data/blocked.txt
    COMMAND_ERROR_IS_FATAL ANY)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ../data/blocked.txt ../tools/build_blocklist.py)
idf_component_register(SRCS "apps_core.cpp" "apps.cpp" "runtime.cpp" "list_builder.cpp" "lists.cpp" "ha_mqtt.cpp" "app_main.cpp" "dns_core.cpp" "service.cpp" "admin.cpp"
    INCLUDE_DIRS "." REQUIRES esp_wifi esp_netif esp_event nvs_flash esp_http_client
    esp_http_server esp-tls mbedtls esp_timer json lwip esp_partition mqtt esp_app_format
    EMBED_FILES "blocklist.bin" "dashboard.html" "blocked.html")
target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror -Wframe-larger-than=6144)
