#include "update_core.hpp"
#include <cstring>

namespace yetdns {
bool version_parse(const char *text, uint32_t out[3]) {
    if (!text) return false;
    if (*text == 'v' || *text == 'V') ++text;
    out[0] = out[1] = out[2] = 0;
    size_t parts = 0;
    for (;;) {
        if (*text < '0' || *text > '9') return false;
        uint32_t value = 0;
        for (; *text >= '0' && *text <= '9'; ++text) {
            value = value * 10 + (*text - '0');
            if (value > 99999) return false;
        }
        out[parts++] = value;
        if (*text != '.' || parts == 3 || text[1] < '0' || text[1] > '9') break;
        ++text;
    }
    return parts >= 2;
}
bool version_newer(const char *current, const char *candidate) {
    uint32_t next[3], now[3];
    if (!version_parse(candidate, next)) return false;
    if (!version_parse(current, now)) return true;
    for (int i = 0; i < 3; ++i) if (next[i] != now[i]) return next[i] > now[i];
    return false;
}
bool digest_parse(const char *text, uint8_t out[32]) {
    if (!text || std::strncmp(text, "sha256:", 7)) return false;
    text += 7;
    if (std::strlen(text) != 64) return false;
    for (int i = 0; i < 32; ++i) {
        uint8_t byte = 0;
        for (int k = 0; k < 2; ++k) {
            char c = text[i * 2 + k]; uint8_t v;
            if (c >= '0' && c <= '9') v = c - '0';
            else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
            else return false;
            byte = byte << 4 | v;
        }
        out[i] = byte;
    }
    return true;
}
bool image_describe(const uint8_t *data, size_t size, const char *project, char *version, size_t capacity) {
    // esp_image_header_t (24 bytes) + first esp_image_segment_header_t (8 bytes), then esp_app_desc_t.
    constexpr size_t desc = 32, version_at = desc + 16, project_at = desc + 48, field = 32;
    if (size < image_header_min || capacity < field || data[0] != 0xE9) return false;
    uint32_t magic = data[desc] | data[desc + 1] << 8 | data[desc + 2] << 16 | uint32_t(data[desc + 3]) << 24;
    if (magic != 0xABCD5432u) return false;
    char name[field + 1]{};
    std::memcpy(name, data + project_at, field);
    if (!project || std::strcmp(name, project)) return false;
    std::memcpy(version, data + version_at, field); version[field - 1] = 0;
    return true;
}
bool update_url_allowed(const char *url) {
    static const char scheme[] = "https://";
    if (!url || std::strncmp(url, scheme, sizeof(scheme) - 1)) return false;
    const char *host = url + sizeof(scheme) - 1, *end = host;
    while (*end && *end != '/' && *end != ':' && *end != '?' && *end != '#') {
        if (*end == '@' || *end == '\\') return false;
        ++end;
    }
    size_t n = end - host;
    auto is = [&](const char *name) { return n == std::strlen(name) && !std::strncmp(host, name, n); };
    auto ends = [&](const char *suffix) { size_t s = std::strlen(suffix); return n > s && !std::strncmp(host + n - s, suffix, s); };
    return is("github.com") || is("api.github.com") || ends(".githubusercontent.com");
}
} // namespace yetdns
