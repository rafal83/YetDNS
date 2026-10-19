#pragma once
#include <cstddef>
#include <cstdint>

namespace yetdns {
// Bytes of an application image needed to read its esp_app_desc_t.
constexpr size_t image_header_min = 112;
// "v1.2.3" / "1.2" -> numeric parts. Needs at least two dotted numbers, so git hashes like
// "9885932-dirty" are rejected; anything after the numbers (e.g. "-rc1") is ignored.
bool version_parse(const char *text, uint32_t out[3]);
// True when `candidate` is a strictly higher release than `current`. A development build whose
// version is not numeric is older than any numeric release.
bool version_newer(const char *current, const char *candidate);
// GitHub asset digest: "sha256:" followed by 64 hexadecimal digits.
bool digest_parse(const char *text, uint8_t out[32]);
// Checks the ESP image magic, the app descriptor and its project name; copies the embedded version.
bool image_describe(const uint8_t *data, size_t size, const char *project, char *version, size_t capacity);
// HTTPS URLs on github.com or *.githubusercontent.com only, without credentials.
bool update_url_allowed(const char *url);
} // namespace yetdns
