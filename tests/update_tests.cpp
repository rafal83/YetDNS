#include "update_core.hpp"
#include <cassert>
#include <cstring>
using namespace yetdns;
int main() {
    uint32_t v[3];
    assert(version_parse("v1.2.3", v) && v[0] == 1 && v[1] == 2 && v[2] == 3);
    assert(version_parse("0.5", v) && v[0] == 0 && v[1] == 5 && v[2] == 0);
    assert(version_parse("0.4.0-3-gabc", v) && v[1] == 4);
    assert(!version_parse("9885932-dirty", v) && !version_parse("7", v) && !version_parse("", v) && !version_parse(nullptr, v));
    assert(!version_parse("abc", v) && !version_parse("1.", v) && !version_parse("1.x", v) && !version_parse("123456.1", v));
    assert(version_newer("0.4.0", "v0.5.0") && version_newer("0.4.9", "0.5.0") && version_newer("0.9.0", "v0.10.0"));
    assert(!version_newer("0.5.0", "0.5.0") && !version_newer("0.5.1", "0.5.0") && !version_newer("1.0.0", "0.9.9"));
    assert(version_newer("9885932-dirty", "0.1.0"));            // development builds accept any release
    assert(!version_newer("0.4.0", "latest") && !version_newer("0.4.0", ""));
    uint8_t digest[32];
    assert(digest_parse("sha256:00ff10Ab00000000000000000000000000000000000000000000000000000001", digest));
    assert(digest[0] == 0 && digest[1] == 0xff && digest[2] == 0x10 && digest[3] == 0xab && digest[31] == 1);
    assert(!digest_parse("sha256:abc", digest) && !digest_parse("md5:00ff10Ab00000000000000000000000000000000000000000000000000000001", digest));
    assert(!digest_parse("sha256:zz00000000000000000000000000000000000000000000000000000000000000", digest) && !digest_parse(nullptr, digest));
    uint8_t image[image_header_min]{};
    image[0] = 0xE9; image[32] = 0x32; image[33] = 0x54; image[34] = 0xCD; image[35] = 0xAB;
    std::strcpy(reinterpret_cast<char *>(image + 48), "0.5.0"); std::strcpy(reinterpret_cast<char *>(image + 80), "yetdns");
    char version[32];
    assert(image_describe(image, sizeof(image), "yetdns", version, sizeof(version)) && !std::strcmp(version, "0.5.0"));
    assert(!image_describe(image, sizeof(image), "other", version, sizeof(version)));
    assert(!image_describe(image, sizeof(image) - 1, "yetdns", version, sizeof(version)));
    image[0] = 0; assert(!image_describe(image, sizeof(image), "yetdns", version, sizeof(version))); image[0] = 0xE9;
    image[35] = 0; assert(!image_describe(image, sizeof(image), "yetdns", version, sizeof(version)));
    image[35] = 0xAB; std::memset(image + 80, 'x', 32); // project name without terminator is not a match
    assert(!image_describe(image, sizeof(image), "yetdns", version, sizeof(version)));
    assert(update_url_allowed("https://github.com/rafal83/YetDNS/releases/download/v0.5.0/yetdns.bin"));
    assert(update_url_allowed("https://api.github.com/repos/a/b/releases/latest") && update_url_allowed("https://objects.githubusercontent.com/x?y=1"));
    assert(!update_url_allowed("http://github.com/x") && !update_url_allowed("https://evil.example/github.com") && !update_url_allowed("https://github.com.evil.example/x"));
    assert(!update_url_allowed("https://user@github.com/x") && !update_url_allowed("https://githubusercontent.com.evil/x") && !update_url_allowed("https://notgithub.com/x"));
    assert(!update_url_allowed("https://evil.example/@github.com/") && !update_url_allowed(nullptr) && !update_url_allowed("https://"));
    assert(!update_url_allowed("https://github.com" "\\" "@evil.example/"));
    return 0;
}
