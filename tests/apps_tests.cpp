#include "apps_core.hpp"
#include <cassert>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <string>
using namespace yetdns;
int main(int argc, char **argv) {
    assert(argc == 2 && application_count() == 43);
    assert(application_index("unknown") == -1 && application_index(nullptr) == -1);
    uint64_t youtube = UINT64_C(1) << application_index("youtube");
    uint64_t instagram = UINT64_C(1) << application_index("instagram");
    assert(!application_denied("youtube.com", 0));
    assert(application_denied("www.youtube.com", youtube));
    assert(application_denied("r1.googlevideo.com", youtube));
    assert(!application_denied("notyoutube.com", youtube));
    assert(!application_denied("youtube.com.evil.example", youtube));
    assert(!application_denied("google.com", application_valid_mask()));
    assert(!application_denied("youtube.com", instagram));
    assert(application_denied("cdninstagram.com", instagram));
    // Independent snapshot fixture exercises every domain/service mapping.
    std::ifstream fixture(argv[1]); assert(fixture);
    std::string id, name; size_t checked = 0;
    while (fixture >> id >> name) {
        int index = application_index(id.c_str()); assert(index >= 0);
        uint64_t mask = UINT64_C(1) << index;
        assert(application_denied(name.c_str(), mask));
        assert(application_denied(("sub." + name).c_str(), mask));
        assert(!application_denied((name + ".invalid").c_str(), mask));
        ++checked;
    }
    assert(checked > 400);
    AppsConfig cfg;
    assert(apps_config_valid(cfg));
    assert(apps_set_scope(cfg, 0, youtube));
    assert(apps_set_scope(cfg, 123, instagram));
    assert(apps_client_mask(cfg, 123) == (youtube | instagram));
    assert(apps_client_mask(cfg, 124) == youtube);
    assert(apps_set_scope(cfg, 123, 0) && cfg.count == 0);
    for (uint32_t i = 1; i <= app_client_max; ++i) assert(apps_set_scope(cfg, i, instagram));
    assert(!apps_set_scope(cfg, 100, youtube));
    assert(apps_set_scope(cfg, 1, youtube) && cfg.count == app_client_max);
    assert(apps_set_scope(cfg, 8, 0) && cfg.count == app_client_max - 1);
    assert(apps_set_scope(cfg, 100, youtube) && apps_config_valid(cfg));
    assert(!apps_set_scope(cfg, 0, UINT64_C(1) << 63));
    cfg.clients[0].address = cfg.clients[1].address; assert(!apps_config_valid(cfg));
    std::printf("Applications: %zu mappings, suffix boundaries, masks and device profiles passed\n", checked);
}
