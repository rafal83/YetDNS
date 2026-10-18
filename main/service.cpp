#include "service.hpp"
#include "lists.hpp"
#include "apps.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <unistd.h>
#include "lwip/sockets.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/queue.h"
#include "freertos/task.h"

namespace yetdns {
Counters stats;
std::atomic<bool> blocking{true}, flush_cache{false};
std::atomic<uint32_t> subnet_ip{}, subnet_mask{};
Blocklist blocklist;
Rules rules;
SemaphoreHandle_t rules_mutex;
static Cache cache(nullptr, 0);
static portMUX_TYPE log_lock = portMUX_INITIALIZER_UNLOCKED;
static LogEntry logs[32];
static size_t log_next{}, log_count{};
static uint32_t seconds_now() { return esp_timer_get_time() / 1000000; }
size_t copy_logs(LogEntry *out, size_t capacity) {
    portENTER_CRITICAL(&log_lock);
    size_t count = std::min(capacity, log_count);
    for (size_t i = 0; i < count; ++i) out[i] = logs[(log_next + 31 - i) % 32];
    portEXIT_CRITICAL(&log_lock);
    return count;
}
void clear_logs() {
    portENTER_CRITICAL(&log_lock); log_next = log_count = 0; portEXIT_CRITICAL(&log_lock);
}
static void record(const Question &q, uint32_t client, const char *result, int64_t start) {
    if (!query_logging) return;
    uint32_t elapsed = esp_timer_get_time() - start;
    portENTER_CRITICAL(&log_lock);
    auto &entry = logs[log_next++ % 32];
    strlcpy(entry.domain, q.name, sizeof(entry.domain));
    strlcpy(entry.result, result, sizeof(entry.result));
    entry.client = client; entry.type = q.type; entry.elapsed_us = elapsed;
    log_count = std::min<size_t>(32, log_count + 1);
    portEXIT_CRITICAL(&log_lock);
}
struct Job {
    uint8_t packet[packet_max], original[cache_key_max];
    size_t n{}, original_n{};
    sockaddr_in peer{};
    int tcp{-1}; uint32_t generation{};
    int64_t started{};
    bool cacheable{}, success{};
};
static Job jobs[CONFIG_YETDNS_PENDING];
static QueueHandle_t free_jobs, work_jobs, done_jobs;
struct Client {
    int fd{-1}; uint32_t generation{};
    sockaddr_in peer{};
    uint8_t buffer[packet_max + 2];
    size_t received{}, expected{}, output{}, sent{};
    bool busy{}; uint32_t touched{};
};
static Client clients[4];
struct Bucket { uint32_t address{}, second{}; unsigned count{}; };
static Bucket buckets[32];
static bool permitted(uint32_t addr) {
    if (!subnet_only) return true;
    uint32_t mask = subnet_mask.load();
    return mask && (addr & mask) == (subnet_ip.load() & mask);
}
static bool rate_ok(uint32_t addr) {
    uint32_t limit = query_limit.load();
    if (!limit) return true;
    uint32_t now = seconds_now();
    Bucket *available = nullptr;
    for (auto &b : buckets) {
        if (b.address == addr) {
            if (b.second != now) { b.second = now; b.count = 0; }
            return ++b.count <= limit;
        }
        if (!b.address || b.second != now) available = &b;
    }
    if (!available) return false;
    *available = {addr, now, 1}; return true;
}
static bool policy(const Question &q, uint32_t client, Action &action, uint8_t *address) {
    xSemaphoreTake(rules_mutex, portMAX_DELAY);
    bool found = evaluate_rules(rules, q.name, client, action, address);
    xSemaphoreGive(rules_mutex);
    if (!found && apps_denied(q.name, client)) { action = Action::deny; found = true; }
    return found;
}
static bool alias_denied(const char *name, void *context) {
    Question q; strlcpy(q.name, name, sizeof(q.name));
    Action action{}; uint8_t address[4]{};
    uint32_t client = *static_cast<uint32_t *>(context);
    bool custom = policy(q, client, action, address);
    return blocking && (custom ? action == Action::deny : filter_contains(name));
}
static bool check_aliases(const uint8_t *packet, size_t n, uint32_t client, bool &denied) {
    return inspect_aliases(packet, n, alias_denied, &client, denied);
}
static size_t blocked_reply(const uint8_t *query, size_t n, uint8_t *out) {
    uint32_t address = block_page_enabled ? subnet_ip.load() : 0;
    return reply(query, n, out, 0, address ? reinterpret_cast<const uint8_t *>(&address) : nullptr, true);
}
static bool recv_exact(int fd, uint8_t *out, size_t n) {
    size_t pos = 0;
    while (pos < n) { int got = recv(fd, out + pos, n - pos, 0); if (got <= 0) return false; pos += got; }
    return true;
}
static bool send_exact(int fd, const uint8_t *data, size_t n) {
    size_t pos = 0;
    while (pos < n) { int sent = send(fd, data + pos, n - pos, 0); if (sent <= 0) return false; pos += sent; }
    return true;
}
static int upstream_socket(const char *ip, int type, uint32_t timeout_ms) {
    int fd = socket(AF_INET, type, 0);
    if (fd < 0) return -1;
    timeval timeout{int(timeout_ms / 1000), int(timeout_ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(53);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1 || connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        close(fd); return -1;
    }
    return fd;
}
static size_t udp_resolve(const char *ip, const uint8_t *query, size_t n, uint8_t *out, uint32_t timeout_ms) {
    int fd = upstream_socket(ip, SOCK_DGRAM, timeout_ms);
    if (fd < 0) return 0;
    // Fresh socket per miss randomizes the ephemeral source port; connected UDP checks source.
    int got = 0;
    if (send(fd, query, n, 0) == int(n)) {
        int64_t deadline = esp_timer_get_time() + timeout_ms * 1000ll;
        do { got = recv(fd, out, packet_max, 0); }
        while (got > 0 && !matching_response(out, got, query, n) && esp_timer_get_time() < deadline);
    }
    close(fd);
    if (got <= 0 || !matching_response(out, got, query, n)) return 0;
    if (!(out[2] & 2)) return got;
    // RFC 7766: retry truncated upstream replies over TCP.
    fd = upstream_socket(ip, SOCK_STREAM, timeout_ms);
    if (fd < 0) return 0;
    uint8_t prefix[2]; write16(prefix, n);
    size_t result = 0;
    if (send_exact(fd, prefix, 2) && send_exact(fd, query, n) && recv_exact(fd, prefix, 2)) {
        size_t len = read16(prefix);
        if (len >= 12 && len <= packet_max && recv_exact(fd, out, len) && matching_response(out, len, query, n)) result = len;
    }
    close(fd); return result;
}
struct HttpBody { uint8_t *data{}; size_t size{}; bool overflow{}, content_type{}; };
static esp_err_t http_event(esp_http_client_event_t *event) {
    auto *body = static_cast<HttpBody *>(event->user_data);
    if (event->event_id == HTTP_EVENT_ON_HEADER && !strcasecmp(event->header_key, "Content-Type"))
        body->content_type = !strcasecmp(event->header_value, "application/dns-message");
    if (event->event_id == HTTP_EVENT_ON_DATA) {
        if (event->data_len < 0 || body->size + size_t(event->data_len) > packet_max) body->overflow = true;
        else { std::memcpy(body->data + body->size, event->data, event->data_len); body->size += event->data_len; }
    }
    return ESP_OK;
}
static void worker(void *) {
    uint8_t response[packet_max];
    HttpBody body{response};
    esp_http_client_handle_t http = nullptr;
    char active_url[384]{};
    for (;;) {
        Job *job;
        xQueueReceive(work_jobs, &job, portMAX_DELAY);
        size_t rn = 0;
        if (esp_timer_get_time() - job->started < 4000000) {
            write16(job->packet, esp_random());
            RuntimeConfig settings = runtime_snapshot();
            if (settings.doh) {
            if (http && std::strcmp(active_url, settings.doh_url)) { esp_http_client_cleanup(http); http = nullptr; }
            if (!http) {
                esp_http_client_config_t cfg{};
                cfg.url = settings.doh_url; cfg.method = HTTP_METHOD_POST; cfg.timeout_ms = settings.timeout_ms;
                cfg.crt_bundle_attach = esp_crt_bundle_attach; cfg.event_handler = http_event; cfg.user_data = &body;
                cfg.keep_alive_enable = true; cfg.disable_auto_redirect = true;
                http = esp_http_client_init(&cfg);
                if (http) {
                    strlcpy(active_url, settings.doh_url, sizeof(active_url));
                    esp_http_client_set_header(http, "Content-Type", "application/dns-message");
                    esp_http_client_set_header(http, "Accept", "application/dns-message");
                    esp_http_client_set_header(http, "Cache-Control", "no-store");
                }
            }
            // No plaintext fallback. Require a synchronized clock for certificate validity.
            if (http && time(nullptr) > 1735689600) {
                body = {response};
                esp_http_client_set_timeout_ms(http, settings.timeout_ms);
                esp_http_client_set_post_field(http, reinterpret_cast<const char *>(job->packet), job->n);
                esp_err_t err = esp_http_client_perform(http);
                if (err == ESP_OK && esp_http_client_get_status_code(http) == 200 && body.content_type && !body.overflow &&
                    matching_response(response, body.size, job->packet, job->n)) rn = body.size;
                if (!rn) esp_http_client_close(http);
            }
            } else {
            if (http) { esp_http_client_cleanup(http); http = nullptr; }
            rn = udp_resolve(settings.primary, job->packet, job->n, response, settings.timeout_ms);
            if (!rn || (read16(response + 2) & 15) == 2)
                rn = udp_resolve(settings.secondary, job->packet, job->n, response, settings.timeout_ms);
            }
        }
        job->success = rn != 0;
        if (rn) { std::memcpy(job->packet, response, rn); std::memcpy(job->packet, job->original, 2); job->n = rn; }
        else job->n = reply(job->original, job->original_n, job->packet, 2);
        xQueueSend(done_jobs, &job, portMAX_DELAY);
    }
}
static void disconnect(Client &c) {
    if (c.fd >= 0) close(c.fd);
    c.fd = -1; ++c.generation; c.received = c.expected = c.output = c.sent = 0; c.busy = false;
}
static void deliver(int udp, int tcp, uint32_t generation, const sockaddr_in &peer,
                    const uint8_t *query, size_t qn, const uint8_t *data, size_t n) {
    if (tcp >= 0) {
        auto &c = clients[tcp];
        if (c.fd < 0 || c.generation != generation) return;
        write16(c.buffer, n); std::memcpy(c.buffer + 2, data, n);
        c.output = n + 2; c.sent = 0; c.busy = false; c.touched = seconds_now();
    } else {
        Question q; uint8_t tc[288];
        if (parse_query(query, qn, q) && n > q.udp_size) {
            n = reply(query, qn, tc, 0, nullptr, false, true); data = tc;
        }
        sendto(udp, data, n, 0, reinterpret_cast<const sockaddr *>(&peer), sizeof(peer));
    }
}
static void process(int udp, int tcp, uint32_t generation, const sockaddr_in &peer, const uint8_t *query, size_t n) {
    int64_t start = esp_timer_get_time();
    ++stats.queries;
    uint8_t response[packet_max], address[4]{}; Question q;
    size_t rn = 0; const char *result = "forwarded";
    if (!rate_ok(peer.sin_addr.s_addr)) { ++stats.limited; rn = reply(query, n, response, 5); result = "limited"; }
    else if (!parse_query(query, n, q)) { ++stats.errors; rn = reply(query, n, response, 1); result = "invalid"; }
    else {
        Action action = Action::allow;
        bool custom = policy(q, peer.sin_addr.s_addr, action, address);
        if (custom && action == Action::rewrite) {
            rn = reply(query, n, response, 0, address); result = "rewrite";
        } else if (blocking && ((custom && action == Action::deny) || (!custom && filter_contains(q.name)))) {
            rn = blocked_reply(query, n, response); result = "blocked"; ++stats.blocked;
        } else if ((rn = cache.get(query, n, response, seconds_now()))) {
            bool denied = false;
            if (!(custom && action == Action::allow) && !check_aliases(response, rn, peer.sin_addr.s_addr, denied)) {
                rn = reply(query, n, response, 2); ++stats.errors; result = "error";
            } else if (denied) { rn = blocked_reply(query, n, response); ++stats.blocked; result = "blocked"; }
            else { ++stats.cached; result = "cache"; }
        }
        else {
            Job *job;
            if (xQueueReceive(free_jobs, &job, 0) == pdTRUE) {
                std::memcpy(job->packet, query, n); job->n = n;
                job->cacheable = q.cacheable;
                job->original_n = n <= cache_key_max ? n : q.end;
                std::memcpy(job->original, query, job->original_n);
                if (n > cache_key_max) write16(job->original + 10, 0);
                job->peer = peer; job->tcp = tcp; job->generation = generation; job->started = start;
                if (tcp >= 0) clients[tcp].busy = true;
                xQueueSend(work_jobs, &job, 0); ++stats.forwarded;
                return;
            }
            ++stats.overload; rn = reply(query, n, response, 2); result = "overload";
        }
    }
    deliver(udp, tcp, generation, peer, query, n, response, rn);
    record(q, peer.sin_addr.s_addr, result, start);
}
static int listener(int type) {
    int fd = socket(AF_INET, type, 0);
    if (fd < 0) return -1;
    int reuse = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(53); address.sin_addr.s_addr = INADDR_ANY;
    if (bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) < 0 ||
        (type == SOCK_STREAM && listen(fd, 4) < 0)) { close(fd); return -1; }
    fcntl(fd, F_SETFL, O_NONBLOCK); return fd;
}
static void server(void *) {
    int udp = listener(SOCK_DGRAM), tcp = listener(SOCK_STREAM);
    if (udp < 0 || tcp < 0) {
        ESP_LOGE("yetdns", "Cannot bind DNS sockets");
        if (udp >= 0) close(udp);
        if (tcp >= 0) close(tcp);
        vTaskDelete(nullptr); return;
    }
    uint8_t packet[packet_max + 1];
    int64_t busy_since = 0;
    for (;;) {
        if (flush_cache.exchange(false)) cache.clear();
        Job *job;
        while (xQueueReceive(done_jobs, &job, 0) == pdTRUE) {
            Question q; parse_query(job->original, job->original_n, q);
            bool denied = false; Action action{}; uint8_t address[4]{};
            bool allowed = policy(q, job->peer.sin_addr.s_addr, action, address) && action == Action::allow;
            if (job->success && !(job->packet[2] & 2) && !allowed) {
                if (!check_aliases(job->packet, job->n, job->peer.sin_addr.s_addr, denied)) {
                    job->success = false; job->n = reply(job->original, job->original_n, job->packet, 2);
                } else if (denied) {
                    job->n = blocked_reply(job->original, job->original_n, job->packet);
                    job->cacheable = false; ++stats.blocked;
                }
            }
            if (job->success && job->cacheable) cache.put(job->original, job->original_n, job->packet, job->n, seconds_now());
            if (!job->success) ++stats.errors;
            deliver(udp, job->tcp, job->generation, job->peer, job->original, job->original_n, job->packet, job->n);
            record(q, job->peer.sin_addr.s_addr, denied ? "blocked" : job->success ? "forwarded" : "error", job->started);
            xQueueSend(free_jobs, &job, 0);
        }
        fd_set reads, writes; FD_ZERO(&reads); FD_ZERO(&writes);
        FD_SET(udp, &reads); FD_SET(tcp, &reads); int highest = std::max(udp, tcp);
        for (auto &c : clients) if (c.fd >= 0) {
            if (seconds_now() - c.touched >= 10) { disconnect(c); continue; }
            if (c.output) FD_SET(c.fd, &writes); else if (!c.busy) FD_SET(c.fd, &reads);
            highest = std::max(highest, c.fd);
        }
        timeval timeout{0, 2000};
        int ready = select(highest + 1, &reads, &writes, nullptr, &timeout);
        if (ready <= 0) { busy_since = 0; continue; }
        int64_t now_us = esp_timer_get_time();
        if (!busy_since) busy_since = now_us;
        if (now_us - busy_since >= 500000) {
            // Continuous traffic must still let the idle task feed the watchdog.
            // Ordinary select timeouts reset this timer, so quiet LANs add no delay.
            vTaskDelay(1); busy_since = 0;
        }
        if (FD_ISSET(udp, &reads)) {
            // Bounded batch: sustain bursts without starving TCP or completions.
            for (int i = 0; i < 8; ++i) {
                sockaddr_in peer{}; socklen_t len = sizeof(peer);
                int n = recvfrom(udp, packet, sizeof(packet), 0, reinterpret_cast<sockaddr *>(&peer), &len);
                if (n < 0) break;
                if (n >= 12 && n <= int(packet_max) && permitted(peer.sin_addr.s_addr)) process(udp, -1, 0, peer, packet, n);
            }
        }
        if (FD_ISSET(tcp, &reads)) {
            sockaddr_in peer{}; socklen_t len = sizeof(peer);
            int fd = accept(tcp, reinterpret_cast<sockaddr *>(&peer), &len);
            if (fd >= 0) {
                bool taken = false;
                if (permitted(peer.sin_addr.s_addr)) for (auto &c : clients) if (c.fd < 0) {
                    c.fd = fd; c.peer = peer; c.touched = seconds_now(); fcntl(fd, F_SETFL, O_NONBLOCK); taken = true; break;
                }
                if (!taken) close(fd);
            }
        }
        for (size_t i = 0; i < 4; ++i) {
            auto &c = clients[i];
            if (c.fd < 0) continue;
            if (FD_ISSET(c.fd, &writes) && c.output) {
                int sent = send(c.fd, c.buffer + c.sent, c.output - c.sent, 0);
                if (sent > 0) { c.sent += sent; c.touched = seconds_now(); if (c.sent == c.output) c.output = c.sent = c.received = c.expected = 0; }
                else if (sent == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) disconnect(c);
            } else if (FD_ISSET(c.fd, &reads) && !c.busy && !c.output) {
                size_t target = c.expected ? c.expected + 2 : 2;
                int got = recv(c.fd, c.buffer + c.received, target - c.received, 0);
                if (got <= 0) { if (!got || (errno != EAGAIN && errno != EWOULDBLOCK)) disconnect(c); continue; }
                c.received += got; c.touched = seconds_now();
                if (c.received == 2 && !c.expected) {
                    c.expected = read16(c.buffer);
                    if (c.expected < 12 || c.expected > packet_max) { disconnect(c); continue; }
                }
                if (c.expected && c.received == c.expected + 2) process(udp, i, c.generation, c.peer, c.buffer + 2, c.expected);
            }
        }
    }
}
esp_err_t service_start() {
    extern const uint8_t list_start[] asm("_binary_blocklist_bin_start");
    extern const uint8_t list_end[] asm("_binary_blocklist_bin_end");
    if (!blocklist.load(list_start, list_end - list_start)) return ESP_ERR_INVALID_CRC;
    ESP_ERROR_CHECK(lists_init());
    ESP_LOGW("yetdns", "%lu exact domains in flash; Wi-Fi power save disabled", (unsigned long)blocklist.count());
    // Allocate once at startup; leave internal RAM to Wi-Fi/TLS when PSRAM is enabled.
    auto *entries = static_cast<CacheEntry *>(heap_caps_calloc(CONFIG_YETDNS_CACHE_ENTRIES, sizeof(CacheEntry), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    if (!entries) entries = static_cast<CacheEntry *>(heap_caps_calloc(CONFIG_YETDNS_CACHE_ENTRIES, sizeof(CacheEntry), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
    if (!entries) return ESP_ERR_NO_MEM;
    cache = Cache(entries, CONFIG_YETDNS_CACHE_ENTRIES);
    free_jobs = xQueueCreate(CONFIG_YETDNS_PENDING, sizeof(Job *));
    work_jobs = xQueueCreate(CONFIG_YETDNS_PENDING, sizeof(Job *));
    done_jobs = xQueueCreate(CONFIG_YETDNS_PENDING, sizeof(Job *));
    if (!free_jobs || !work_jobs || !done_jobs) return ESP_ERR_NO_MEM;
    for (auto &j : jobs) { Job *ptr = &j; xQueueSend(free_jobs, &ptr, 0); }
    for (int i = 0; i < CONFIG_YETDNS_WORKERS; ++i)
        if (xTaskCreate(worker, "dns_upstream", 10240, nullptr, 5, nullptr) != pdPASS) return ESP_ERR_NO_MEM;
    if (xTaskCreate(server, "dns_server", 12288, nullptr, 8, nullptr) != pdPASS) return ESP_ERR_NO_MEM;
    return ESP_OK;
}
} // namespace yetdns
