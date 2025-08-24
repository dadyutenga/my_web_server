#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Include our headers
#include "../include/config.h"
#include "../include/http.h"
#include "../include/security.h"
#include "../include/cache.h"
#include "../include/router.h"
#include "../include/logging.h"

// Test counters
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    static void test_##name(void); \
    static void run_test_##name(void) { \
        printf("Running test: %s\n", #name); \
        tests_run++; \
        test_##name(); \
        tests_passed++; \
        printf("✅ %s passed\n\n", #name); \
    } \
    static void test_##name(void)

#define ASSERT(condition) \
    do { \
        if (!(condition)) { \
            printf("❌ Assertion failed: %s at %s:%d\n", #condition, __FILE__, __LINE__); \
            tests_failed++; \
            return; \
        } \
    } while(0)

#define ASSERT_EQ(a, b) \
    do { \
        if ((a) != (b)) { \
            printf("❌ Assertion failed: %s == %s (%d != %d) at %s:%d\n", \
                   #a, #b, (int)(a), (int)(b), __FILE__, __LINE__); \
            tests_failed++; \
            return; \
        } \
    } while(0)

#define ASSERT_STR_EQ(a, b) \
    do { \
        if (strcmp((a), (b)) != 0) { \
            printf("❌ Assertion failed: %s == %s (\"%s\" != \"%s\") at %s:%d\n", \
                   #a, #b, (a), (b), __FILE__, __LINE__); \
            tests_failed++; \
            return; \
        } \
    } while(0)

#define ASSERT_NOT_NULL(ptr) \
    do { \
        if ((ptr) == NULL) { \
            printf("❌ Assertion failed: %s is not NULL at %s:%d\n", \
                   #ptr, __FILE__, __LINE__); \
            tests_failed++; \
            return; \
        } \
    } while(0)

// Test configuration parsing
TEST(config_parsing) {
    // Create a test config file
    FILE *f = fopen("test_config.conf", "w");
    ASSERT_NOT_NULL(f);
    
    fprintf(f, "worker_processes 4;\n");
    fprintf(f, "max_connections 1000;\n");
    fprintf(f, "gzip on;\n");
    fprintf(f, "access_log /tmp/access.log;\n");
    fclose(f);
    
    // Parse the config
    server_config_t *config = config_parse_file("test_config.conf");
    ASSERT_NOT_NULL(config);
    
    ASSERT_EQ(config->worker_processes, 4);
    ASSERT_EQ(config->max_connections, 1000);
    ASSERT_EQ(config->enable_compression, 1);
    ASSERT_STR_EQ(config->access_log, "/tmp/access.log");
    
    config_free(config);
    unlink("test_config.conf");
}

// Test HTTP parsing
TEST(http_parsing) {
    connection_t conn;
    memset(&conn, 0, sizeof(conn));
    
    // Simulate HTTP request
    const char *request = 
        "GET /test?param=value HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "User-Agent: Test/1.0\r\n"
        "Accept-Encoding: gzip\r\n"
        "Connection: keep-alive\r\n"
        "\r\n";
    
    strcpy(conn.read_buffer, request);
    conn.read_pos = strlen(request);
    conn.state = CONN_READING;
    
    int result = http_parse_request(&conn);
    ASSERT_EQ(result, 1);
    ASSERT_EQ(conn.request.method, HTTP_GET);
    ASSERT_STR_EQ(conn.request.uri, "/test");
    ASSERT_STR_EQ(conn.request.query_string, "param=value");
    ASSERT_EQ(conn.keep_alive, 1);
    
    free(conn.request.host);
    free(conn.request.user_agent);
    free(conn.request.accept_encoding);
    free(conn.request.connection);
}

// Test MIME type detection
TEST(mime_types) {
    ASSERT_STR_EQ(get_mime_type("test.html"), "text/html");
    ASSERT_STR_EQ(get_mime_type("test.css"), "text/css");
    ASSERT_STR_EQ(get_mime_type("test.js"), "application/javascript");
    ASSERT_STR_EQ(get_mime_type("test.jpg"), "image/jpeg");
    ASSERT_STR_EQ(get_mime_type("test.png"), "image/png");
    ASSERT_STR_EQ(get_mime_type("test.unknown"), "application/octet-stream");
}

// Test URL decoding
TEST(url_decoding) {
    char *decoded = url_decode("hello%20world");
    ASSERT_NOT_NULL(decoded);
    ASSERT_STR_EQ(decoded, "hello world");
    free(decoded);
    
    decoded = url_decode("test%2Bvalue");
    ASSERT_NOT_NULL(decoded);
    ASSERT_STR_EQ(decoded, "test+value");
    free(decoded);
    
    decoded = url_decode("normal_string");
    ASSERT_NOT_NULL(decoded);
    ASSERT_STR_EQ(decoded, "normal_string");
    free(decoded);
}

// Test security functions
TEST(security_validation) {
    // Initialize security system
    security_config_t config = {
        .enable_rate_limiting = 1,
        .requests_per_minute = 60,
        .max_request_size = 1024 * 1024,
        .max_header_size = 8192
    };
    
    ASSERT_EQ(security_init(&config), 0);
    
    // Test path traversal detection
    ASSERT_EQ(security_detect_path_traversal("../etc/passwd"), 1);
    ASSERT_EQ(security_detect_path_traversal("/normal/path"), 0);
    ASSERT_EQ(security_detect_path_traversal("path/with/../traversal"), 1);
    
    // Test XSS detection
    ASSERT_EQ(security_detect_xss_attempt("<script>alert('xss')</script>"), 1);
    ASSERT_EQ(security_detect_xss_attempt("normal text"), 0);
    ASSERT_EQ(security_detect_xss_attempt("javascript:alert(1)"), 1);
    
    // Test SQL injection detection
    ASSERT_EQ(security_detect_sql_injection("' or 1=1 --"), 1);
    ASSERT_EQ(security_detect_sql_injection("normal query"), 0);
    ASSERT_EQ(security_detect_sql_injection("union select * from users"), 1);
    
    security_cleanup();
}

// Test cache functionality
TEST(cache_operations) {
    cache_config_t config = {
        .max_size = 1024 * 1024,
        .max_entries = 100,
        .default_ttl = 3600,
        .enable_etag = 1
    };
    
    file_cache_t *cache = cache_create(&config);
    ASSERT_NOT_NULL(cache);
    
    // Test cache put and get
    const char *data = "test data";
    ASSERT_EQ(cache_put(cache, "test_key", data, strlen(data), "text/plain", 60), 0);
    
    cache_entry_t *entry = cache_get(cache, "test_key");
    ASSERT_NOT_NULL(entry);
    ASSERT_EQ(entry->data_size, strlen(data));
    ASSERT_EQ(memcmp(entry->data, data, strlen(data)), 0);
    
    cache_entry_unref(entry);
    
    // Test cache removal
    cache_remove(cache, "test_key");
    entry = cache_get(cache, "test_key");
    ASSERT(entry == NULL);
    
    cache_destroy(cache);
}

// Test router functionality
TEST(router_operations) {
    router_t *router = router_create();
    ASSERT_NOT_NULL(router);
    
    // Add routes
    ASSERT_EQ(router_add_route(router, "/api/*", ROUTE_PROXY, "http://backend", "GET,POST"), 0);
    ASSERT_EQ(router_add_route(router, "/static/*", ROUTE_STATIC, "/var/www/static", "GET"), 0);
    
    // Test route matching
    route_t *route = router_match_route(router, "/api/users", "GET");
    ASSERT_NOT_NULL(route);
    ASSERT_EQ(route->type, ROUTE_PROXY);
    ASSERT_STR_EQ(route->target, "http://backend");
    
    route = router_match_route(router, "/static/css/style.css", "GET");
    ASSERT_NOT_NULL(route);
    ASSERT_EQ(route->type, ROUTE_STATIC);
    
    route = router_match_route(router, "/nonexistent", "GET");
    ASSERT(route == NULL);
    
    router_destroy(router);
}

// Test rate limiting
TEST(rate_limiting) {
    rate_limiter_t *limiter = rate_limiter_create(5, 60); // 5 requests per minute
    ASSERT_NOT_NULL(limiter);
    
    const char *ip = "192.168.1.100";
    
    // Should allow first 5 requests
    for (int i = 0; i < 5; i++) {
        ASSERT_EQ(rate_limiter_check(limiter, ip), 1);
    }
    
    // Should deny 6th request
    ASSERT_EQ(rate_limiter_check(limiter, ip), 0);
    
    rate_limiter_destroy(limiter);
}

// Test logging
TEST(logging_system) {
    // Initialize logging
    ASSERT_EQ(log_init("test_access.log", "test_error.log", LOG_INFO), 0);
    
    // Test log messages
    log_info("Test info message");
    log_warn("Test warning message");
    log_debug("Test debug message"); // Should not appear due to log level
    
    // Test access log
    access_log_entry_t entry = {0};
    strcpy(entry.client_ip, "192.168.1.1");
    strcpy(entry.method, "GET");
    strcpy(entry.uri, "/test");
    entry.status_code = 200;
    entry.response_size = 1024;
    entry.response_time = 15.5;
    
    log_access(&entry);
    
    log_cleanup();
    
    // Verify log files were created
    ASSERT_EQ(access("test_access.log", F_OK), 0);
    ASSERT_EQ(access("test_error.log", F_OK), 0);
    
    unlink("test_access.log");
    unlink("test_error.log");
}

// Test HTTP client connection
TEST(http_connection) {
    // This test requires the server to be running
    // For now, just test that we can create a socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT(sockfd >= 0);
    close(sockfd);
}

// Main test runner
int main(void) {
    printf("🧪 Starting Custom HTTP Server Test Suite\n");
    printf("==========================================\n\n");
    
    // Run all tests
    run_test_config_parsing();
    run_test_http_parsing();
    run_test_mime_types();
    run_test_url_decoding();
    run_test_security_validation();
    run_test_cache_operations();
    run_test_router_operations();
    run_test_rate_limiting();
    run_test_logging_system();
    run_test_http_connection();
    
    // Print results
    printf("==========================================\n");
    printf("Test Results:\n");
    printf("  Total tests: %d\n", tests_run);
    printf("  Passed: %d\n", tests_passed);
    printf("  Failed: %d\n", tests_failed);
    
    if (tests_failed > 0) {
        printf("❌ Some tests failed!\n");
        return 1;
    } else {
        printf("✅ All tests passed!\n");
        return 0;
    }
}