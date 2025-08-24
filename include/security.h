#ifndef SECURITY_H
#define SECURITY_H

#include "server.h"
#include <sys/time.h>

// Rate limiting structures
typedef struct rate_limit_entry {
    char ip[INET_ADDRSTRLEN];
    int request_count;
    struct timeval window_start;
    struct rate_limit_entry *next;
} rate_limit_entry_t;

typedef struct rate_limiter {
    rate_limit_entry_t **buckets;
    int bucket_count;
    int requests_per_window;
    int window_seconds;
    pthread_mutex_t mutex;
} rate_limiter_t;

// Security configuration
typedef struct security_config {
    int enable_rate_limiting;
    int requests_per_minute;
    int ban_duration;
    char **blocked_ips;
    int blocked_ip_count;
    char **allowed_ips;
    int allowed_ip_count;
    int max_request_size;
    int max_header_size;
    int enable_csrf_protection;
    char *csrf_secret;
} security_config_t;

// IP ban list entry
typedef struct ip_ban {
    char ip[INET_ADDRSTRLEN];
    struct timeval ban_time;
    int ban_duration;
    struct ip_ban *next;
} ip_ban_t;

// Security functions
int security_init(security_config_t *config);
void security_cleanup(void);

// Rate limiting
rate_limiter_t *rate_limiter_create(int requests_per_window, int window_seconds);
void rate_limiter_destroy(rate_limiter_t *limiter);
int rate_limiter_check(rate_limiter_t *limiter, const char *ip);
void rate_limiter_cleanup_expired(rate_limiter_t *limiter);

// IP filtering
int security_is_ip_allowed(const char *ip);
int security_is_ip_blocked(const char *ip);
void security_block_ip(const char *ip, int duration);
void security_unblock_ip(const char *ip);

// Request validation
int security_validate_request(connection_t *conn);
int security_validate_headers(const char *headers);
int security_validate_uri(const char *uri);
int security_validate_method(http_method_t method);

// DDoS protection
int security_check_connection_limit(const char *ip);
void security_update_connection_count(const char *ip, int increment);

// CSRF protection
char *security_generate_csrf_token(void);
int security_validate_csrf_token(const char *token);

// Security headers
void security_add_headers(char *headers);
void security_add_csp_header(char *headers, const char *policy);
void security_add_hsts_header(char *headers);

// Input sanitization
char *security_sanitize_input(const char *input);
char *security_escape_html(const char *input);
int security_validate_filename(const char *filename);

// Attack detection
int security_detect_sql_injection(const char *input);
int security_detect_xss_attempt(const char *input);
int security_detect_path_traversal(const char *path);

// Global security context
extern rate_limiter_t *g_rate_limiter;
extern security_config_t *g_security_config;
extern ip_ban_t *g_ip_ban_list;

#endif // SECURITY_H