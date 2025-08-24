#include "../include/security.h"
#include "../include/logging.h"
#include <openssl/rand.h>
#include <openssl/sha.h>

// Global security variables
rate_limiter_t *g_rate_limiter = NULL;
security_config_t *g_security_config = NULL;
ip_ban_t *g_ip_ban_list = NULL;

// Connection count tracking
static struct {
    char ip[INET_ADDRSTRLEN];
    int count;
    struct timeval last_update;
} *g_connection_counts = NULL;
static int g_connection_count_size = 0;
static pthread_mutex_t g_connection_mutex = PTHREAD_MUTEX_INITIALIZER;

// Hash function for IP addresses
static unsigned int hash_ip(const char *ip) {
    unsigned int hash = 5381;
    for (int i = 0; ip[i]; i++) {
        hash = ((hash << 5) + hash) + ip[i];
    }
    return hash;
}

// Initialize security system
int security_init(security_config_t *config) {
    if (!config) {
        LOG_ERROR_MSG("Security configuration is NULL");
        return -1;
    }
    
    g_security_config = malloc(sizeof(security_config_t));
    if (!g_security_config) {
        LOG_ERROR_MSG("Failed to allocate security configuration");
        return -1;
    }
    
    memcpy(g_security_config, config, sizeof(security_config_t));
    
    // Initialize rate limiter
    if (config->enable_rate_limiting) {
        g_rate_limiter = rate_limiter_create(config->requests_per_minute, 60);
        if (!g_rate_limiter) {
            LOG_ERROR_MSG("Failed to create rate limiter");
            free(g_security_config);
            return -1;
        }
    }
    
    // Initialize connection count tracking
    g_connection_count_size = 1024;
    g_connection_counts = calloc(g_connection_count_size, 
                                sizeof(*g_connection_counts));
    if (!g_connection_counts) {
        LOG_ERROR_MSG("Failed to allocate connection count tracking");
        if (g_rate_limiter) rate_limiter_destroy(g_rate_limiter);
        free(g_security_config);
        return -1;
    }
    
    LOG_INFO_MSG("Security system initialized");
    return 0;
}

// Cleanup security system
void security_cleanup(void) {
    if (g_rate_limiter) {
        rate_limiter_destroy(g_rate_limiter);
        g_rate_limiter = NULL;
    }
    
    if (g_security_config) {
        free(g_security_config->blocked_ips);
        free(g_security_config->allowed_ips);
        free(g_security_config->csrf_secret);
        free(g_security_config);
        g_security_config = NULL;
    }
    
    // Free IP ban list
    ip_ban_t *current = g_ip_ban_list;
    while (current) {
        ip_ban_t *next = current->next;
        free(current);
        current = next;
    }
    g_ip_ban_list = NULL;
    
    // Free connection counts
    free(g_connection_counts);
    g_connection_counts = NULL;
    
    LOG_INFO_MSG("Security system cleaned up");
}

// Create rate limiter
rate_limiter_t *rate_limiter_create(int requests_per_window, int window_seconds) {
    rate_limiter_t *limiter = calloc(1, sizeof(rate_limiter_t));
    if (!limiter) {
        LOG_ERROR_MSG("Failed to allocate rate limiter");
        return NULL;
    }
    
    limiter->bucket_count = 1024;
    limiter->requests_per_window = requests_per_window;
    limiter->window_seconds = window_seconds;
    
    limiter->buckets = calloc(limiter->bucket_count, sizeof(rate_limit_entry_t*));
    if (!limiter->buckets) {
        LOG_ERROR_MSG("Failed to allocate rate limiter buckets");
        free(limiter);
        return NULL;
    }
    
    pthread_mutex_init(&limiter->mutex, NULL);
    
    LOG_INFO_MSG("Rate limiter created: %d requests per %d seconds", 
                 requests_per_window, window_seconds);
    return limiter;
}

// Destroy rate limiter
void rate_limiter_destroy(rate_limiter_t *limiter) {
    if (!limiter) return;
    
    pthread_mutex_lock(&limiter->mutex);
    
    for (int i = 0; i < limiter->bucket_count; i++) {
        rate_limit_entry_t *entry = limiter->buckets[i];
        while (entry) {
            rate_limit_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
    }
    
    free(limiter->buckets);
    pthread_mutex_unlock(&limiter->mutex);
    pthread_mutex_destroy(&limiter->mutex);
    free(limiter);
}

// Check rate limit for IP
int rate_limiter_check(rate_limiter_t *limiter, const char *ip) {
    if (!limiter || !ip) return 1;
    
    pthread_mutex_lock(&limiter->mutex);
    
    unsigned int bucket = hash_ip(ip) % limiter->bucket_count;
    rate_limit_entry_t *entry = limiter->buckets[bucket];
    
    struct timeval now;
    gettimeofday(&now, NULL);
    
    // Find existing entry for this IP
    while (entry) {
        if (strcmp(entry->ip, ip) == 0) {
            break;
        }
        entry = entry->next;
    }
    
    if (!entry) {
        // Create new entry
        entry = calloc(1, sizeof(rate_limit_entry_t));
        if (!entry) {
            pthread_mutex_unlock(&limiter->mutex);
            return 0;
        }
        
        strncpy(entry->ip, ip, INET_ADDRSTRLEN - 1);
        entry->window_start = now;
        entry->request_count = 1;
        entry->next = limiter->buckets[bucket];
        limiter->buckets[bucket] = entry;
        
        pthread_mutex_unlock(&limiter->mutex);
        return 1;
    }
    
    // Check if window has expired
    time_t window_elapsed = now.tv_sec - entry->window_start.tv_sec;
    if (window_elapsed >= limiter->window_seconds) {
        // Reset window
        entry->window_start = now;
        entry->request_count = 1;
        pthread_mutex_unlock(&limiter->mutex);
        return 1;
    }
    
    // Check if limit exceeded
    if (entry->request_count >= limiter->requests_per_window) {
        pthread_mutex_unlock(&limiter->mutex);
        LOG_WARN_MSG("Rate limit exceeded for IP: %s", ip);
        return 0;
    }
    
    entry->request_count++;
    pthread_mutex_unlock(&limiter->mutex);
    return 1;
}

// Cleanup expired rate limit entries
void rate_limiter_cleanup_expired(rate_limiter_t *limiter) {
    if (!limiter) return;
    
    pthread_mutex_lock(&limiter->mutex);
    
    struct timeval now;
    gettimeofday(&now, NULL);
    
    for (int i = 0; i < limiter->bucket_count; i++) {
        rate_limit_entry_t **entry_ptr = &limiter->buckets[i];
        
        while (*entry_ptr) {
            rate_limit_entry_t *entry = *entry_ptr;
            time_t window_elapsed = now.tv_sec - entry->window_start.tv_sec;
            
            if (window_elapsed >= limiter->window_seconds * 2) {
                // Remove expired entry
                *entry_ptr = entry->next;
                free(entry);
            } else {
                entry_ptr = &entry->next;
            }
        }
    }
    
    pthread_mutex_unlock(&limiter->mutex);
}

// Check if IP is allowed
int security_is_ip_allowed(const char *ip) {
    if (!g_security_config || !ip) return 1;
    
    // Check if IP is in allowed list
    if (g_security_config->allowed_ips) {
        for (int i = 0; i < g_security_config->allowed_ip_count; i++) {
            if (strcmp(g_security_config->allowed_ips[i], ip) == 0) {
                return 1;
            }
        }
        // If allowed list exists but IP not in it, deny
        return 0;
    }
    
    return 1;
}

// Check if IP is blocked
int security_is_ip_blocked(const char *ip) {
    if (!g_security_config || !ip) return 0;
    
    // Check permanent block list
    if (g_security_config->blocked_ips) {
        for (int i = 0; i < g_security_config->blocked_ip_count; i++) {
            if (strcmp(g_security_config->blocked_ips[i], ip) == 0) {
                return 1;
            }
        }
    }
    
    // Check temporary bans
    struct timeval now;
    gettimeofday(&now, NULL);
    
    ip_ban_t *ban = g_ip_ban_list;
    while (ban) {
        if (strcmp(ban->ip, ip) == 0) {
            time_t elapsed = now.tv_sec - ban->ban_time.tv_sec;
            if (elapsed < ban->ban_duration) {
                return 1;
            }
            // Ban expired, remove it
            // (In a production system, you'd want proper cleanup)
        }
        ban = ban->next;
    }
    
    return 0;
}

// Block IP temporarily
void security_block_ip(const char *ip, int duration) {
    if (!ip) return;
    
    ip_ban_t *ban = malloc(sizeof(ip_ban_t));
    if (!ban) {
        LOG_ERROR_MSG("Failed to allocate IP ban entry");
        return;
    }
    
    strncpy(ban->ip, ip, INET_ADDRSTRLEN - 1);
    gettimeofday(&ban->ban_time, NULL);
    ban->ban_duration = duration;
    ban->next = g_ip_ban_list;
    g_ip_ban_list = ban;
    
    LOG_WARN_MSG("IP %s banned for %d seconds", ip, duration);
}

// Unblock IP
void security_unblock_ip(const char *ip) {
    if (!ip) return;
    
    ip_ban_t **ban_ptr = &g_ip_ban_list;
    while (*ban_ptr) {
        ip_ban_t *ban = *ban_ptr;
        if (strcmp(ban->ip, ip) == 0) {
            *ban_ptr = ban->next;
            free(ban);
            LOG_INFO_MSG("IP %s unblocked", ip);
            return;
        }
        ban_ptr = &ban->next;
    }
}

// Validate HTTP request
int security_validate_request(connection_t *conn) {
    if (!conn || !g_security_config) return 1;
    
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &conn->client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    
    // Check if IP is allowed
    if (!security_is_ip_allowed(client_ip)) {
        LOG_WARN_MSG("IP not in allowed list: %s", client_ip);
        return 0;
    }
    
    // Check if IP is blocked
    if (security_is_ip_blocked(client_ip)) {
        LOG_WARN_MSG("Blocked IP attempted connection: %s", client_ip);
        return 0;
    }
    
    // Validate request size
    if (conn->request.content_length > g_security_config->max_request_size) {
        LOG_WARN_MSG("Request too large from %s: %zu bytes", 
                     client_ip, conn->request.content_length);
        return 0;
    }
    
    // Validate headers
    if (!security_validate_headers(conn->request.headers)) {
        LOG_WARN_MSG("Invalid headers from %s", client_ip);
        return 0;
    }
    
    // Validate URI
    if (!security_validate_uri(conn->request.uri)) {
        LOG_WARN_MSG("Invalid URI from %s: %s", client_ip, conn->request.uri);
        return 0;
    }
    
    // Validate HTTP method
    if (!security_validate_method(conn->request.method)) {
        LOG_WARN_MSG("Invalid method from %s: %d", client_ip, conn->request.method);
        return 0;
    }
    
    return 1;
}

// Validate headers
int security_validate_headers(const char *headers) {
    if (!headers || !g_security_config) return 1;
    
    // Check header size
    if (strlen(headers) > g_security_config->max_header_size) {
        return 0;
    }
    
    // Check for suspicious headers
    if (strstr(headers, "\0") || strstr(headers, "\r\r") || strstr(headers, "\n\n")) {
        return 0;
    }
    
    return 1;
}

// Validate URI
int security_validate_uri(const char *uri) {
    if (!uri) return 0;
    
    // Check for path traversal
    if (security_detect_path_traversal(uri)) {
        return 0;
    }
    
    // Check for XSS attempts
    if (security_detect_xss_attempt(uri)) {
        return 0;
    }
    
    // Check for SQL injection
    if (security_detect_sql_injection(uri)) {
        return 0;
    }
    
    return 1;
}

// Validate HTTP method
int security_validate_method(http_method_t method) {
    // Allow common methods
    switch (method) {
        case HTTP_GET:
        case HTTP_POST:
        case HTTP_PUT:
        case HTTP_DELETE:
        case HTTP_HEAD:
        case HTTP_OPTIONS:
            return 1;
        default:
            return 0;
    }
}

// Check connection limit per IP
int security_check_connection_limit(const char *ip) {
    if (!ip || !g_connection_counts) return 1;
    
    pthread_mutex_lock(&g_connection_mutex);
    
    // Find entry for this IP
    for (int i = 0; i < g_connection_count_size; i++) {
        if (strlen(g_connection_counts[i].ip) == 0) {
            // Empty slot, IP not found
            break;
        }
        
        if (strcmp(g_connection_counts[i].ip, ip) == 0) {
            // Check connection limit (simple implementation: max 10 per IP)
            if (g_connection_counts[i].count >= 10) {
                pthread_mutex_unlock(&g_connection_mutex);
                return 0;
            }
            break;
        }
    }
    
    pthread_mutex_unlock(&g_connection_mutex);
    return 1;
}

// Update connection count for IP
void security_update_connection_count(const char *ip, int increment) {
    if (!ip || !g_connection_counts) return;
    
    pthread_mutex_lock(&g_connection_mutex);
    
    // Find or create entry for this IP
    int slot = -1;
    for (int i = 0; i < g_connection_count_size; i++) {
        if (strlen(g_connection_counts[i].ip) == 0) {
            slot = i;
            break;
        }
        
        if (strcmp(g_connection_counts[i].ip, ip) == 0) {
            slot = i;
            break;
        }
    }
    
    if (slot >= 0) {
        if (strlen(g_connection_counts[slot].ip) == 0) {
            strncpy(g_connection_counts[slot].ip, ip, INET_ADDRSTRLEN - 1);
            g_connection_counts[slot].count = 0;
        }
        
        g_connection_counts[slot].count += increment;
        if (g_connection_counts[slot].count < 0) {
            g_connection_counts[slot].count = 0;
        }
        
        gettimeofday(&g_connection_counts[slot].last_update, NULL);
    }
    
    pthread_mutex_unlock(&g_connection_mutex);
}

// Add security headers
void security_add_headers(char *headers) {
    if (!headers) return;
    
    strcat(headers, "X-Content-Type-Options: nosniff\r\n");
    strcat(headers, "X-Frame-Options: DENY\r\n");
    strcat(headers, "X-XSS-Protection: 1; mode=block\r\n");
    strcat(headers, "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n");
    strcat(headers, "Content-Security-Policy: default-src 'self'\r\n");
}

// Detect path traversal
int security_detect_path_traversal(const char *path) {
    if (!path) return 0;
    
    if (strstr(path, "../") || strstr(path, "..\\") || 
        strstr(path, "%2e%2e") || strstr(path, "%2E%2E")) {
        return 1;
    }
    
    return 0;
}

// Detect XSS attempts
int security_detect_xss_attempt(const char *input) {
    if (!input) return 0;
    
    const char *xss_patterns[] = {
        "<script", "</script>", "javascript:", "onload=", 
        "onerror=", "onclick=", "onmouseover=", NULL
    };
    
    for (int i = 0; xss_patterns[i]; i++) {
        if (strcasestr(input, xss_patterns[i])) {
            return 1;
        }
    }
    
    return 0;
}

// Detect SQL injection
int security_detect_sql_injection(const char *input) {
    if (!input) return 0;
    
    const char *sql_patterns[] = {
        "' or ", " or '", "union select", "drop table", 
        "delete from", "insert into", "update set", NULL
    };
    
    for (int i = 0; sql_patterns[i]; i++) {
        if (strcasestr(input, sql_patterns[i])) {
            return 1;
        }
    }
    
    return 0;
}

// Generate CSRF token
char *security_generate_csrf_token(void) {
    unsigned char random_bytes[32];
    if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
        return NULL;
    }
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(random_bytes, sizeof(random_bytes), hash);
    
    char *token = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
    if (!token) return NULL;
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(token + i * 2, "%02x", hash[i]);
    }
    
    return token;
}

// Validate CSRF token
int security_validate_csrf_token(const char *token) {
    if (!token || strlen(token) != SHA256_DIGEST_LENGTH * 2) {
        return 0;
    }
    
    // Simple validation - in production, you'd store and verify tokens
    return 1;
}