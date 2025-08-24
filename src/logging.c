#include "../include/logging.h"
#include <syslog.h>
#include <stdarg.h>

// Global logger
logger_t *g_logger = NULL;

// Log level names
static const char *log_level_names[] = {
    "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

// Initialize logging system
int log_init(const char *access_log_file, const char *error_log_file, log_level_t level) {
    g_logger = calloc(1, sizeof(logger_t));
    if (!g_logger) {
        fprintf(stderr, "Failed to allocate logger\n");
        return -1;
    }
    
    g_logger->level = level;
    pthread_mutex_init(&g_logger->mutex, NULL);
    
    // Open access log
    if (access_log_file) {
        g_logger->access_log = fopen(access_log_file, "a");
        if (!g_logger->access_log) {
            fprintf(stderr, "Failed to open access log: %s\n", access_log_file);
        }
    }
    
    // Open error log
    if (error_log_file) {
        g_logger->error_log = fopen(error_log_file, "a");
        if (!g_logger->error_log) {
            fprintf(stderr, "Failed to open error log: %s\n", error_log_file);
        }
    }
    
    // Set default log format
    g_logger->log_format = strdup("%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"");
    
    printf("Logging system initialized (level: %s)\n", log_level_names[level]);
    return 0;
}

// Cleanup logging system
void log_cleanup(void) {
    if (!g_logger) return;
    
    pthread_mutex_lock(&g_logger->mutex);
    
    if (g_logger->access_log) {
        fclose(g_logger->access_log);
    }
    
    if (g_logger->error_log) {
        fclose(g_logger->error_log);
    }
    
    if (g_logger->general_log) {
        fclose(g_logger->general_log);
    }
    
    free(g_logger->log_format);
    
    pthread_mutex_unlock(&g_logger->mutex);
    pthread_mutex_destroy(&g_logger->mutex);
    
    free(g_logger);
    g_logger = NULL;
}

// Format timestamp
char *log_format_timestamp(void) {
    static char timestamp[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    
    strftime(timestamp, sizeof(timestamp), "%d/%b/%Y:%H:%M:%S %z", tm_info);
    return timestamp;
}

// Get log level string
const char *log_level_to_string(log_level_t level) {
    if (level >= 0 && level < sizeof(log_level_names) / sizeof(log_level_names[0])) {
        return log_level_names[level];
    }
    return "UNKNOWN";
}

// Log access entry
void log_access(const access_log_entry_t *entry) {
    if (!g_logger || !g_logger->access_log || !entry) return;
    
    pthread_mutex_lock(&g_logger->mutex);
    
    fprintf(g_logger->access_log,
            "%s - - [%s] \"%s %s HTTP/1.1\" %d %zu \"%s\" \"%s\" %.3f\n",
            entry->client_ip,
            entry->timestamp,
            entry->method,
            entry->uri,
            entry->status_code,
            entry->response_size,
            entry->referer[0] ? entry->referer : "-",
            entry->user_agent[0] ? entry->user_agent : "-",
            entry->response_time);
    
    fflush(g_logger->access_log);
    pthread_mutex_unlock(&g_logger->mutex);
}

// Generic error logging function
void log_error(log_level_t level, const char *format, ...) {
    if (!g_logger || level < g_logger->level) return;
    
    pthread_mutex_lock(&g_logger->mutex);
    
    char timestamp[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    FILE *output = g_logger->error_log ? g_logger->error_log : stderr;
    
    fprintf(output, "[%s] [%s] ", timestamp, log_level_to_string(level));
    
    va_list args;
    va_start(args, format);
    vfprintf(output, format, args);
    va_end(args);
    
    fprintf(output, "\n");
    fflush(output);
    
    pthread_mutex_unlock(&g_logger->mutex);
    
    // Also log to syslog if enabled
    if (g_logger->syslog_enabled) {
        int syslog_level;
        switch (level) {
            case LOG_DEBUG: syslog_level = LOG_DEBUG; break;
            case LOG_INFO: syslog_level = LOG_INFO; break;
            case LOG_WARN: syslog_level = LOG_WARNING; break;
            case LOG_ERROR: syslog_level = LOG_ERR; break;
            case LOG_FATAL: syslog_level = LOG_CRIT; break;
            default: syslog_level = LOG_INFO; break;
        }
        
        va_start(args, format);
        vsyslog(syslog_level, format, args);
        va_end(args);
    }
}

// Convenience logging functions
void log_info(const char *format, ...) {
    if (!g_logger || LOG_INFO < g_logger->level) return;
    
    va_list args;
    va_start(args, format);
    
    pthread_mutex_lock(&g_logger->mutex);
    
    char timestamp[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    FILE *output = g_logger->error_log ? g_logger->error_log : stdout;
    fprintf(output, "[%s] [INFO] ", timestamp);
    vfprintf(output, format, args);
    fprintf(output, "\n");
    fflush(output);
    
    pthread_mutex_unlock(&g_logger->mutex);
    va_end(args);
}

void log_debug(const char *format, ...) {
    if (!g_logger || LOG_DEBUG < g_logger->level) return;
    
    va_list args;
    va_start(args, format);
    
    pthread_mutex_lock(&g_logger->mutex);
    
    char timestamp[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    FILE *output = g_logger->error_log ? g_logger->error_log : stdout;
    fprintf(output, "[%s] [DEBUG] ", timestamp);
    vfprintf(output, format, args);
    fprintf(output, "\n");
    fflush(output);
    
    pthread_mutex_unlock(&g_logger->mutex);
    va_end(args);
}

void log_warn(const char *format, ...) {
    if (!g_logger || LOG_WARN < g_logger->level) return;
    
    va_list args;
    va_start(args, format);
    
    pthread_mutex_lock(&g_logger->mutex);
    
    char timestamp[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    FILE *output = g_logger->error_log ? g_logger->error_log : stderr;
    fprintf(output, "[%s] [WARN] ", timestamp);
    vfprintf(output, format, args);
    fprintf(output, "\n");
    fflush(output);
    
    pthread_mutex_unlock(&g_logger->mutex);
    va_end(args);
}

void log_fatal(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    if (g_logger) {
        pthread_mutex_lock(&g_logger->mutex);
    }
    
    char timestamp[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    FILE *output = (g_logger && g_logger->error_log) ? g_logger->error_log : stderr;
    fprintf(output, "[%s] [FATAL] ", timestamp);
    vfprintf(output, format, args);
    fprintf(output, "\n");
    fflush(output);
    
    if (g_logger) {
        pthread_mutex_unlock(&g_logger->mutex);
    }
    
    va_end(args);
}

// Log HTTP request
void log_request(connection_t *conn) {
    if (!conn) return;
    
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &conn->client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    
    log_debug("Request from %s: %s %s", 
              client_ip, 
              http_method_to_string(conn->request.method),
              conn->request.uri);
}

// Log HTTP response
void log_response(connection_t *conn) {
    if (!conn || !g_logger) return;
    
    access_log_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    
    // Fill access log entry
    inet_ntop(AF_INET, &conn->client_addr.sin_addr, entry.client_ip, INET_ADDRSTRLEN);
    strcpy(entry.timestamp, log_format_timestamp());
    strcpy(entry.method, http_method_to_string(conn->request.method));
    strncpy(entry.uri, conn->request.uri, sizeof(entry.uri) - 1);
    strcpy(entry.version, conn->request.version);
    entry.status_code = conn->response.status;
    entry.response_size = conn->response.body_length;
    
    if (conn->request.user_agent) {
        strncpy(entry.user_agent, conn->request.user_agent, sizeof(entry.user_agent) - 1);
    }
    
    // Calculate response time
    if (conn->response.timestamp.tv_sec > 0) {
        entry.response_time = 
            (conn->response.timestamp.tv_sec - conn->request.timestamp.tv_sec) * 1000.0 +
            (conn->response.timestamp.tv_usec - conn->request.timestamp.tv_usec) / 1000.0;
    }
    
    log_access(&entry);
}

// Set log format
void log_set_format(const char *format) {
    if (!g_logger || !format) return;
    
    pthread_mutex_lock(&g_logger->mutex);
    free(g_logger->log_format);
    g_logger->log_format = strdup(format);
    pthread_mutex_unlock(&g_logger->mutex);
}

// Format access log entry
char *log_format_entry(const access_log_entry_t *entry) {
    if (!entry || !g_logger) return NULL;
    
    static char formatted[1024];
    snprintf(formatted, sizeof(formatted),
            "%s - - [%s] \"%s %s HTTP/1.1\" %d %zu \"%s\" \"%s\" %.3f",
            entry->client_ip,
            entry->timestamp,
            entry->method,
            entry->uri,
            entry->status_code,
            entry->response_size,
            entry->referer[0] ? entry->referer : "-",
            entry->user_agent[0] ? entry->user_agent : "-",
            entry->response_time);
    
    return formatted;
}

// Enable syslog
int log_enable_syslog(const char *ident) {
    if (!g_logger) return -1;
    
    openlog(ident, LOG_PID | LOG_CONS, LOG_DAEMON);
    g_logger->syslog_enabled = 1;
    
    log_info("Syslog enabled with identifier: %s", ident);
    return 0;
}

// Disable syslog
void log_disable_syslog(void) {
    if (!g_logger) return;
    
    if (g_logger->syslog_enabled) {
        closelog();
        g_logger->syslog_enabled = 0;
        log_info("Syslog disabled");
    }
}

// Rotate log files
void log_rotate(void) {
    if (!g_logger) return;
    
    pthread_mutex_lock(&g_logger->mutex);
    
    // Close current log files
    if (g_logger->access_log) {
        fclose(g_logger->access_log);
        g_logger->access_log = NULL;
    }
    
    if (g_logger->error_log) {
        fclose(g_logger->error_log);
        g_logger->error_log = NULL;
    }
    
    // Reopen log files (they should be rotated externally)
    // This is a simplified implementation
    
    pthread_mutex_unlock(&g_logger->mutex);
    
    log_info("Log files rotated");
}