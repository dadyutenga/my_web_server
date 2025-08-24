#ifndef LOGGING_H
#define LOGGING_H

#include "server.h"
#include <stdarg.h>

// Log levels
typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_FATAL
} log_level_t;

// Log types
typedef enum {
    LOG_ACCESS,
    LOG_ERROR_LOG,
    LOG_GENERAL
} log_type_t;

// Logger structure
typedef struct logger {
    FILE *access_log;
    FILE *error_log;
    FILE *general_log;
    log_level_t level;
    pthread_mutex_t mutex;
    int syslog_enabled;
    char *log_format;
} logger_t;

// Access log entry
typedef struct access_log_entry {
    char client_ip[INET_ADDRSTRLEN];
    char timestamp[64];
    char method[16];
    char uri[MAX_URI_SIZE];
    char version[16];
    int status_code;
    size_t response_size;
    char referer[MAX_URI_SIZE];
    char user_agent[256];
    double response_time;
} access_log_entry_t;

// Logging functions
int log_init(const char *access_log_file, const char *error_log_file, log_level_t level);
void log_cleanup(void);
void log_rotate(void);

// Main logging functions
void log_access(const access_log_entry_t *entry);
void log_error(log_level_t level, const char *format, ...);
void log_info(const char *format, ...);
void log_debug(const char *format, ...);
void log_warn(const char *format, ...);
void log_fatal(const char *format, ...);

// Logging utility functions
void log_request(connection_t *conn);
void log_response(connection_t *conn);
const char *log_level_to_string(log_level_t level);
char *log_format_timestamp(void);

// Log format functions
void log_set_format(const char *format);
char *log_format_entry(const access_log_entry_t *entry);

// Syslog integration
int log_enable_syslog(const char *ident);
void log_disable_syslog(void);

// Global logger
extern logger_t *g_logger;

// Log macros for convenience
#define LOG_DEBUG_MSG(fmt, ...) log_debug(fmt, ##__VA_ARGS__)
#define LOG_INFO_MSG(fmt, ...) log_info(fmt, ##__VA_ARGS__)
#define LOG_WARN_MSG(fmt, ...) log_warn(fmt, ##__VA_ARGS__)
#define LOG_ERROR_MSG(fmt, ...) log_error(LOG_ERROR, fmt, ##__VA_ARGS__)
#define LOG_FATAL_MSG(fmt, ...) log_fatal(fmt, ##__VA_ARGS__)

#endif // LOGGING_H