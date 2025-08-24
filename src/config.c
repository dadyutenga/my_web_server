#include "../include/config.h"
#include "../include/logging.h"
#include <ctype.h>
#include <sys/inotify.h>
#include <libgen.h>

// Global configuration watch variables
static int g_inotify_fd = -1;
static int g_watch_fd = -1;
static char *g_config_filename = NULL;

// Helper function to trim whitespace
static char *trim_whitespace(char *str) {
    char *end;
    
    // Trim leading space
    while(isspace((unsigned char)*str)) str++;
    
    if(*str == 0) return str;
    
    // Trim trailing space
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;
    
    end[1] = '\0';
    return str;
}

// Parse boolean value
int config_parse_boolean(const char *value) {
    if (!value) return 0;
    
    if (strcasecmp(value, "true") == 0 || 
        strcasecmp(value, "yes") == 0 || 
        strcasecmp(value, "on") == 0 || 
        strcmp(value, "1") == 0) {
        return 1;
    }
    return 0;
}

// Parse integer with bounds checking
int config_parse_integer(const char *value, int min_val, int max_val) {
    if (!value) return 0;
    
    char *endptr;
    long val = strtol(value, &endptr, 10);
    
    if (*endptr != '\0' || val < min_val || val > max_val) {
        return 0;
    }
    
    return (int)val;
}

// Parse string value (allocates memory)
char *config_parse_string(const char *value) {
    if (!value) return NULL;
    
    // Remove quotes if present
    if ((value[0] == '"' && value[strlen(value)-1] == '"') ||
        (value[0] == '\'' && value[strlen(value)-1] == '\'')) {
        char *result = malloc(strlen(value) - 1);
        strncpy(result, value + 1, strlen(value) - 2);
        result[strlen(value) - 2] = '\0';
        return result;
    }
    
    return strdup(value);
}

// Parse size value (supports K, M, G suffixes)
int config_parse_size(const char *value) {
    if (!value) return 0;
    
    char *endptr;
    long val = strtol(value, &endptr, 10);
    
    if (val < 0) return 0;
    
    switch (tolower(*endptr)) {
        case 'k': val *= 1024; break;
        case 'm': val *= 1024 * 1024; break;
        case 'g': val *= 1024 * 1024 * 1024; break;
        case '\0': break;
        default: return 0;
    }
    
    return (int)val;
}

// Create default configuration
server_config_t *config_create_default(void) {
    server_config_t *config = calloc(1, sizeof(server_config_t));
    if (!config) return NULL;
    
    config->http_port = 80;
    config->https_port = 443;
    config->document_root = strdup("/var/www/html");
    config->ssl_cert_path = strdup("/etc/ssl/certs/server.crt");
    config->ssl_key_path = strdup("/etc/ssl/private/server.key");
    config->log_file = strdup("/var/log/server.log");
    config->access_log = strdup("/var/log/access.log");
    config->error_log = strdup("/var/log/error.log");
    config->worker_processes = 4;
    config->max_connections = 1024;
    config->keepalive_timeout = 60;
    config->client_timeout = 30;
    config->enable_compression = 1;
    config->enable_ssl_redirect = 0;
    config->num_server_blocks = 0;
    
    return config;
}

// Parse a single directive line
static int parse_directive(char *line, char **name, char **value) {
    *name = NULL;
    *value = NULL;
    
    // Skip empty lines and comments
    line = trim_whitespace(line);
    if (strlen(line) == 0 || line[0] == '#') {
        return 0;
    }
    
    // Find the first space or tab
    char *space = strpbrk(line, " \t");
    if (!space) {
        *name = strdup(line);
        *value = strdup("");
        return 1;
    }
    
    // Split name and value
    *space = '\0';
    *name = strdup(line);
    *value = strdup(trim_whitespace(space + 1));
    
    // Remove trailing semicolon
    int len = strlen(*value);
    if (len > 0 && (*value)[len-1] == ';') {
        (*value)[len-1] = '\0';
    }
    
    return 1;
}

// Parse server block
static server_block_t *parse_server_block(FILE *file, int *line_num) {
    server_block_t *server = calloc(1, sizeof(server_block_t));
    if (!server) return NULL;
    
    // Set defaults
    server->listen_port = 80;
    server->ssl_enabled = 0;
    server->document_root = strdup("/var/www/html");
    
    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        (*line_num)++;
        
        char *name, *value;
        if (!parse_directive(line, &name, &value)) {
            free(name);
            free(value);
            continue;
        }
        
        if (strcmp(name, "}") == 0) {
            free(name);
            free(value);
            break;
        }
        
        if (strcmp(name, "listen") == 0) {
            if (strstr(value, "ssl")) {
                server->ssl_enabled = 1;
                server->listen_port = config_parse_integer(value, 1, 65535);
                if (server->listen_port == 0) server->listen_port = 443;
            } else {
                server->listen_port = config_parse_integer(value, 1, 65535);
                if (server->listen_port == 0) server->listen_port = 80;
            }
        } else if (strcmp(name, "server_name") == 0) {
            free(server->server_name);
            server->server_name = config_parse_string(value);
        } else if (strcmp(name, "root") == 0) {
            free(server->document_root);
            server->document_root = config_parse_string(value);
        } else if (strcmp(name, "ssl_certificate") == 0) {
            free(server->ssl_cert_path);
            server->ssl_cert_path = config_parse_string(value);
        } else if (strcmp(name, "ssl_certificate_key") == 0) {
            free(server->ssl_key_path);
            server->ssl_key_path = config_parse_string(value);
        }
        
        free(name);
        free(value);
    }
    
    return server;
}

// Main configuration parser
server_config_t *config_parse_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        LOG_ERROR_MSG("Failed to open configuration file: %s", filename);
        return NULL;
    }
    
    server_config_t *config = config_create_default();
    if (!config) {
        fclose(file);
        return NULL;
    }
    
    char line[1024];
    int line_num = 0;
    
    while (fgets(line, sizeof(line), file)) {
        line_num++;
        
        char *name, *value;
        if (!parse_directive(line, &name, &value)) {
            free(name);
            free(value);
            continue;
        }
        
        // Main configuration directives
        if (strcmp(name, "worker_processes") == 0) {
            config->worker_processes = config_parse_integer(value, 1, 128);
        } else if (strcmp(name, "max_connections") == 0) {
            config->max_connections = config_parse_integer(value, 1, 100000);
        } else if (strcmp(name, "keepalive_timeout") == 0) {
            config->keepalive_timeout = config_parse_integer(value, 1, 3600);
        } else if (strcmp(name, "client_timeout") == 0) {
            config->client_timeout = config_parse_integer(value, 1, 300);
        } else if (strcmp(name, "gzip") == 0) {
            config->enable_compression = config_parse_boolean(value);
        } else if (strcmp(name, "ssl_redirect") == 0) {
            config->enable_ssl_redirect = config_parse_boolean(value);
        } else if (strcmp(name, "access_log") == 0) {
            free(config->access_log);
            config->access_log = config_parse_string(value);
        } else if (strcmp(name, "error_log") == 0) {
            free(config->error_log);
            config->error_log = config_parse_string(value);
        } else if (strcmp(name, "server") == 0 && strcmp(value, "{") == 0) {
            // Parse server block
            server_block_t *server = parse_server_block(file, &line_num);
            if (server) {
                config->server_blocks = realloc(config->server_blocks, 
                    sizeof(server_block_t) * (config->num_server_blocks + 1));
                config->server_blocks[config->num_server_blocks] = *server;
                config->num_server_blocks++;
                free(server);
            }
        }
        
        free(name);
        free(value);
    }
    
    fclose(file);
    return config;
}

// Validate configuration
int config_validate(server_config_t *config) {
    if (!config) return 0;
    
    // Check required fields
    if (!config->document_root) {
        LOG_ERROR_MSG("document_root is required");
        return 0;
    }
    
    if (config->http_port < 1 || config->http_port > 65535) {
        LOG_ERROR_MSG("Invalid HTTP port: %d", config->http_port);
        return 0;
    }
    
    if (config->https_port < 1 || config->https_port > 65535) {
        LOG_ERROR_MSG("Invalid HTTPS port: %d", config->https_port);
        return 0;
    }
    
    if (config->worker_processes < 1) {
        LOG_ERROR_MSG("worker_processes must be at least 1");
        return 0;
    }
    
    // Check if document root exists
    struct stat st;
    if (stat(config->document_root, &st) != 0 || !S_ISDIR(st.st_mode)) {
        LOG_ERROR_MSG("Document root does not exist or is not a directory: %s", 
                      config->document_root);
        return 0;
    }
    
    return 1;
}

// Free configuration memory
void config_free(server_config_t *config) {
    if (!config) return;
    
    free(config->document_root);
    free(config->ssl_cert_path);
    free(config->ssl_key_path);
    free(config->log_file);
    free(config->access_log);
    free(config->error_log);
    
    for (int i = 0; i < config->num_server_blocks; i++) {
        server_block_t *server = &config->server_blocks[i];
        free(server->server_name);
        free(server->listen_addr);
        free(server->document_root);
        free(server->ssl_cert_path);
        free(server->ssl_key_path);
        
        for (int j = 0; j < server->num_locations; j++) {
            location_t *location = &server->locations[j];
            free(location->path);
            free(location->proxy_pass);
            free(location->root);
            free(location->index);
        }
        free(server->locations);
    }
    free(config->server_blocks);
    free(config);
}

// Watch configuration file for changes
int config_watch_file(const char *filename) {
    g_inotify_fd = inotify_init1(IN_NONBLOCK);
    if (g_inotify_fd == -1) {
        LOG_ERROR_MSG("Failed to initialize inotify");
        return -1;
    }
    
    g_watch_fd = inotify_add_watch(g_inotify_fd, filename, IN_MODIFY);
    if (g_watch_fd == -1) {
        LOG_ERROR_MSG("Failed to watch configuration file: %s", filename);
        close(g_inotify_fd);
        return -1;
    }
    
    g_config_filename = strdup(filename);
    LOG_INFO_MSG("Watching configuration file: %s", filename);
    return 0;
}

// Stop watching configuration file
void config_stop_watching(void) {
    if (g_inotify_fd != -1) {
        close(g_inotify_fd);
        g_inotify_fd = -1;
    }
    
    if (g_config_filename) {
        free(g_config_filename);
        g_config_filename = NULL;
    }
    
    g_watch_fd = -1;
}

// Reload configuration
int config_reload(const char *filename) {
    LOG_INFO_MSG("Reloading configuration from: %s", filename);
    
    server_config_t *new_config = config_parse_file(filename);
    if (!new_config) {
        LOG_ERROR_MSG("Failed to reload configuration");
        return -1;
    }
    
    if (!config_validate(new_config)) {
        LOG_ERROR_MSG("Configuration validation failed");
        config_free(new_config);
        return -1;
    }
    
    // Here we would update the global configuration
    // This requires careful synchronization in a real implementation
    
    LOG_INFO_MSG("Configuration reloaded successfully");
    return 0;
}