#include "../include/server.h"
#include "../include/config.h"
#include "../include/logging.h"
#include "../include/http.h"
#include "../include/ssl.h"
#include "../include/router.h"
#include "../include/security.h"
#include "../include/cache.h"

// Global server state
server_config_t *g_config = NULL;
int g_epoll_fd = -1;
int g_server_socket = -1;
int g_https_server_socket = -1;
volatile sig_atomic_t g_shutdown = 0;
volatile sig_atomic_t g_reload_config = 0;
volatile sig_atomic_t g_graceful_shutdown = 0;
static char *g_config_file = NULL;

// Connection pool
static connection_t *g_connections = NULL;
static int g_connection_count = 0;
static pthread_mutex_t g_connection_mutex = PTHREAD_MUTEX_INITIALIZER;

// Active connections list for graceful shutdown
static connection_t **g_active_connections = NULL;
static int g_active_connection_capacity = 0;

// Worker thread pool
static pthread_t *g_worker_threads = NULL;
static int g_num_workers = 0;

// Signal handlers
static void signal_handler(int sig) {
    switch (sig) {
        case SIGINT:
        case SIGTERM:
            LOG_INFO_MSG("Received shutdown signal %d", sig);
            g_graceful_shutdown = 1;
            break;
        case SIGQUIT:
            LOG_INFO_MSG("Received SIGQUIT - immediate shutdown");
            g_shutdown = 1;
            break;
        case SIGHUP:
            LOG_INFO_MSG("Received SIGHUP - scheduling config reload");
            g_reload_config = 1;
            break;
        case SIGPIPE:
            // Ignore broken pipe signals
            break;
    }
}

// Hot reload configuration
static int reload_configuration(void) {
    if (!g_config_file) {
        LOG_ERROR_MSG("No config file path stored for reload");
        return -1;
    }
    
    LOG_INFO_MSG("Reloading configuration from %s", g_config_file);
    
    // Parse new configuration
    server_config_t *new_config = config_parse_file(g_config_file);
    if (!new_config) {
        LOG_ERROR_MSG("Failed to parse new configuration - keeping old config");
        return -1;
    }
    
    // Validate new configuration
    if (!config_validate(new_config)) {
        LOG_ERROR_MSG("New configuration validation failed - keeping old config");
        config_free(new_config);
        return -1;
    }
    
    // Swap configurations atomically
    server_config_t *old_config = g_config;
    g_config = new_config;
    
    // Free old configuration
    config_free(old_config);
    
    LOG_INFO_MSG("Configuration reloaded successfully");
    return 0;
}

// Setup signal handlers
static int setup_signals(void) {
    struct sigaction sa;
    
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    
    if (sigaction(SIGINT, &sa, NULL) == -1 ||
        sigaction(SIGTERM, &sa, NULL) == -1 ||
        sigaction(SIGHUP, &sa, NULL) == -1 ||
        sigaction(SIGQUIT, &sa, NULL) == -1) {
        LOG_ERROR_MSG("Failed to setup signal handlers");
        return -1;
    }
    
    // Ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    
    return 0;
}

// Track active connection for graceful shutdown
static void track_connection(connection_t *conn) {
    pthread_mutex_lock(&g_connection_mutex);
    
    if (g_connection_count >= g_active_connection_capacity) {
        int new_capacity = g_active_connection_capacity == 0 ? 64 : g_active_connection_capacity * 2;
        connection_t **new_array = realloc(g_active_connections, new_capacity * sizeof(connection_t*));
        if (new_array) {
            g_active_connections = new_array;
            g_active_connection_capacity = new_capacity;
        }
    }
    
    if (g_connection_count < g_active_connection_capacity) {
        g_active_connections[g_connection_count] = conn;
    }
    g_connection_count++;
    
    pthread_mutex_unlock(&g_connection_mutex);
}

// Untrack connection
static void untrack_connection(connection_t *conn) {
    pthread_mutex_lock(&g_connection_mutex);
    
    for (int i = 0; i < g_connection_count; i++) {
        if (g_active_connections[i] == conn) {
            g_active_connections[i] = g_active_connections[g_connection_count - 1];
            g_connection_count--;
            break;
        }
    }
    
    pthread_mutex_unlock(&g_connection_mutex);
}

// Graceful shutdown - wait for connections to drain
static void graceful_shutdown_wait(int timeout_seconds) {
    LOG_INFO_MSG("Graceful shutdown: waiting for %d active connections", g_connection_count);
    
    time_t start_time = time(NULL);
    
    while (g_connection_count > 0 && (time(NULL) - start_time) < timeout_seconds) {
        usleep(100000); // 100ms
    }
    
    if (g_connection_count > 0) {
        LOG_WARN_MSG("Graceful shutdown timeout: %d connections still active", g_connection_count);
    } else {
        LOG_INFO_MSG("Graceful shutdown complete: all connections closed");
    }
    
    g_shutdown = 1;
}

// Make socket non-blocking
int make_socket_non_blocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) {
        LOG_ERROR_MSG("fcntl F_GETFL failed: %s", strerror(errno));
        return -1;
    }
    
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        LOG_ERROR_MSG("fcntl F_SETFL failed: %s", strerror(errno));
        return -1;
    }
    
    return 0;
}

// Create and bind socket
static int create_server_socket(int port, int is_https) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        LOG_ERROR_MSG("Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        LOG_ERROR_MSG("setsockopt SO_REUSEADDR failed: %s", strerror(errno));
        close(sockfd);
        return -1;
    }
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) == -1) {
        LOG_WARN_MSG("setsockopt SO_REUSEPORT failed: %s", strerror(errno));
    }
    
    // Bind socket
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        LOG_ERROR_MSG("Failed to bind to port %d: %s", port, strerror(errno));
        close(sockfd);
        return -1;
    }
    
    if (listen(sockfd, SOMAXCONN) == -1) {
        LOG_ERROR_MSG("Failed to listen on port %d: %s", port, strerror(errno));
        close(sockfd);
        return -1;
    }
    
    if (make_socket_non_blocking(sockfd) == -1) {
        close(sockfd);
        return -1;
    }
    
    LOG_INFO_MSG("%s server listening on port %d", 
                 is_https ? "HTTPS" : "HTTP", port);
    
    return sockfd;
}

// Setup epoll
int setup_epoll(void) {
    g_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epoll_fd == -1) {
        LOG_ERROR_MSG("Failed to create epoll: %s", strerror(errno));
        return -1;
    }
    
    // Add HTTP server socket to epoll
    if (g_server_socket != -1) {
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = g_server_socket;
        
        if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, g_server_socket, &ev) == -1) {
            LOG_ERROR_MSG("Failed to add HTTP server socket to epoll: %s", 
                          strerror(errno));
            return -1;
        }
    }
    
    // Add HTTPS server socket to epoll
    if (g_https_server_socket != -1) {
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = g_https_server_socket;
        
        if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, g_https_server_socket, &ev) == -1) {
            LOG_ERROR_MSG("Failed to add HTTPS server socket to epoll: %s", 
                          strerror(errno));
            return -1;
        }
    }
    
    return 0;
}

// Accept new connections
static int accept_connections(int server_sockfd, int is_https) {
    int accepted = 0;
    
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_sockfd = accept(server_sockfd, 
                                  (struct sockaddr*)&client_addr, 
                                  &client_len);
        
        if (client_sockfd == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No more connections to accept
                break;
            } else {
                LOG_ERROR_MSG("accept failed: %s", strerror(errno));
                break;
            }
        }
        
        // Check connection limit
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        
        if (!security_check_connection_limit(client_ip)) {
            LOG_WARN_MSG("Connection limit exceeded for IP: %s", client_ip);
            close(client_sockfd);
            continue;
        }
        
        // Check rate limiting
        if (!rate_limiter_check(g_rate_limiter, client_ip)) {
            LOG_WARN_MSG("Rate limit exceeded for IP: %s", client_ip);
            close(client_sockfd);
            continue;
        }
        
        // Make client socket non-blocking
        if (make_socket_non_blocking(client_sockfd) == -1) {
            close(client_sockfd);
            continue;
        }
        
        // Create connection object
        connection_t *conn = calloc(1, sizeof(connection_t));
        if (!conn) {
            LOG_ERROR_MSG("Failed to allocate connection object");
            close(client_sockfd);
            continue;
        }
        
        conn->sockfd = client_sockfd;
        conn->client_addr = client_addr;
        conn->state = CONN_READING;
        gettimeofday(&conn->last_activity, NULL);
        
        if (is_https) {
            // Setup SSL connection
            conn->ssl = ssl_create_connection(g_ssl_ctx, client_sockfd);
            if (!conn->ssl) {
                LOG_ERROR_MSG("Failed to create SSL connection");
                close(client_sockfd);
                free(conn);
                continue;
            }
        }
        
        // Add to epoll
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET;
        ev.data.ptr = conn;
        
        if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, client_sockfd, &ev) == -1) {
            LOG_ERROR_MSG("Failed to add client socket to epoll: %s", 
                          strerror(errno));
            if (conn->ssl) ssl_close_connection(conn->ssl);
            close(client_sockfd);
            free(conn);
            continue;
        }
        
        pthread_mutex_lock(&g_connection_mutex);
        g_connection_count++;
        pthread_mutex_unlock(&g_connection_mutex);
        
        security_update_connection_count(client_ip, 1);
        
        LOG_DEBUG_MSG("Accepted connection from %s:%d", 
                      client_ip, ntohs(client_addr.sin_port));
        
        accepted++;
    }
    
    return accepted;
}

// Close connection
static void close_connection(connection_t *conn) {
    if (!conn) return;
    
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &conn->client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    
    // Remove from epoll
    epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, conn->sockfd, NULL);
    
    // Close SSL connection
    if (conn->ssl) {
        ssl_close_connection(conn->ssl);
    }
    
    // Close socket
    close(conn->sockfd);
    
    // Update connection count
    pthread_mutex_lock(&g_connection_mutex);
    g_connection_count--;
    pthread_mutex_unlock(&g_connection_mutex);
    
    security_update_connection_count(client_ip, -1);
    
    // Free connection memory
    free(conn->request.body);
    free(conn->response.content_type);
    free(conn->response.body);
    free(conn->response.headers);
    free(conn);
    
    LOG_DEBUG_MSG("Closed connection from %s", client_ip);
}

// Main event loop
static void event_loop(void) {
    struct epoll_event events[MAX_EVENTS];
    
    while (!g_shutdown) {
        // Check for graceful shutdown
        if (g_graceful_shutdown && !g_shutdown) {
            // Stop accepting new connections
            if (g_server_socket != -1) {
                epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, g_server_socket, NULL);
            }
            if (g_https_server_socket != -1) {
                epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, g_https_server_socket, NULL);
            }
            graceful_shutdown_wait(30); // 30 second timeout
            break;
        }
        
        // Check for config reload
        if (g_reload_config) {
            g_reload_config = 0;
            reload_configuration();
        }
        
        int nfds = epoll_wait(g_epoll_fd, events, MAX_EVENTS, 1000);
        
        if (nfds == -1) {
            if (errno == EINTR) continue;
            LOG_ERROR_MSG("epoll_wait failed: %s", strerror(errno));
            break;
        }
        
        for (int i = 0; i < nfds; i++) {
            struct epoll_event *ev = &events[i];
            
            if (ev->data.fd == g_server_socket) {
                // New HTTP connection
                accept_connections(g_server_socket, 0);
            } else if (ev->data.fd == g_https_server_socket) {
                // New HTTPS connection
                accept_connections(g_https_server_socket, 1);
            } else {
                // Client connection event
                connection_t *conn = (connection_t*)ev->data.ptr;
                
                if (ev->events & (EPOLLERR | EPOLLHUP)) {
                    close_connection(conn);
                    continue;
                }
                
                if (ev->events & EPOLLIN) {
                    // Read data from client
                    if (http_parse_request(conn) < 0) {
                        close_connection(conn);
                        continue;
                    }
                    
                    // Process complete requests
                    if (conn->state == CONN_PROCESSING) {
                        // Check for HTTP to HTTPS redirect
                        if (g_config->enable_ssl_redirect && !conn->ssl && g_ssl_ctx) {
                            char redirect_url[MAX_URI_SIZE + 64];
                            snprintf(redirect_url, sizeof(redirect_url),
                                    "https://%s:%d%s",
                                    conn->request.host ? conn->request.host : "localhost",
                                    g_config->https_port,
                                    conn->request.uri);
                            http_build_redirect_response(conn, redirect_url);
                            conn->response.status = HTTP_301_MOVED;
                            conn->state = CONN_WRITING;
                            ev->events = EPOLLOUT | EPOLLET;
                            ev->data.ptr = conn;
                            epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, conn->sockfd, ev);
                            continue;
                        }
                        
                        if (http_handle_request(conn) < 0) {
                            close_connection(conn);
                            continue;
                        }
                        
                        // Switch to writing mode
                        ev->events = EPOLLOUT | EPOLLET;
                        ev->data.ptr = conn;
                        epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, conn->sockfd, ev);
                    }
                }
                
                if (ev->events & EPOLLOUT) {
                    // Send response to client
                    if (http_send_response(conn) < 0) {
                        close_connection(conn);
                        continue;
                    }
                    
                    // Check if we should keep the connection alive
                    if (!conn->keep_alive) {
                        close_connection(conn);
                    } else {
                        // Reset for next request
                        conn->state = CONN_READING;
                        memset(&conn->request, 0, sizeof(conn->request));
                        memset(&conn->response, 0, sizeof(conn->response));
                        conn->read_pos = 0;
                        conn->write_pos = 0;
                        
                        ev->events = EPOLLIN | EPOLLET;
                        ev->data.ptr = conn;
                        epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, conn->sockfd, ev);
                    }
                }
            }
        }
        
        // Cleanup expired cache entries
        if (g_file_cache) {
            cache_cleanup_expired(g_file_cache);
        }
        
        // Cleanup rate limiter
        if (g_rate_limiter) {
            rate_limiter_cleanup_expired(g_rate_limiter);
        }
    }
}

// Initialize server
int server_init(server_config_t *config) {
    g_config = config;
    
    // Setup signal handlers
    if (setup_signals() == -1) {
        return -1;
    }
    
    // Initialize logging
    if (log_init(config->access_log, config->error_log, LOG_INFO) == -1) {
        return -1;
    }
    
    // Initialize SSL if needed
    if (ssl_init() == -1) {
        LOG_ERROR_MSG("Failed to initialize SSL");
        return -1;
    }
    
    // Create SSL context for HTTPS
    g_ssl_ctx = ssl_create_context(config->ssl_cert_path, config->ssl_key_path);
    if (!g_ssl_ctx && config->https_port > 0) {
        LOG_WARN_MSG("Failed to create SSL context, HTTPS will be disabled");
    }
    
    // Initialize security
    security_config_t sec_config = {
        .enable_rate_limiting = 1,
        .requests_per_minute = 60,
        .ban_duration = 300,
        .max_request_size = 1024 * 1024,
        .max_header_size = 8192
    };
    
    if (security_init(&sec_config) == -1) {
        LOG_ERROR_MSG("Failed to initialize security");
        return -1;
    }
    
    // Initialize file cache
    cache_config_t cache_config = {
        .max_size = 100 * 1024 * 1024, // 100MB
        .max_entries = 10000,
        .default_ttl = 3600,
        .enable_etag = 1,
        .enable_last_modified = 1
    };
    
    g_file_cache = cache_create(&cache_config);
    if (!g_file_cache) {
        LOG_ERROR_MSG("Failed to initialize file cache");
        return -1;
    }
    
    // Create server sockets
    if (config->http_port > 0) {
        g_server_socket = create_server_socket(config->http_port, 0);
        if (g_server_socket == -1) {
            return -1;
        }
    }
    
    if (config->https_port > 0 && g_ssl_ctx) {
        g_https_server_socket = create_server_socket(config->https_port, 1);
        if (g_https_server_socket == -1) {
            LOG_WARN_MSG("Failed to create HTTPS server socket");
        }
    }
    
    // Setup epoll
    if (setup_epoll() == -1) {
        return -1;
    }
    
    LOG_INFO_MSG("Server initialized successfully");
    return 0;
}

// Run server
int server_run(server_config_t *config) {
    LOG_INFO_MSG("Starting server with %d worker processes", 
                 config->worker_processes);
    
    // Start event loop
    event_loop();
    
    LOG_INFO_MSG("Server shutting down");
    return 0;
}

// Shutdown server
void server_shutdown(void) {
    LOG_INFO_MSG("Shutting down server...");
    
    g_shutdown = 1;
    
    // Close server sockets
    if (g_server_socket != -1) {
        close(g_server_socket);
        g_server_socket = -1;
    }
    
    if (g_https_server_socket != -1) {
        close(g_https_server_socket);
        g_https_server_socket = -1;
    }
    
    // Close epoll
    if (g_epoll_fd != -1) {
        close(g_epoll_fd);
        g_epoll_fd = -1;
    }
    
    // Cleanup SSL
    if (g_ssl_ctx) {
        ssl_destroy_context(g_ssl_ctx);
        g_ssl_ctx = NULL;
    }
    ssl_cleanup();
    
    // Cleanup cache
    if (g_file_cache) {
        cache_destroy(g_file_cache);
        g_file_cache = NULL;
    }
    
    // Cleanup security
    security_cleanup();
    
    // Free active connections array
    free(g_active_connections);
    g_active_connections = NULL;
    g_active_connection_capacity = 0;
    
    // Free config file path
    free(g_config_file);
    g_config_file = NULL;
    
    // Cleanup logging
    log_cleanup();
    
    LOG_INFO_MSG("Server shutdown complete");
}

// Main function
int main(int argc, char *argv[]) {
    const char *config_file = "config/server.conf";
    
    if (argc > 1) {
        config_file = argv[1];
    }
    
    // Store config file path for hot reload
    g_config_file = strdup(config_file);
    
    // Parse configuration
    server_config_t *config = config_parse_file(config_file);
    if (!config) {
        fprintf(stderr, "Failed to parse configuration file: %s\n", config_file);
        return 1;
    }
    
    // Validate configuration
    if (!config_validate(config)) {
        fprintf(stderr, "Configuration validation failed\n");
        config_free(config);
        return 1;
    }
    
    // Initialize server
    if (server_init(config) == -1) {
        fprintf(stderr, "Server initialization failed\n");
        config_free(config);
        return 1;
    }
    
    // Run server
    int result = server_run(config);
    
    // Cleanup
    server_shutdown();
    config_free(config);
    
    return result;
}