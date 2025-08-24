#include "../include/router.h"
#include "../include/logging.h"
#include "../include/http.h"
#include <netdb.h>
#include <fcntl.h>

// Global router
router_t *g_router = NULL;

// Create router
router_t *router_create(void) {
    router_t *router = calloc(1, sizeof(router_t));
    if (!router) {
        LOG_ERROR_MSG("Failed to allocate router");
        return NULL;
    }
    
    LOG_INFO_MSG("Router created");
    return router;
}

// Destroy router
void router_destroy(router_t *router) {
    if (!router) return;
    
    // Free routes
    route_t *route = router->routes;
    while (route) {
        route_t *next = route->next;
        free(route->pattern);
        free(route->target);
        free(route->methods);
        free(route);
        route = next;
    }
    
    // Free upstreams
    upstream_t *upstream = router->upstreams;
    while (upstream) {
        upstream_t *next_upstream = upstream->next;
        
        backend_server_t *server = upstream->servers;
        while (server) {
            backend_server_t *next_server = server->next;
            free(server->host);
            free(server);
            server = next_server;
        }
        
        free(upstream->name);
        free(upstream->method);
        free(upstream);
        upstream = next_upstream;
    }
    
    free(router->default_server);
    free(router);
    
    LOG_INFO_MSG("Router destroyed");
}

// Add route to router
int router_add_route(router_t *router, const char *pattern, route_type_t type,
                    const char *target, const char *methods) {
    if (!router || !pattern || !target) return -1;
    
    route_t *route = calloc(1, sizeof(route_t));
    if (!route) {
        LOG_ERROR_MSG("Failed to allocate route");
        return -1;
    }
    
    route->pattern = strdup(pattern);
    route->type = type;
    route->target = strdup(target);
    route->methods = methods ? strdup(methods) : strdup("GET");
    route->exact_match = 0;
    
    // Add to front of list
    route->next = router->routes;
    router->routes = route;
    
    LOG_INFO_MSG("Added route: %s -> %s", pattern, target);
    return 0;
}

// Match route pattern
static int match_pattern(const char *pattern, const char *path) {
    if (!pattern || !path) return 0;
    
    // Simple pattern matching - can be extended for wildcards
    if (strcmp(pattern, path) == 0) return 1;
    
    // Check if pattern is a prefix
    size_t pattern_len = strlen(pattern);
    if (pattern[pattern_len - 1] == '*') {
        return strncmp(pattern, path, pattern_len - 1) == 0;
    }
    
    // Check prefix match for directories
    if (pattern[pattern_len - 1] == '/' || 
        strncmp(pattern, path, pattern_len) == 0) {
        return path[pattern_len] == '/' || path[pattern_len] == '\0';
    }
    
    return 0;
}

// Find matching route
route_t *router_match_route(router_t *router, const char *path, const char *method) {
    if (!router || !path || !method) return NULL;
    
    route_t *route = router->routes;
    while (route) {
        if (match_pattern(route->pattern, path)) {
            // Check if method is allowed
            if (strstr(route->methods, method) || 
                strcmp(route->methods, "*") == 0) {
                return route;
            }
        }
        route = route->next;
    }
    
    return NULL;
}

// Remove route
void router_remove_route(router_t *router, const char *pattern) {
    if (!router || !pattern) return;
    
    route_t **route_ptr = &router->routes;
    while (*route_ptr) {
        route_t *route = *route_ptr;
        if (strcmp(route->pattern, pattern) == 0) {
            *route_ptr = route->next;
            free(route->pattern);
            free(route->target);
            free(route->methods);
            free(route);
            LOG_INFO_MSG("Removed route: %s", pattern);
            return;
        }
        route_ptr = &route->next;
    }
}

// Create upstream
upstream_t *router_create_upstream(const char *name) {
    if (!name) return NULL;
    
    upstream_t *upstream = calloc(1, sizeof(upstream_t));
    if (!upstream) {
        LOG_ERROR_MSG("Failed to allocate upstream");
        return NULL;
    }
    
    upstream->name = strdup(name);
    upstream->method = strdup("round_robin");
    upstream->max_fails = 1;
    upstream->fail_timeout = 10;
    
    LOG_INFO_MSG("Created upstream: %s", name);
    return upstream;
}

// Add backend server to upstream
int router_add_backend(upstream_t *upstream, const char *host, int port, int weight) {
    if (!upstream || !host || port <= 0) return -1;
    
    backend_server_t *server = calloc(1, sizeof(backend_server_t));
    if (!server) {
        LOG_ERROR_MSG("Failed to allocate backend server");
        return -1;
    }
    
    server->host = strdup(host);
    server->port = port;
    server->weight = weight > 0 ? weight : 1;
    server->active = 1;
    server->connections = 0;
    gettimeofday(&server->last_check, NULL);
    
    // Add to front of list
    server->next = upstream->servers;
    upstream->servers = server;
    
    LOG_INFO_MSG("Added backend: %s:%d to upstream %s", host, port, upstream->name);
    return 0;
}

// Remove backend server
void router_remove_backend(upstream_t *upstream, const char *host, int port) {
    if (!upstream || !host) return;
    
    backend_server_t **server_ptr = &upstream->servers;
    while (*server_ptr) {
        backend_server_t *server = *server_ptr;
        if (strcmp(server->host, host) == 0 && server->port == port) {
            *server_ptr = server->next;
            free(server->host);
            free(server);
            LOG_INFO_MSG("Removed backend: %s:%d from upstream %s", 
                         host, port, upstream->name);
            return;
        }
        server_ptr = &server->next;
    }
}

// Select backend server based on load balancing method
backend_server_t *router_select_backend(upstream_t *upstream, connection_t *conn) {
    if (!upstream || !upstream->servers) return NULL;
    
    // Count active servers
    int active_count = 0;
    backend_server_t *server = upstream->servers;
    while (server) {
        if (server->active) active_count++;
        server = server->next;
    }
    
    if (active_count == 0) return NULL;
    
    if (strcmp(upstream->method, "round_robin") == 0) {
        // Simple round-robin selection
        static int round_robin_counter = 0;
        int target = round_robin_counter++ % active_count;
        
        server = upstream->servers;
        int current = 0;
        while (server) {
            if (server->active) {
                if (current == target) return server;
                current++;
            }
            server = server->next;
        }
    } else if (strcmp(upstream->method, "least_conn") == 0) {
        // Least connections method
        backend_server_t *best = NULL;
        int min_connections = INT_MAX;
        
        server = upstream->servers;
        while (server) {
            if (server->active && server->connections < min_connections) {
                min_connections = server->connections;
                best = server;
            }
            server = server->next;
        }
        return best;
    } else if (strcmp(upstream->method, "ip_hash") == 0) {
        // IP hash method
        if (conn) {
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &conn->client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            
            unsigned int hash = 0;
            for (int i = 0; client_ip[i]; i++) {
                hash = hash * 31 + client_ip[i];
            }
            
            int target = hash % active_count;
            server = upstream->servers;
            int current = 0;
            while (server) {
                if (server->active) {
                    if (current == target) return server;
                    current++;
                }
                server = server->next;
            }
        }
    }
    
    // Fallback to first active server
    server = upstream->servers;
    while (server) {
        if (server->active) return server;
        server = server->next;
    }
    
    return NULL;
}

// Health check backend server
int router_health_check(backend_server_t *backend) {
    if (!backend) return 0;
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) return 0;
    
    // Set non-blocking and timeout
    fcntl(sockfd, F_SETFL, O_NONBLOCK);
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(backend->port);
    
    struct hostent *host = gethostbyname(backend->host);
    if (!host) {
        close(sockfd);
        return 0;
    }
    
    memcpy(&addr.sin_addr, host->h_addr, host->h_length);
    
    int result = connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    if (result == 0 || errno == EINPROGRESS) {
        // Connection successful or in progress
        close(sockfd);
        gettimeofday(&backend->last_check, NULL);
        return 1;
    }
    
    close(sockfd);
    return 0;
}

// Update backend statistics
void router_update_backend_stats(backend_server_t *backend, int success) {
    if (!backend) return;
    
    if (success) {
        backend->active = 1;
    } else {
        // Mark as inactive after max_fails
        static int fail_count = 0;
        fail_count++;
        if (fail_count >= 3) { // Simple implementation
            backend->active = 0;
            fail_count = 0;
        }
    }
}

// Find server block by host and port
server_block_t *router_find_server_block(const char *host, int port) {
    if (!g_config || !host) return NULL;
    
    for (int i = 0; i < g_config->num_server_blocks; i++) {
        server_block_t *server = &g_config->server_blocks[i];
        
        if (server->listen_port == port) {
            if (!server->server_name || 
                strcmp(server->server_name, host) == 0 ||
                strcmp(server->server_name, "*") == 0) {
                return server;
            }
        }
    }
    
    return NULL;
}

// Find location in server block
location_t *router_find_location(server_block_t *server, const char *uri) {
    if (!server || !uri) return NULL;
    
    for (int i = 0; i < server->num_locations; i++) {
        location_t *location = &server->locations[i];
        
        if (match_pattern(location->path, uri)) {
            return location;
        }
    }
    
    return NULL;
}

// Normalize path (remove .., etc.)
char *router_normalize_path(const char *path) {
    if (!path) return NULL;
    
    char *normalized = strdup(path);
    if (!normalized) return NULL;
    
    // Remove double slashes
    char *src = normalized, *dst = normalized;
    int last_was_slash = 0;
    
    while (*src) {
        if (*src == '/') {
            if (!last_was_slash) {
                *dst++ = *src;
                last_was_slash = 1;
            }
        } else {
            *dst++ = *src;
            last_was_slash = 0;
        }
        src++;
    }
    *dst = '\0';
    
    return normalized;
}

// Check if path is safe (no path traversal)
int router_is_safe_path(const char *path) {
    if (!path) return 0;
    
    // Check for path traversal
    if (strstr(path, "../") || strstr(path, "..\\")) {
        return 0;
    }
    
    // Check for null bytes
    if (strlen(path) != strcspn(path, "\0")) {
        return 0;
    }
    
    return 1;
}

// Resolve full file path
char *router_resolve_path(const char *document_root, const char *uri) {
    if (!document_root || !uri) return NULL;
    
    char *normalized_uri = router_normalize_path(uri);
    if (!normalized_uri) return NULL;
    
    if (!router_is_safe_path(normalized_uri)) {
        free(normalized_uri);
        return NULL;
    }
    
    size_t root_len = strlen(document_root);
    size_t uri_len = strlen(normalized_uri);
    char *full_path = malloc(root_len + uri_len + 2);
    
    if (full_path) {
        strcpy(full_path, document_root);
        if (root_len > 0 && document_root[root_len - 1] != '/') {
            strcat(full_path, "/");
        }
        if (normalized_uri[0] == '/') {
            strcat(full_path, normalized_uri + 1);
        } else {
            strcat(full_path, normalized_uri);
        }
    }
    
    free(normalized_uri);
    return full_path;
}

// Proxy request to backend
int router_proxy_request(connection_t *conn, const char *upstream_url) {
    if (!conn || !upstream_url) return -1;
    
    // Parse upstream URL
    char protocol[16], host[256], path[1024];
    int port = 80;
    
    if (sscanf(upstream_url, "%15[^:]://%255[^:]:%d%1023s", 
               protocol, host, &port, path) < 2) {
        if (sscanf(upstream_url, "%15[^:]://%255[^/]%1023s", 
                   protocol, host, path) < 2) {
            LOG_ERROR_MSG("Invalid upstream URL: %s", upstream_url);
            return -1;
        }
    }
    
    // Create backend server structure
    backend_server_t backend;
    backend.host = host;
    backend.port = port;
    backend.active = 1;
    backend.connections = 0;
    
    return router_forward_to_backend(conn, &backend);
}

// Forward request to backend server
int router_forward_to_backend(connection_t *conn, backend_server_t *backend) {
    if (!conn || !backend) return -1;
    
    // Create connection to backend
    int backend_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (backend_fd == -1) {
        LOG_ERROR_MSG("Failed to create backend socket");
        return -1;
    }
    
    struct sockaddr_in backend_addr;
    memset(&backend_addr, 0, sizeof(backend_addr));
    backend_addr.sin_family = AF_INET;
    backend_addr.sin_port = htons(backend->port);
    
    struct hostent *host = gethostbyname(backend->host);
    if (!host) {
        LOG_ERROR_MSG("Failed to resolve backend host: %s", backend->host);
        close(backend_fd);
        return -1;
    }
    
    memcpy(&backend_addr.sin_addr, host->h_addr, host->h_length);
    
    if (connect(backend_fd, (struct sockaddr*)&backend_addr, sizeof(backend_addr)) == -1) {
        LOG_ERROR_MSG("Failed to connect to backend %s:%d", backend->host, backend->port);
        close(backend_fd);
        router_update_backend_stats(backend, 0);
        return -1;
    }
    
    // Forward HTTP request
    char request_line[2048];
    snprintf(request_line, sizeof(request_line),
            "%s %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "%s"
            "\r\n",
            http_method_to_string(conn->request.method),
            conn->request.uri,
            backend->host, backend->port,
            conn->request.headers);
    
    if (send(backend_fd, request_line, strlen(request_line), 0) == -1) {
        LOG_ERROR_MSG("Failed to send request to backend");
        close(backend_fd);
        router_update_backend_stats(backend, 0);
        return -1;
    }
    
    // Forward request body if present
    if (conn->request.body && conn->request.body_length > 0) {
        if (send(backend_fd, conn->request.body, conn->request.body_length, 0) == -1) {
            LOG_ERROR_MSG("Failed to send request body to backend");
            close(backend_fd);
            router_update_backend_stats(backend, 0);
            return -1;
        }
    }
    
    // Read response from backend
    char response_buffer[8192];
    ssize_t bytes_received = recv(backend_fd, response_buffer, sizeof(response_buffer) - 1, 0);
    
    if (bytes_received <= 0) {
        LOG_ERROR_MSG("Failed to receive response from backend");
        close(backend_fd);
        router_update_backend_stats(backend, 0);
        return -1;
    }
    
    response_buffer[bytes_received] = '\0';
    
    // Forward response to client
    if (conn->ssl) {
        ssl_write(conn->ssl, response_buffer, bytes_received);
    } else {
        send(conn->sockfd, response_buffer, bytes_received, 0);
    }
    
    // Read and forward remaining data
    while ((bytes_received = recv(backend_fd, response_buffer, sizeof(response_buffer), 0)) > 0) {
        if (conn->ssl) {
            ssl_write(conn->ssl, response_buffer, bytes_received);
        } else {
            send(conn->sockfd, response_buffer, bytes_received, 0);
        }
    }
    
    close(backend_fd);
    router_update_backend_stats(backend, 1);
    backend->connections--;
    
    LOG_DEBUG_MSG("Proxied request to %s:%d", backend->host, backend->port);
    return 0;
}

// URL rewriting
char *router_rewrite_url(const char *url, const char *pattern, const char *replacement) {
    if (!url || !pattern || !replacement) return NULL;
    
    // Simple string replacement implementation
    char *match = strstr(url, pattern);
    if (!match) {
        return strdup(url);
    }
    
    size_t prefix_len = match - url;
    size_t pattern_len = strlen(pattern);
    size_t replacement_len = strlen(replacement);
    size_t suffix_len = strlen(match + pattern_len);
    
    char *result = malloc(prefix_len + replacement_len + suffix_len + 1);
    if (!result) return NULL;
    
    strncpy(result, url, prefix_len);
    strcpy(result + prefix_len, replacement);
    strcpy(result + prefix_len + replacement_len, match + pattern_len);
    
    return result;
}