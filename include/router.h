#ifndef ROUTER_H
#define ROUTER_H

#include "server.h"

// Route types
typedef enum {
    ROUTE_STATIC,
    ROUTE_PROXY,
    ROUTE_REDIRECT,
    ROUTE_CGI
} route_type_t;

// Route structure
typedef struct route {
    char *pattern;
    route_type_t type;
    char *target;
    char *methods;
    int exact_match;
    struct route *next;
} route_t;

// Backend server for load balancing
typedef struct backend_server {
    char *host;
    int port;
    int weight;
    int active;
    int connections;
    struct timeval last_check;
    struct backend_server *next;
} backend_server_t;

// Upstream configuration for load balancing
typedef struct upstream {
    char *name;
    backend_server_t *servers;
    char *method; // round_robin, least_conn, ip_hash
    int max_fails;
    int fail_timeout;
    struct upstream *next;
} upstream_t;

// Router context
typedef struct router {
    route_t *routes;
    upstream_t *upstreams;
    char *default_server;
} router_t;

// Router functions
router_t *router_create(void);
void router_destroy(router_t *router);

// Route management
int router_add_route(router_t *router, const char *pattern, route_type_t type, 
                    const char *target, const char *methods);
route_t *router_match_route(router_t *router, const char *path, const char *method);
void router_remove_route(router_t *router, const char *pattern);

// URL rewriting
char *router_rewrite_url(const char *url, const char *pattern, const char *replacement);

// Reverse proxy functions
int router_proxy_request(connection_t *conn, const char *upstream_url);
int router_forward_to_backend(connection_t *conn, backend_server_t *backend);

// Load balancing
backend_server_t *router_select_backend(upstream_t *upstream, connection_t *conn);
int router_health_check(backend_server_t *backend);
void router_update_backend_stats(backend_server_t *backend, int success);

// Upstream management
upstream_t *router_create_upstream(const char *name);
int router_add_backend(upstream_t *upstream, const char *host, int port, int weight);
void router_remove_backend(upstream_t *upstream, const char *host, int port);

// Virtual host routing
server_block_t *router_find_server_block(const char *host, int port);
location_t *router_find_location(server_block_t *server, const char *uri);

// URL manipulation
char *router_normalize_path(const char *path);
int router_is_safe_path(const char *path);
char *router_resolve_path(const char *document_root, const char *uri);

// CGI handling
int router_handle_cgi(connection_t *conn, const char *script_path);

// Global router
extern router_t *g_router;

#endif // ROUTER_H