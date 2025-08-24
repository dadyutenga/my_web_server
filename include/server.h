#ifndef SERVER_H
#define SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <zlib.h>

// Forward declarations
typedef struct server_config server_config_t;
typedef struct connection connection_t;
typedef struct http_request http_request_t;
typedef struct http_response http_response_t;

// Constants
#define MAX_EVENTS 1024
#define BUFFER_SIZE 8192
#define MAX_CONNECTIONS 10000
#define MAX_HEADER_SIZE 8192
#define MAX_URI_SIZE 2048
#define MAX_METHOD_SIZE 16
#define MAX_VERSION_SIZE 16

// HTTP methods
typedef enum {
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_HEAD,
    HTTP_OPTIONS,
    HTTP_PATCH
} http_method_t;

// HTTP status codes
typedef enum {
    HTTP_200_OK = 200,
    HTTP_301_MOVED = 301,
    HTTP_302_FOUND = 302,
    HTTP_400_BAD_REQUEST = 400,
    HTTP_401_UNAUTHORIZED = 401,
    HTTP_403_FORBIDDEN = 403,
    HTTP_404_NOT_FOUND = 404,
    HTTP_405_METHOD_NOT_ALLOWED = 405,
    HTTP_500_INTERNAL_ERROR = 500,
    HTTP_501_NOT_IMPLEMENTED = 501,
    HTTP_502_BAD_GATEWAY = 502,
    HTTP_503_SERVICE_UNAVAILABLE = 503
} http_status_t;

// Connection states
typedef enum {
    CONN_READING,
    CONN_PROCESSING,
    CONN_WRITING,
    CONN_CLOSING
} conn_state_t;

// Server configuration
struct server_config {
    int http_port;
    int https_port;
    char *document_root;
    char *ssl_cert_path;
    char *ssl_key_path;
    char *log_file;
    char *access_log;
    char *error_log;
    int worker_processes;
    int max_connections;
    int keepalive_timeout;
    int client_timeout;
    int enable_compression;
    int enable_ssl_redirect;
    struct server_block *server_blocks;
    int num_server_blocks;
};

// Server block for virtual hosts
typedef struct server_block {
    char *server_name;
    char *listen_addr;
    int listen_port;
    char *document_root;
    int ssl_enabled;
    char *ssl_cert_path;
    char *ssl_key_path;
    struct location *locations;
    int num_locations;
} server_block_t;

// Location block for routing
typedef struct location {
    char *path;
    char *proxy_pass;
    char *root;
    char *index;
    int enable_gzip;
} location_t;

// Core server functions
int server_init(server_config_t *config);
int server_run(server_config_t *config);
void server_shutdown(void);

// Worker process functions
void *worker_thread(void *arg);
int setup_epoll(void);
int make_socket_non_blocking(int sockfd);

// Global server state
extern server_config_t *g_config;
extern int g_epoll_fd;
extern int g_server_socket;
extern int g_https_server_socket;
extern volatile sig_atomic_t g_shutdown;

#endif // SERVER_H