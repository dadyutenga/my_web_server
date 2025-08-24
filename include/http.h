#ifndef HTTP_H
#define HTTP_H

#include "server.h"
#include <sys/time.h>

// HTTP request structure
struct http_request {
    http_method_t method;
    char uri[MAX_URI_SIZE];
    char query_string[MAX_URI_SIZE];
    char version[MAX_VERSION_SIZE];
    char headers[MAX_HEADER_SIZE];
    char *body;
    size_t body_length;
    size_t content_length;
    char *host;
    char *user_agent;
    char *accept_encoding;
    char *connection;
    int keep_alive;
    struct timeval timestamp;
};

// HTTP response structure
struct http_response {
    http_status_t status;
    char *content_type;
    char *body;
    size_t body_length;
    char *headers;
    int compressed;
    int chunked;
    struct timeval timestamp;
};

// Connection structure
struct connection {
    int sockfd;
    int ssl_fd;
    struct sockaddr_in client_addr;
    conn_state_t state;
    http_request_t request;
    http_response_t response;
    char read_buffer[BUFFER_SIZE];
    char write_buffer[BUFFER_SIZE * 2];
    size_t read_pos;
    size_t write_pos;
    size_t bytes_to_write;
    struct timeval last_activity;
    int keep_alive;
    void *ssl;
};

// HTTP parsing and handling functions
int http_parse_request(connection_t *conn);
int http_handle_request(connection_t *conn);
int http_send_response(connection_t *conn);

// HTTP utility functions
const char *http_method_to_string(http_method_t method);
const char *http_status_to_string(http_status_t status);
const char *get_mime_type(const char *path);
char *url_decode(const char *src);
char *get_header_value(const char *headers, const char *name);

// Response building functions
void http_build_response(connection_t *conn, http_status_t status, 
                        const char *content_type, const char *body, size_t body_len);
void http_build_error_response(connection_t *conn, http_status_t status);
void http_build_redirect_response(connection_t *conn, const char *location);

// Header manipulation
void http_add_header(char *headers, const char *name, const char *value);
void http_add_security_headers(char *headers);
void http_add_cors_headers(char *headers);

// Content compression
int http_compress_content(const char *input, size_t input_len, 
                         char **output, size_t *output_len);

#endif // HTTP_H