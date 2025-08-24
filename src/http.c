#include "../include/http.h"
#include "../include/logging.h"
#include "../include/cache.h"
#include "../include/security.h"
#include "../include/router.h"
#include <sys/sendfile.h>

// MIME types mapping
static const struct {
    const char *extension;
    const char *mime_type;
} mime_types[] = {
    {"html", "text/html"},
    {"htm", "text/html"},
    {"css", "text/css"},
    {"js", "application/javascript"},
    {"json", "application/json"},
    {"xml", "application/xml"},
    {"txt", "text/plain"},
    {"jpg", "image/jpeg"},
    {"jpeg", "image/jpeg"},
    {"png", "image/png"},
    {"gif", "image/gif"},
    {"svg", "image/svg+xml"},
    {"ico", "image/x-icon"},
    {"pdf", "application/pdf"},
    {"zip", "application/zip"},
    {"tar", "application/x-tar"},
    {"gz", "application/gzip"},
    {"mp3", "audio/mpeg"},
    {"mp4", "video/mp4"},
    {"avi", "video/x-msvideo"},
    {"mov", "video/quicktime"},
    {NULL, NULL}
};

// HTTP status messages
static const struct {
    http_status_t status;
    const char *message;
} status_messages[] = {
    {HTTP_200_OK, "200 OK"},
    {HTTP_301_MOVED, "301 Moved Permanently"},
    {HTTP_302_FOUND, "302 Found"},
    {HTTP_400_BAD_REQUEST, "400 Bad Request"},
    {HTTP_401_UNAUTHORIZED, "401 Unauthorized"},
    {HTTP_403_FORBIDDEN, "403 Forbidden"},
    {HTTP_404_NOT_FOUND, "404 Not Found"},
    {HTTP_405_METHOD_NOT_ALLOWED, "405 Method Not Allowed"},
    {HTTP_500_INTERNAL_ERROR, "500 Internal Server Error"},
    {HTTP_501_NOT_IMPLEMENTED, "501 Not Implemented"},
    {HTTP_502_BAD_GATEWAY, "502 Bad Gateway"},
    {HTTP_503_SERVICE_UNAVAILABLE, "503 Service Unavailable"},
    {(http_status_t)0, NULL}
};

// HTTP methods
static const struct {
    const char *name;
    http_method_t method;
} http_methods[] = {
    {"GET", HTTP_GET},
    {"POST", HTTP_POST},
    {"PUT", HTTP_PUT},
    {"DELETE", HTTP_DELETE},
    {"HEAD", HTTP_HEAD},
    {"OPTIONS", HTTP_OPTIONS},
    {"PATCH", HTTP_PATCH},
    {NULL, (http_method_t)0}
};

// Get MIME type for file extension
const char *get_mime_type(const char *path) {
    if (!path) return "application/octet-stream";
    
    const char *ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";
    
    ext++; // Skip the dot
    
    for (int i = 0; mime_types[i].extension; i++) {
        if (strcasecmp(ext, mime_types[i].extension) == 0) {
            return mime_types[i].mime_type;
        }
    }
    
    return "application/octet-stream";
}

// Convert HTTP method to string
const char *http_method_to_string(http_method_t method) {
    for (int i = 0; http_methods[i].name; i++) {
        if (http_methods[i].method == method) {
            return http_methods[i].name;
        }
    }
    return "UNKNOWN";
}

// Convert HTTP status to string
const char *http_status_to_string(http_status_t status) {
    for (int i = 0; status_messages[i].message; i++) {
        if (status_messages[i].status == status) {
            return status_messages[i].message;
        }
    }
    return "Unknown Status";
}

// URL decode function
char *url_decode(const char *src) {
    if (!src) return NULL;
    
    size_t len = strlen(src);
    char *dst = malloc(len + 1);
    if (!dst) return NULL;
    
    size_t i = 0, j = 0;
    while (i < len) {
        if (src[i] == '%' && i + 2 < len) {
            char hex[3] = {src[i+1], src[i+2], 0};
            dst[j++] = (char)strtol(hex, NULL, 16);
            i += 3;
        } else if (src[i] == '+') {
            dst[j++] = ' ';
            i++;
        } else {
            dst[j++] = src[i++];
        }
    }
    dst[j] = '\0';
    
    return dst;
}

// Get header value
char *get_header_value(const char *headers, const char *name) {
    if (!headers || !name) return NULL;
    
    char search[256];
    snprintf(search, sizeof(search), "%s:", name);
    
    const char *start = strcasestr(headers, search);
    if (!start) return NULL;
    
    start += strlen(search);
    while (*start == ' ' || *start == '\t') start++;
    
    const char *end = strstr(start, "\r\n");
    if (!end) end = start + strlen(start);
    
    size_t len = end - start;
    char *value = malloc(len + 1);
    if (!value) return NULL;
    
    strncpy(value, start, len);
    value[len] = '\0';
    
    return value;
}

// Parse HTTP request
int http_parse_request(connection_t *conn) {
    if (conn->state != CONN_READING) return 0;
    
    // Read data from socket
    ssize_t bytes_read;
    if (conn->ssl) {
        bytes_read = ssl_read(conn->ssl, 
                             conn->read_buffer + conn->read_pos,
                             BUFFER_SIZE - conn->read_pos - 1);
    } else {
        bytes_read = recv(conn->sockfd, 
                         conn->read_buffer + conn->read_pos,
                         BUFFER_SIZE - conn->read_pos - 1, 0);
    }
    
    if (bytes_read <= 0) {
        if (bytes_read == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            return -1; // Connection closed or error
        }
        return 0; // No data available yet
    }
    
    conn->read_pos += bytes_read;
    conn->read_buffer[conn->read_pos] = '\0';
    
    // Update last activity time
    gettimeofday(&conn->last_activity, NULL);
    
    // Look for end of headers
    char *header_end = strstr(conn->read_buffer, "\r\n\r\n");
    if (!header_end) {
        // Check if headers are too large
        if (conn->read_pos >= MAX_HEADER_SIZE) {
            LOG_WARN_MSG("Request headers too large");
            return -1;
        }
        return 0; // Need more data
    }
    
    // Parse request line
    char *line_end = strstr(conn->read_buffer, "\r\n");
    if (!line_end) return -1;
    
    *line_end = '\0';
    
    char method_str[MAX_METHOD_SIZE];
    char uri[MAX_URI_SIZE];
    char version[MAX_VERSION_SIZE];
    
    if (sscanf(conn->read_buffer, "%15s %2047s %15s", 
               method_str, uri, version) != 3) {
        LOG_WARN_MSG("Invalid request line");
        return -1;
    }
    
    // Parse method
    conn->request.method = HTTP_GET; // Default
    for (int i = 0; http_methods[i].name; i++) {
        if (strcmp(method_str, http_methods[i].name) == 0) {
            conn->request.method = http_methods[i].method;
            break;
        }
    }
    
    // Parse URI and query string
    char *query_start = strchr(uri, '?');
    if (query_start) {
        *query_start = '\0';
        strncpy(conn->request.query_string, query_start + 1, 
                sizeof(conn->request.query_string) - 1);
    }
    
    strncpy(conn->request.uri, uri, sizeof(conn->request.uri) - 1);
    strncpy(conn->request.version, version, sizeof(conn->request.version) - 1);
    
    // Parse headers
    char *headers_start = line_end + 2;
    size_t headers_len = header_end - headers_start;
    if (headers_len < MAX_HEADER_SIZE) {
        strncpy(conn->request.headers, headers_start, headers_len);
        conn->request.headers[headers_len] = '\0';
    }
    
    // Extract common headers
    conn->request.host = get_header_value(conn->request.headers, "Host");
    conn->request.user_agent = get_header_value(conn->request.headers, "User-Agent");
    conn->request.accept_encoding = get_header_value(conn->request.headers, "Accept-Encoding");
    conn->request.connection = get_header_value(conn->request.headers, "Connection");
    
    // Check for keep-alive
    if (conn->request.connection && 
        strcasecmp(conn->request.connection, "keep-alive") == 0) {
        conn->keep_alive = 1;
    }
    
    // Parse Content-Length
    char *content_length_str = get_header_value(conn->request.headers, "Content-Length");
    if (content_length_str) {
        conn->request.content_length = strtoul(content_length_str, NULL, 10);
        free(content_length_str);
    }
    
    // Parse body for POST/PUT requests
    if (conn->request.content_length > 0) {
        char *body_start = header_end + 4;
        size_t body_in_buffer = conn->read_pos - (body_start - conn->read_buffer);
        
        if (body_in_buffer >= conn->request.content_length) {
            // Complete body received
            conn->request.body = malloc(conn->request.content_length + 1);
            if (conn->request.body) {
                memcpy(conn->request.body, body_start, conn->request.content_length);
                conn->request.body[conn->request.content_length] = '\0';
                conn->request.body_length = conn->request.content_length;
            }
        } else {
            // Need to read more body data
            // For simplicity, we'll handle this later
            return 0;
        }
    }
    
    // Set timestamp
    gettimeofday(&conn->request.timestamp, NULL);
    
    // Move to processing state
    conn->state = CONN_PROCESSING;
    
    LOG_DEBUG_MSG("Parsed request: %s %s", method_str, uri);
    return 1;
}

// Serve static file
static int serve_static_file(connection_t *conn, const char *filepath) {
    // Check cache first
    cache_entry_t *cached = cache_get_file(g_file_cache, filepath);
    if (cached) {
        // Check if client has cached version
        if (cached->etag && cache_check_etag(conn, cached->etag)) {
            http_build_response(conn, 304, NULL, NULL, 0);
            cache_entry_unref(cached);
            return 0;
        }
        
        // Serve from cache
        http_build_response(conn, HTTP_200_OK, cached->content_type, 
                           cached->data, cached->data_size);
        cache_entry_unref(cached);
        return 0;
    }
    
    // Open file
    int fd = open(filepath, O_RDONLY);
    if (fd == -1) {
        if (errno == ENOENT) {
            http_build_error_response(conn, HTTP_404_NOT_FOUND);
        } else {
            http_build_error_response(conn, HTTP_403_FORBIDDEN);
        }
        return 0;
    }
    
    struct stat st;
    if (fstat(fd, &st) == -1) {
        close(fd);
        http_build_error_response(conn, HTTP_500_INTERNAL_ERROR);
        return 0;
    }
    
    // Check if it's a regular file
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        http_build_error_response(conn, HTTP_403_FORBIDDEN);
        return 0;
    }
    
    // Get MIME type
    const char *content_type = get_mime_type(filepath);
    
    // For small files, read into memory and cache
    if (st.st_size < 1024 * 1024) { // 1MB threshold
        char *buffer = malloc(st.st_size);
        if (buffer && read(fd, buffer, st.st_size) == st.st_size) {
            // Cache the file
            cache_put(g_file_cache, filepath, buffer, st.st_size, 
                     content_type, 3600);
            
            http_build_response(conn, HTTP_200_OK, content_type, 
                               buffer, st.st_size);
            free(buffer);
        } else {
            http_build_error_response(conn, HTTP_500_INTERNAL_ERROR);
        }
    } else {
        // For large files, use sendfile
        char headers[1024];
        snprintf(headers, sizeof(headers),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: %s\r\n"
                "Content-Length: %ld\r\n"
                "Connection: %s\r\n"
                "\r\n",
                content_type, st.st_size,
                conn->keep_alive ? "keep-alive" : "close");
        
        // Send headers first
        if (conn->ssl) {
            ssl_write(conn->ssl, headers, strlen(headers));
        } else {
            send(conn->sockfd, headers, strlen(headers), 0);
        }
        
        // Send file content
        if (!conn->ssl) {
            sendfile(conn->sockfd, fd, NULL, st.st_size);
        } else {
            // For SSL, we need to read and write in chunks
            char buffer[8192];
            ssize_t bytes_read;
            while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
                ssl_write(conn->ssl, buffer, bytes_read);
            }
        }
    }
    
    close(fd);
    return 0;
}

// Handle HTTP request
int http_handle_request(connection_t *conn) {
    if (conn->state != CONN_PROCESSING) return 0;
    
    // Validate request
    if (!security_validate_request(conn)) {
        http_build_error_response(conn, HTTP_400_BAD_REQUEST);
        return 0;
    }
    
    // Log request
    log_request(conn);
    
    // URL decode
    char *decoded_uri = url_decode(conn->request.uri);
    if (!decoded_uri) {
        http_build_error_response(conn, HTTP_500_INTERNAL_ERROR);
        return 0;
    }
    
    // Security checks
    if (!security_validate_uri(decoded_uri)) {
        free(decoded_uri);
        http_build_error_response(conn, HTTP_403_FORBIDDEN);
        return 0;
    }
    
    // Find matching route
    route_t *route = router_match_route(g_router, decoded_uri, 
                                       http_method_to_string(conn->request.method));
    
    if (route) {
        switch (route->type) {
            case ROUTE_STATIC: {
                char filepath[PATH_MAX];
                snprintf(filepath, sizeof(filepath), "%s%s", 
                        route->target, decoded_uri);
                serve_static_file(conn, filepath);
                break;
            }
            case ROUTE_PROXY:
                router_proxy_request(conn, route->target);
                break;
            case ROUTE_REDIRECT:
                http_build_redirect_response(conn, route->target);
                break;
            default:
                http_build_error_response(conn, HTTP_501_NOT_IMPLEMENTED);
                break;
        }
    } else {
        // Default static file serving
        char filepath[PATH_MAX];
        snprintf(filepath, sizeof(filepath), "%s%s", 
                g_config->document_root, decoded_uri);
        
        // Check if it's a directory
        struct stat st;
        if (stat(filepath, &st) == 0 && S_ISDIR(st.st_mode)) {
            strncat(filepath, "/index.html", sizeof(filepath) - strlen(filepath) - 1);
        }
        
        serve_static_file(conn, filepath);
    }
    
    free(decoded_uri);
    
    // Move to writing state
    conn->state = CONN_WRITING;
    return 0;
}

// Build HTTP response
void http_build_response(connection_t *conn, http_status_t status,
                        const char *content_type, const char *body, size_t body_len) {
    
    conn->response.status = status;
    
    if (content_type) {
        conn->response.content_type = strdup(content_type);
    } else {
        conn->response.content_type = strdup("text/html");
    }
    
    if (body && body_len > 0) {
        // Check if compression is enabled and supported
        if (g_config->enable_compression && conn->request.accept_encoding &&
            strstr(conn->request.accept_encoding, "gzip")) {
            
            char *compressed_data;
            size_t compressed_len;
            
            if (http_compress_content(body, body_len, &compressed_data, &compressed_len) == 0) {
                conn->response.body = compressed_data;
                conn->response.body_length = compressed_len;
                conn->response.compressed = 1;
            } else {
                conn->response.body = malloc(body_len);
                memcpy(conn->response.body, body, body_len);
                conn->response.body_length = body_len;
            }
        } else {
            conn->response.body = malloc(body_len);
            if (conn->response.body) {
                memcpy(conn->response.body, body, body_len);
                conn->response.body_length = body_len;
            }
        }
    }
    
    // Build headers
    char headers[2048];
    snprintf(headers, sizeof(headers),
            "Server: CustomServer/1.0\r\n"
            "Date: %s\r\n"
            "Connection: %s\r\n",
            log_format_timestamp(),
            conn->keep_alive ? "keep-alive" : "close");
    
    if (conn->response.compressed) {
        strcat(headers, "Content-Encoding: gzip\r\n");
    }
    
    // Add security headers
    security_add_headers(headers);
    
    conn->response.headers = strdup(headers);
    gettimeofday(&conn->response.timestamp, NULL);
}

// Build error response
void http_build_error_response(connection_t *conn, http_status_t status) {
    const char *status_msg = http_status_to_string(status);
    
    char body[1024];
    snprintf(body, sizeof(body),
            "<html><head><title>%s</title></head>"
            "<body><h1>%s</h1></body></html>",
            status_msg, status_msg);
    
    http_build_response(conn, status, "text/html", body, strlen(body));
}

// Build redirect response
void http_build_redirect_response(connection_t *conn, const char *location) {
    conn->response.status = HTTP_302_FOUND;
    
    char headers[1024];
    snprintf(headers, sizeof(headers),
            "Location: %s\r\n"
            "Server: CustomServer/1.0\r\n"
            "Connection: %s\r\n",
            location,
            conn->keep_alive ? "keep-alive" : "close");
    
    conn->response.headers = strdup(headers);
    
    char body[512];
    snprintf(body, sizeof(body),
            "<html><head><title>302 Found</title></head>"
            "<body><h1>Found</h1><p>The document has moved <a href=\"%s\">here</a>.</p></body></html>",
            location);
    
    conn->response.body = strdup(body);
    conn->response.body_length = strlen(body);
    conn->response.content_type = strdup("text/html");
}

// Send HTTP response
int http_send_response(connection_t *conn) {
    if (conn->state != CONN_WRITING) return 0;
    
    if (conn->write_pos == 0) {
        // Build complete response
        const char *status_line = http_status_to_string(conn->response.status);
        
        int total_len = snprintf(conn->write_buffer, sizeof(conn->write_buffer),
                               "HTTP/1.1 %s\r\n"
                               "Content-Type: %s\r\n"
                               "Content-Length: %zu\r\n"
                               "%s"
                               "\r\n",
                               status_line,
                               conn->response.content_type,
                               conn->response.body_length,
                               conn->response.headers ? conn->response.headers : "");
        
        if (conn->response.body && conn->response.body_length > 0) {
            if (total_len + conn->response.body_length < sizeof(conn->write_buffer)) {
                memcpy(conn->write_buffer + total_len, conn->response.body, 
                       conn->response.body_length);
                total_len += conn->response.body_length;
            }
        }
        
        conn->bytes_to_write = total_len;
    }
    
    // Send data
    ssize_t bytes_sent;
    if (conn->ssl) {
        bytes_sent = ssl_write(conn->ssl, 
                              conn->write_buffer + conn->write_pos,
                              conn->bytes_to_write - conn->write_pos);
    } else {
        bytes_sent = send(conn->sockfd, 
                         conn->write_buffer + conn->write_pos,
                         conn->bytes_to_write - conn->write_pos, 0);
    }
    
    if (bytes_sent <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0; // Try again later
        }
        return -1; // Error
    }
    
    conn->write_pos += bytes_sent;
    
    if (conn->write_pos >= conn->bytes_to_write) {
        // Response sent completely
        log_response(conn);
        return 1;
    }
    
    return 0; // More data to send
}

// Compress content using gzip
int http_compress_content(const char *input, size_t input_len,
                         char **output, size_t *output_len) {
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    
    if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 
                     16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return -1;
    }
    
    size_t max_output = compressBound(input_len);
    *output = malloc(max_output);
    if (!*output) {
        deflateEnd(&stream);
        return -1;
    }
    
    stream.next_in = (Bytef*)input;
    stream.avail_in = input_len;
    stream.next_out = (Bytef*)*output;
    stream.avail_out = max_output;
    
    if (deflate(&stream, Z_FINISH) != Z_STREAM_END) {
        free(*output);
        deflateEnd(&stream);
        return -1;
    }
    
    *output_len = stream.total_out;
    deflateEnd(&stream);
    
    return 0;
}