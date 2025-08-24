#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>

#define PORT 8080
#define BUFFER_SIZE 4096
#define MAX_CLIENTS 100

const char* get_mime_type(const char* file_ext) {
    if (strcmp(file_ext, "html") == 0 || strcmp(file_ext, "htm") == 0) {
        return "text/html";
    }
    return "text/plain";
}

void send_response(int client_socket, const char* status, const char* content_type, const char* body) {
    char response[BUFFER_SIZE * 4];
    snprintf(response, sizeof(response),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        status, content_type, strlen(body), body);
    
    send(client_socket, response, strlen(response), 0);
}

void serve_file(int client_socket, const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        const char* not_found = "<html><body><h1>404 Not Found</h1></body></html>";
        send_response(client_socket, "404 Not Found", "text/html", not_found);
        return;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* buffer = malloc(file_size + 1);
    fread(buffer, 1, file_size, file);
    buffer[file_size] = '\0';
    fclose(file);

    send_response(client_socket, "200 OK", get_mime_type("html"), buffer);
    free(buffer);
}

typedef struct {
    char method[16];
    char path[256];
    char version[16];
    char headers[BUFFER_SIZE];
    char body[BUFFER_SIZE];
    int content_length;
} http_request;

void handle_sigchld(int sig) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

void parse_request(const char* raw_request, http_request* req) {
    memset(req, 0, sizeof(http_request));
    
    char* request_copy = strdup(raw_request);
    char* line = strtok(request_copy, "\r\n");
    
    // Parse request line
    if (line) {
        sscanf(line, "%s %s %s", req->method, req->path, req->version);
    }
    
    // Parse headers
    int header_end = 0;
    while ((line = strtok(NULL, "\r\n")) && strlen(line) > 0) {
        strcat(req->headers, line);
        strcat(req->headers, "\r\n");
        
        if (strncasecmp(line, "Content-Length:", 15) == 0) {
            req->content_length = atoi(line + 16);
        }
    }
    
    // Parse body (for POST/PUT)
    if (req->content_length > 0) {
        char* body_start = strstr(raw_request, "\r\n\r\n");
        if (body_start) {
            body_start += 4;
            strncpy(req->body, body_start, req->content_length);
        }
    }
    
    free(request_copy);
}

void send_response_with_headers(int client_socket, const char* status, const char* content_type, const char* body, const char* extra_headers) {
    char response[BUFFER_SIZE * 4];
    snprintf(response, sizeof(response),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Server: CustomC/1.0\r\n"
        "Connection: close\r\n"
        "%s"
        "\r\n"
        "%s",
        status, content_type, strlen(body), extra_headers ? extra_headers : "", body);
    
    send(client_socket, response, strlen(response), 0);
}

void handle_get(int client_socket, const char* path) {
    if (strcmp(path, "/") == 0) {
        serve_file(client_socket, "index.html");
    } else {
        serve_file(client_socket, path + 1);
    }
}

void handle_post(int client_socket, const char* path, const char* body) {
    char response_body[BUFFER_SIZE];
    snprintf(response_body, sizeof(response_body),
        "<html><body>"
        "<h1>POST Request Received</h1>"
        "<p>Path: %s</p>"
        "<p>Body: %s</p>"
        "</body></html>", path, body);
    
    send_response_with_headers(client_socket, "200 OK", "text/html", response_body, NULL);
}

void handle_put(int client_socket, const char* path, const char* body) {
    // Simple file upload simulation
    char filename[256];
    snprintf(filename, sizeof(filename), "uploads%s", path);
    
    FILE* file = fopen(filename, "w");
    if (file) {
        fwrite(body, 1, strlen(body), file);
        fclose(file);
        
        char response_body[BUFFER_SIZE];
        snprintf(response_body, sizeof(response_body),
            "<html><body>"
            "<h1>PUT Request Success</h1>"
            "<p>File %s updated/created</p>"
            "</body></html>", path);
        
        send_response_with_headers(client_socket, "201 Created", "text/html", response_body, NULL);
    } else {
        const char* error_body = "<html><body><h1>500 Internal Server Error</h1></body></html>";
        send_response_with_headers(client_socket, "500 Internal Server Error", "text/html", error_body, NULL);
    }
}

void handle_delete(int client_socket, const char* path) {
    char filename[256];
    snprintf(filename, sizeof(filename), "uploads%s", path);
    
    if (remove(filename) == 0) {
        char response_body[BUFFER_SIZE];
        snprintf(response_body, sizeof(response_body),
            "<html><body>"
            "<h1>DELETE Request Success</h1>"
            "<p>File %s deleted</p>"
            "</body></html>", path);
        
        send_response_with_headers(client_socket, "200 OK", "text/html", response_body, NULL);
    } else {
        const char* not_found = "<html><body><h1>404 Not Found</h1></body></html>";
        send_response_with_headers(client_socket, "404 Not Found", "text/html", not_found, NULL);
    }
}

void handle_client(int client_socket) {
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    
    ssize_t bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received <= 0) {
        close(client_socket);
        return;
    }
    
    http_request req;
    parse_request(buffer, &req);
    
    printf("Request: %s %s\n", req.method, req.path);
    
    if (strcmp(req.method, "GET") == 0) {
        handle_get(client_socket, req.path);
    } else if (strcmp(req.method, "POST") == 0) {
        handle_post(client_socket, req.path, req.body);
    } else if (strcmp(req.method, "PUT") == 0) {
        handle_put(client_socket, req.path, req.body);
    } else if (strcmp(req.method, "DELETE") == 0) {
        handle_delete(client_socket, req.path);
    } else {
        const char* not_implemented = "<html><body><h1>501 Not Implemented</h1></body></html>";
        send_response_with_headers(client_socket, "501 Not Implemented", "text/html", not_implemented, NULL);
    }
    
    close(client_socket);
}

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Set up signal handler for child processes
    signal(SIGCHLD, handle_sigchld);

    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    // Set socket options
    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Bind failed");
        close(server_socket);
        exit(1);
    }

    // Listen for connections
    if (listen(server_socket, MAX_CLIENTS) == -1) {
        perror("Listen failed");
        close(server_socket);
        exit(1);
    }

    printf("HTTP Server running on http://localhost:%d\n", PORT);
    printf("Supports GET, POST, PUT, DELETE methods\n");

    while (1) {
        // Accept client connection
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket == -1) {
            perror("Accept failed");
            continue;
        }

        // Fork to handle multiple clients
        pid_t pid = fork();
        if (pid == 0) {
            // Child process
            close(server_socket);
            handle_client(client_socket);
            exit(0);
        } else if (pid > 0) {
            // Parent process
            close(client_socket);
        } else {
            perror("Fork failed");
            close(client_socket);
        }
    }

    close(server_socket);
    return 0;
}