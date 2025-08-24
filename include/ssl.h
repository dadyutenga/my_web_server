#ifndef SSL_H
#define SSL_H

#include "server.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

// SSL context structure
typedef struct ssl_context {
    SSL_CTX *ctx;
    char *cert_file;
    char *key_file;
    char *ca_file;
    int verify_peer;
} ssl_context_t;

// SSL initialization and cleanup
int ssl_init(void);
void ssl_cleanup(void);

// SSL context management
ssl_context_t *ssl_create_context(const char *cert_file, const char *key_file);
void ssl_destroy_context(ssl_context_t *ssl_ctx);

// SSL connection handling
SSL *ssl_create_connection(ssl_context_t *ssl_ctx, int sockfd);
int ssl_accept_connection(SSL *ssl);
int ssl_read(SSL *ssl, void *buf, int num);
int ssl_write(SSL *ssl, const void *buf, int num);
void ssl_close_connection(SSL *ssl);

// SSL utility functions
int ssl_load_certificates(SSL_CTX *ctx, const char *cert_file, const char *key_file);
void ssl_print_errors(void);
int ssl_verify_certificate(SSL *ssl);

// TLS version and cipher suite management
int ssl_set_min_tls_version(SSL_CTX *ctx, int version);
int ssl_set_cipher_suites(SSL_CTX *ctx, const char *cipher_list);

// Global SSL context
extern ssl_context_t *g_ssl_ctx;

#endif // SSL_H