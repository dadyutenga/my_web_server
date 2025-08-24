#include "../include/ssl.h"
#include "../include/logging.h"

// Global SSL context
ssl_context_t *g_ssl_ctx = NULL;

// Initialize OpenSSL
int ssl_init(void) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    LOG_INFO_MSG("OpenSSL initialized");
    return 0;
}

// Cleanup OpenSSL
void ssl_cleanup(void) {
    EVP_cleanup();
    ERR_free_strings();
    LOG_INFO_MSG("OpenSSL cleaned up");
}

// Print SSL errors
void ssl_print_errors(void) {
    unsigned long error;
    char error_string[256];
    
    while ((error = ERR_get_error()) != 0) {
        ERR_error_string_n(error, error_string, sizeof(error_string));
        LOG_ERROR_MSG("SSL Error: %s", error_string);
    }
}

// Load certificates
int ssl_load_certificates(SSL_CTX *ctx, const char *cert_file, const char *key_file) {
    if (!cert_file || !key_file) {
        LOG_ERROR_MSG("Certificate or key file not specified");
        return -1;
    }
    
    // Load certificate
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        LOG_ERROR_MSG("Failed to load certificate file: %s", cert_file);
        ssl_print_errors();
        return -1;
    }
    
    // Load private key
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        LOG_ERROR_MSG("Failed to load private key file: %s", key_file);
        ssl_print_errors();
        return -1;
    }
    
    // Verify private key
    if (!SSL_CTX_check_private_key(ctx)) {
        LOG_ERROR_MSG("Private key does not match certificate");
        ssl_print_errors();
        return -1;
    }
    
    LOG_INFO_MSG("SSL certificates loaded successfully");
    return 0;
}

// Set minimum TLS version
int ssl_set_min_tls_version(SSL_CTX *ctx, int version) {
    if (SSL_CTX_set_min_proto_version(ctx, version) <= 0) {
        LOG_ERROR_MSG("Failed to set minimum TLS version");
        ssl_print_errors();
        return -1;
    }
    
    LOG_INFO_MSG("Minimum TLS version set to %d", version);
    return 0;
}

// Set cipher suites
int ssl_set_cipher_suites(SSL_CTX *ctx, const char *cipher_list) {
    if (!cipher_list) {
        cipher_list = "HIGH:!aNULL:!MD5:!RC4:!3DES";
    }
    
    if (SSL_CTX_set_cipher_list(ctx, cipher_list) <= 0) {
        LOG_ERROR_MSG("Failed to set cipher list");
        ssl_print_errors();
        return -1;
    }
    
    LOG_INFO_MSG("Cipher suites configured");
    return 0;
}

// Create SSL context
ssl_context_t *ssl_create_context(const char *cert_file, const char *key_file) {
    ssl_context_t *ssl_ctx = calloc(1, sizeof(ssl_context_t));
    if (!ssl_ctx) {
        LOG_ERROR_MSG("Failed to allocate SSL context");
        return NULL;
    }
    
    // Create SSL context
    ssl_ctx->ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx->ctx) {
        LOG_ERROR_MSG("Failed to create SSL context");
        ssl_print_errors();
        free(ssl_ctx);
        return NULL;
    }
    
    // Set options for security
    SSL_CTX_set_options(ssl_ctx->ctx, 
                       SSL_OP_NO_SSLv2 | 
                       SSL_OP_NO_SSLv3 | 
                       SSL_OP_NO_TLSv1 | 
                       SSL_OP_NO_TLSv1_1 |
                       SSL_OP_CIPHER_SERVER_PREFERENCE |
                       SSL_OP_SINGLE_DH_USE |
                       SSL_OP_SINGLE_ECDH_USE);
    
    // Set minimum TLS version to 1.2
    if (ssl_set_min_tls_version(ssl_ctx->ctx, TLS1_2_VERSION) < 0) {
        SSL_CTX_free(ssl_ctx->ctx);
        free(ssl_ctx);
        return NULL;
    }
    
    // Set cipher suites
    if (ssl_set_cipher_suites(ssl_ctx->ctx, NULL) < 0) {
        SSL_CTX_free(ssl_ctx->ctx);
        free(ssl_ctx);
        return NULL;
    }
    
    // Load certificates
    if (ssl_load_certificates(ssl_ctx->ctx, cert_file, key_file) < 0) {
        SSL_CTX_free(ssl_ctx->ctx);
        free(ssl_ctx);
        return NULL;
    }
    
    // Set up ECDH
    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ecdh) {
        SSL_CTX_set_tmp_ecdh(ssl_ctx->ctx, ecdh);
        EC_KEY_free(ecdh);
    }
    
    // Store file paths
    ssl_ctx->cert_file = strdup(cert_file);
    ssl_ctx->key_file = strdup(key_file);
    
    LOG_INFO_MSG("SSL context created successfully");
    return ssl_ctx;
}

// Destroy SSL context
void ssl_destroy_context(ssl_context_t *ssl_ctx) {
    if (!ssl_ctx) return;
    
    if (ssl_ctx->ctx) {
        SSL_CTX_free(ssl_ctx->ctx);
    }
    
    free(ssl_ctx->cert_file);
    free(ssl_ctx->key_file);
    free(ssl_ctx->ca_file);
    free(ssl_ctx);
    
    LOG_INFO_MSG("SSL context destroyed");
}

// Create SSL connection
SSL *ssl_create_connection(ssl_context_t *ssl_ctx, int sockfd) {
    if (!ssl_ctx || !ssl_ctx->ctx) {
        LOG_ERROR_MSG("Invalid SSL context");
        return NULL;
    }
    
    SSL *ssl = SSL_new(ssl_ctx->ctx);
    if (!ssl) {
        LOG_ERROR_MSG("Failed to create SSL connection");
        ssl_print_errors();
        return NULL;
    }
    
    if (SSL_set_fd(ssl, sockfd) <= 0) {
        LOG_ERROR_MSG("Failed to set SSL file descriptor");
        ssl_print_errors();
        SSL_free(ssl);
        return NULL;
    }
    
    return ssl;
}

// Accept SSL connection
int ssl_accept_connection(SSL *ssl) {
    if (!ssl) return -1;
    
    int ret = SSL_accept(ssl);
    if (ret <= 0) {
        int error = SSL_get_error(ssl, ret);
        
        switch (error) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                // Non-blocking operation, try again later
                return 0;
            
            case SSL_ERROR_SYSCALL:
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return 0;
                }
                LOG_ERROR_MSG("SSL accept syscall error: %s", strerror(errno));
                break;
            
            default:
                LOG_ERROR_MSG("SSL accept failed with error %d", error);
                ssl_print_errors();
                break;
        }
        
        return -1;
    }
    
    LOG_DEBUG_MSG("SSL connection accepted successfully");
    return 1;
}

// Read from SSL connection
int ssl_read(SSL *ssl, void *buf, int num) {
    if (!ssl) return -1;
    
    int ret = SSL_read(ssl, buf, num);
    if (ret <= 0) {
        int error = SSL_get_error(ssl, ret);
        
        switch (error) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                errno = EAGAIN;
                return -1;
            
            case SSL_ERROR_ZERO_RETURN:
                // SSL connection closed
                return 0;
            
            case SSL_ERROR_SYSCALL:
                if (errno == 0) {
                    // Unexpected EOF
                    return 0;
                }
                break;
            
            default:
                LOG_ERROR_MSG("SSL read failed with error %d", error);
                ssl_print_errors();
                break;
        }
        
        return -1;
    }
    
    return ret;
}

// Write to SSL connection
int ssl_write(SSL *ssl, const void *buf, int num) {
    if (!ssl) return -1;
    
    int ret = SSL_write(ssl, buf, num);
    if (ret <= 0) {
        int error = SSL_get_error(ssl, ret);
        
        switch (error) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                errno = EAGAIN;
                return -1;
            
            case SSL_ERROR_ZERO_RETURN:
                // SSL connection closed
                return 0;
            
            default:
                LOG_ERROR_MSG("SSL write failed with error %d", error);
                ssl_print_errors();
                break;
        }
        
        return -1;
    }
    
    return ret;
}

// Close SSL connection
void ssl_close_connection(SSL *ssl) {
    if (!ssl) return;
    
    // Shutdown SSL connection gracefully
    int ret = SSL_shutdown(ssl);
    if (ret == 0) {
        // First shutdown successful, do second shutdown
        SSL_shutdown(ssl);
    } else if (ret < 0) {
        int error = SSL_get_error(ssl, ret);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
            LOG_DEBUG_MSG("SSL shutdown error: %d", error);
        }
    }
    
    SSL_free(ssl);
}

// Verify certificate
int ssl_verify_certificate(SSL *ssl) {
    if (!ssl) return 0;
    
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        LOG_WARN_MSG("No client certificate provided");
        return 0;
    }
    
    long verify_result = SSL_get_verify_result(ssl);
    X509_free(cert);
    
    if (verify_result != X509_V_OK) {
        LOG_WARN_MSG("Certificate verification failed: %ld", verify_result);
        return 0;
    }
    
    LOG_DEBUG_MSG("Certificate verified successfully");
    return 1;
}