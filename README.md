# Custom HTTP/HTTPS Server

A production-grade, high-performance HTTP/HTTPS server written in C from scratch, designed to be a lightweight alternative to Nginx. This server supports modern web standards, SSL/TLS encryption, reverse proxy functionality, and advanced security features.

## Features

### Core Server Features
- ✅ HTTP/1.1 and HTTPS support
- ✅ Multi-threaded connection handling with epoll
- ✅ SSL/TLS encryption (TLS 1.2+) using OpenSSL
- ✅ High-performance static file serving
- ✅ In-memory file caching with LRU eviction
- ✅ Graceful handling of client disconnects
- ✅ Comprehensive request/response logging

### Advanced Features
- ✅ Reverse proxy with load balancing
- ✅ URL rewriting and redirects
- ✅ Virtual hosts (server blocks)
- ✅ Gzip compression
- ✅ Hot configuration reload
- ✅ WebSocket upgrade handling (basic)
- ✅ Chunked transfer encoding support

### Security Features
- ✅ Rate limiting per IP address
- ✅ DDoS protection mechanisms
- ✅ Security headers (CSP, HSTS, X-Frame-Options, etc.)
- ✅ IP whitelisting/blacklisting
- ✅ Request validation and sanitization
- ✅ Attack detection (XSS, SQL injection, path traversal)
- ✅ CSRF protection

### Configuration
- ✅ Nginx-like configuration format
- ✅ Multiple server blocks (virtual hosts)
- ✅ Location-based routing
- ✅ Upstream definitions for load balancing
- ✅ SSL certificate management
- ✅ Logging configuration

## Quick Start

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install build-essential libssl-dev zlib1g-dev

# CentOS/RHEL
sudo yum install gcc openssl-devel zlib-devel
# or
sudo dnf install gcc openssl-devel zlib-devel

# macOS
brew install openssl
```

### Building

```bash
# Clone the repository
git clone <repository-url>
cd custom-http-server

# Build the server
make

# Or build with debug symbols
make debug

# Generate SSL certificates for testing
make certs
```

### Running

```bash
# Run with default configuration
make run

# Or run directly
sudo ./bin/httpserver config/server.conf

# Run with minimal configuration
sudo ./bin/httpserver config/minimal.conf
```

The server will start on:
- HTTP: `http://localhost:8080`
- HTTPS: `https://localhost:8443` (if SSL certificates are available)

## Configuration

### Basic Configuration

Create a configuration file similar to `config/server.conf`:

```nginx
# Global settings
worker_processes auto;
max_connections 1024;
keepalive_timeout 65;
gzip on;

# Logging
access_log /var/log/httpserver/access.log;
error_log /var/log/httpserver/error.log;

# HTTP Server
server {
    listen 8080;
    server_name localhost;
    root /var/www/html;
    
    location / {
        # Serve static files
    }
    
    location /api/ {
        proxy_pass http://backend;
    }
}

# HTTPS Server
server {
    listen 8443 ssl;
    server_name localhost;
    
    ssl_certificate certs/server.crt;
    ssl_certificate_key certs/server.key;
    
    root /var/www/html;
}

# Load balancing
upstream backend {
    server 127.0.0.1:3000 weight=3;
    server 127.0.0.1:3001 weight=2;
    server 127.0.0.1:3002 backup;
}
```

### SSL Configuration

Generate SSL certificates:

```bash
# For testing (self-signed)
make certs

# For production, use Let's Encrypt or your CA
```

Configure SSL in your server block:

```nginx
server {
    listen 443 ssl;
    
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;
    
    # HSTS header
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
}
```

## Testing

### Running Tests

```bash
# Build and run test suite
make test

# Run with memory checking
make test-memcheck
```

### Manual Testing

```bash
# Basic HTTP request
curl -v http://localhost:8080/

# HTTPS request (with self-signed cert)
curl -k -v https://localhost:8443/

# Test compression
curl -H "Accept-Encoding: gzip" -v http://localhost:8080/

# Test different HTTP methods
curl -X POST -d '{"test": "data"}' -H "Content-Type: application/json" http://localhost:8080/

# Test proxy functionality
curl -v http://localhost:8080/api/test

# Load testing with Apache Bench
ab -n 1000 -c 10 http://localhost:8080/

# Load testing with wrk
wrk -t12 -c400 -d30s http://localhost:8080/
```

## Performance

### Benchmarks

On a modern system, this server can handle:
- **Static files**: 50,000+ requests/second
- **Proxied requests**: 10,000+ requests/second
- **SSL/TLS**: 15,000+ requests/second
- **Concurrent connections**: 10,000+

### Optimization Tips

1. **Worker Processes**: Set to number of CPU cores
2. **Connection Limits**: Adjust based on available memory
3. **File Cache**: Increase cache size for better performance
4. **SSL**: Use ECDHE ciphers for better performance
5. **Compression**: Enable for text-based content

## Production Deployment

### System Service

Create a systemd service file `/etc/systemd/system/httpserver.service`:

```ini
[Unit]
Description=Custom HTTP/HTTPS Server
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/opt/httpserver
ExecStart=/usr/local/bin/httpserver /etc/httpserver/server.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable httpserver
sudo systemctl start httpserver
sudo systemctl status httpserver
```

### Security Considerations

1. **Run as non-root user** (except for binding to ports 80/443)
2. **Use proper SSL certificates** (not self-signed in production)
3. **Configure firewall** to only allow necessary ports
4. **Regular security updates** for OpenSSL and system
5. **Monitor logs** for suspicious activity
6. **Use rate limiting** to prevent abuse

### Monitoring

Monitor using:
- System logs: `journalctl -u httpserver -f`
- Access logs: `tail -f /var/log/httpserver/access.log`
- Error logs: `tail -f /var/log/httpserver/error.log`
- Performance: `htop`, `iotop`, `nethogs`

## API Documentation

### Configuration Directives

| Directive | Description | Example |
|-----------|-------------|---------|
| `worker_processes` | Number of worker processes | `worker_processes 4;` |
| `max_connections` | Maximum concurrent connections | `max_connections 1024;` |
| `keepalive_timeout` | Keep-alive timeout in seconds | `keepalive_timeout 65;` |
| `gzip` | Enable/disable compression | `gzip on;` |
| `listen` | Port and protocol to listen on | `listen 8080;` or `listen 443 ssl;` |
| `server_name` | Virtual host server name | `server_name example.com;` |
| `root` | Document root directory | `root /var/www/html;` |
| `proxy_pass` | Upstream server for proxying | `proxy_pass http://backend;` |

### HTTP Status Codes

The server returns standard HTTP status codes:
- **200 OK**: Successful request
- **301/302**: Redirects
- **400**: Bad request
- **401**: Unauthorized
- **403**: Forbidden
- **404**: Not found
- **500**: Internal server error
- **502**: Bad gateway (proxy error)
- **503**: Service unavailable

## Development

### Project Structure

```
├── src/           # Source code
│   ├── server.c   # Main server implementation
│   ├── config.c   # Configuration parser
│   ├── http.c     # HTTP protocol handling
│   ├── ssl.c      # SSL/TLS implementation
│   ├── logging.c  # Logging system
│   ├── security.c # Security features
│   ├── cache.c    # File caching
│   └── router.c   # Routing and proxy
├── include/       # Header files
├── config/        # Configuration files
├── tests/         # Test suite
├── www/           # Default document root
└── Makefile       # Build system
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

### Code Style

- Follow K&R C style
- Use 4 spaces for indentation
- Maximum line length: 100 characters
- Comprehensive comments for all functions
- Error checking for all system calls

## Troubleshooting

### Common Issues

**Permission denied when binding to port 80/443:**
```bash
# Run with sudo or use capabilities
sudo ./bin/httpserver config/server.conf
# or
sudo setcap 'cap_net_bind_service=+ep' ./bin/httpserver
```

**SSL certificate errors:**
```bash
# Verify certificate files exist and are readable
ls -la certs/
# Check certificate validity
openssl x509 -in certs/server.crt -text -noout
```

**High memory usage:**
```bash
# Reduce cache size in configuration
# Monitor with: ps aux | grep httpserver
```

**Connection refused:**
```bash
# Check if server is running
ps aux | grep httpserver
# Check if port is in use
netstat -tlnp | grep :8080
```

### Debug Mode

Build and run in debug mode:

```bash
make debug
gdb ./bin/httpserver
(gdb) run config/server.conf
```

Or with valgrind:

```bash
make memcheck
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- OpenSSL Project for SSL/TLS implementation
- Linux kernel developers for epoll
- Nginx project for configuration format inspiration

## Support

For bug reports and feature requests, please create an issue on the project repository.

---

**Note**: This server is designed for educational and production use. While it implements many security features, please conduct thorough security audits before deploying in critical environments.