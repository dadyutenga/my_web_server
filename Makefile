# Makefile for Custom HTTP/HTTPS Server
# Author: AI Assistant
# Date: 2025

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -pthread -D_GNU_SOURCE -O2
LDFLAGS = -lssl -lcrypto -lz -lpthread

# Directories
SRCDIR = src
INCDIR = include
OBJDIR = obj
BINDIR = bin
CONFIGDIR = config
TESTDIR = tests

# Source files
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
TARGET = $(BINDIR)/httpserver

# Test files
TEST_SOURCES = $(wildcard $(TESTDIR)/*.c)
TEST_OBJECTS = $(TEST_SOURCES:$(TESTDIR)/%.c=$(OBJDIR)/test_%.o)
TEST_TARGET = $(BINDIR)/test_runner

# Default target
.PHONY: all clean install uninstall test run debug release help

all: release

# Release build
release: CFLAGS += -DNDEBUG
release: $(TARGET)

# Debug build
debug: CFLAGS += -g -DDEBUG -fsanitize=address
debug: LDFLAGS += -fsanitize=address
debug: $(TARGET)

# Create target executable
$(TARGET): $(OBJECTS) | $(BINDIR)
	@echo "Linking $@..."
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)
	@echo "Build complete: $@"

# Compile source files
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

# Compile test files
$(OBJDIR)/test_%.o: $(TESTDIR)/%.c | $(OBJDIR)
	@echo "Compiling test $<..."
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

# Create directories
$(OBJDIR):
	mkdir -p $(OBJDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

# Test target
test: CFLAGS += -g -DDEBUG
test: $(TEST_TARGET)
	@echo "Running tests..."
	./$(TEST_TARGET)

$(TEST_TARGET): $(filter-out $(OBJDIR)/server.o, $(OBJECTS)) $(TEST_OBJECTS) | $(BINDIR)
	@echo "Linking test executable..."
	$(CC) $(filter-out $(OBJDIR)/server.o, $(OBJECTS)) $(TEST_OBJECTS) -o $@ $(LDFLAGS)

# Run the server
run: $(TARGET)
	@echo "Starting server..."
	sudo ./$(TARGET) $(CONFIGDIR)/server.conf

# Run with valgrind for memory checking
memcheck: debug
	@echo "Running with valgrind..."
	sudo valgrind --leak-check=full --show-leak-kinds=all ./$(TARGET) $(CONFIGDIR)/server.conf

# Install system-wide
install: release
	@echo "Installing server..."
	sudo cp $(TARGET) /usr/local/bin/httpserver
	sudo mkdir -p /etc/httpserver
	sudo cp -r $(CONFIGDIR)/* /etc/httpserver/
	sudo mkdir -p /var/log/httpserver
	sudo mkdir -p /var/www/html
	@echo "Installation complete"
	@echo "Configuration files: /etc/httpserver/"
	@echo "Document root: /var/www/html"
	@echo "Log directory: /var/log/httpserver"

# Uninstall
uninstall:
	@echo "Uninstalling server..."
	sudo rm -f /usr/local/bin/httpserver
	sudo rm -rf /etc/httpserver
	@echo "Uninstall complete"

# Generate SSL certificates for testing
certs:
	@echo "Generating SSL certificates..."
	mkdir -p certs
	openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt \
		-days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
	@echo "SSL certificates generated in certs/"

# Format code
format:
	@echo "Formatting code..."
	find $(SRCDIR) $(INCDIR) -name "*.c" -o -name "*.h" | xargs clang-format -i

# Static analysis
analyze:
	@echo "Running static analysis..."
	cppcheck --enable=all --inconclusive $(SRCDIR)/ $(INCDIR)/

# Check for memory leaks in tests
test-memcheck: test
	@echo "Running tests with valgrind..."
	valgrind --leak-check=full --show-leak-kinds=all ./$(TEST_TARGET)

# Generate documentation
docs:
	@echo "Generating documentation..."
	doxygen Doxyfile

# Create tarball for distribution
dist: clean
	@echo "Creating distribution tarball..."
	tar czf httpserver-$(shell date +%Y%m%d).tar.gz \
		$(SRCDIR)/ $(INCDIR)/ $(CONFIGDIR)/ $(TESTDIR)/ Makefile README.md

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(OBJDIR) $(BINDIR)
	rm -f *.tar.gz

# Deep clean (including certs and logs)
distclean: clean
	@echo "Deep cleaning..."
	rm -rf certs/ logs/ docs/

# Show help
help:
	@echo "Available targets:"
	@echo "  all        - Build release version (default)"
	@echo "  release    - Build optimized release version"
	@echo "  debug      - Build debug version with AddressSanitizer"
	@echo "  test       - Build and run tests"
	@echo "  run        - Run the server with default config"
	@echo "  install    - Install system-wide"
	@echo "  uninstall  - Remove system installation"
	@echo "  certs      - Generate SSL certificates for testing"
	@echo "  format     - Format source code"
	@echo "  analyze    - Run static analysis"
	@echo "  memcheck   - Run with valgrind"
	@echo "  docs       - Generate documentation"
	@echo "  dist       - Create distribution tarball"
	@echo "  clean      - Remove build artifacts"
	@echo "  distclean  - Remove all generated files"
	@echo "  help       - Show this help"

# Dependencies
$(OBJDIR)/server.o: $(INCDIR)/server.h $(INCDIR)/config.h $(INCDIR)/logging.h $(INCDIR)/http.h $(INCDIR)/ssl.h $(INCDIR)/router.h $(INCDIR)/security.h $(INCDIR)/cache.h
$(OBJDIR)/config.o: $(INCDIR)/config.h $(INCDIR)/logging.h
$(OBJDIR)/http.o: $(INCDIR)/http.h $(INCDIR)/logging.h $(INCDIR)/cache.h $(INCDIR)/security.h $(INCDIR)/router.h
$(OBJDIR)/ssl.o: $(INCDIR)/ssl.h $(INCDIR)/logging.h
$(OBJDIR)/logging.o: $(INCDIR)/logging.h
$(OBJDIR)/security.o: $(INCDIR)/security.h $(INCDIR)/logging.h
$(OBJDIR)/cache.o: $(INCDIR)/cache.h $(INCDIR)/logging.h
$(OBJDIR)/router.o: $(INCDIR)/router.h $(INCDIR)/logging.h $(INCDIR)/http.h