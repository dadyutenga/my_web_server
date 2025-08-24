#ifndef CONFIG_H
#define CONFIG_H

#include "server.h"

// Configuration parsing functions
server_config_t *config_parse_file(const char *filename);
void config_free(server_config_t *config);
int config_reload(const char *filename);

// Configuration validation
int config_validate(server_config_t *config);

// Default configuration values
server_config_t *config_create_default(void);

// Configuration file watching for hot reload
int config_watch_file(const char *filename);
void config_stop_watching(void);

// Configuration utility functions
int config_parse_boolean(const char *value);
int config_parse_integer(const char *value, int min_val, int max_val);
char *config_parse_string(const char *value);
int config_parse_size(const char *value);

// Server block parsing
server_block_t *config_parse_server_block(const char *block_content);
location_t *config_parse_location(const char *location_content);

// Configuration directives
typedef struct config_directive {
    char *name;
    char *value;
    struct config_directive *next;
} config_directive_t;

// Configuration context
typedef struct config_context {
    config_directive_t *directives;
    struct config_context *parent;
    struct config_context *children;
    char *name;
} config_context_t;

// Configuration parser state
typedef struct config_parser {
    FILE *file;
    char *filename;
    int line_number;
    char *current_line;
    config_context_t *current_context;
    config_context_t *root_context;
} config_parser_t;

// Configuration parsing helpers
config_parser_t *config_parser_create(const char *filename);
void config_parser_destroy(config_parser_t *parser);
config_directive_t *config_parse_directive(config_parser_t *parser);
config_context_t *config_parse_context(config_parser_t *parser);

#endif // CONFIG_H