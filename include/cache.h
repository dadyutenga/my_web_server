#ifndef CACHE_H
#define CACHE_H

#include "server.h"

// Cache entry structure
typedef struct cache_entry {
    char *key;
    char *data;
    size_t data_size;
    time_t created;
    time_t last_accessed;
    time_t expires;
    char *content_type;
    char *etag;
    int ref_count;
    struct cache_entry *next;
    struct cache_entry *prev;
} cache_entry_t;

// Cache configuration
typedef struct cache_config {
    size_t max_size;
    size_t max_entries;
    int default_ttl;
    int enable_etag;
    int enable_last_modified;
} cache_config_t;

// File cache structure
typedef struct file_cache {
    cache_entry_t **buckets;
    int bucket_count;
    size_t current_size;
    int entry_count;
    cache_entry_t *lru_head;
    cache_entry_t *lru_tail;
    pthread_rwlock_t lock;
    cache_config_t config;
} file_cache_t;

// Cache statistics
typedef struct cache_stats {
    long hits;
    long misses;
    long evictions;
    size_t memory_used;
    int entries;
} cache_stats_t;

// Cache functions
file_cache_t *cache_create(cache_config_t *config);
void cache_destroy(file_cache_t *cache);

// Cache operations
cache_entry_t *cache_get(file_cache_t *cache, const char *key);
int cache_put(file_cache_t *cache, const char *key, const char *data, 
              size_t data_size, const char *content_type, int ttl);
void cache_remove(file_cache_t *cache, const char *key);
void cache_clear(file_cache_t *cache);

// Cache management
void cache_cleanup_expired(file_cache_t *cache);
void cache_evict_lru(file_cache_t *cache);
cache_stats_t cache_get_stats(file_cache_t *cache);

// File-specific cache functions
int cache_file(file_cache_t *cache, const char *filepath);
cache_entry_t *cache_get_file(file_cache_t *cache, const char *filepath);
int cache_is_file_modified(const char *filepath, time_t cached_time);

// ETag and Last-Modified support
char *cache_generate_etag(const char *filepath, struct stat *st);
int cache_check_etag(connection_t *conn, const char *etag);
int cache_check_last_modified(connection_t *conn, time_t last_modified);

// Cache utility functions
void cache_entry_touch(cache_entry_t *entry);
void cache_entry_ref(cache_entry_t *entry);
void cache_entry_unref(cache_entry_t *entry);
unsigned int cache_hash(const char *key);

// Memory mapping for large files
typedef struct mmap_cache_entry {
    char *filepath;
    void *data;
    size_t size;
    int fd;
    time_t mtime;
    struct mmap_cache_entry *next;
} mmap_cache_entry_t;

mmap_cache_entry_t *cache_mmap_file(const char *filepath);
void cache_munmap_file(mmap_cache_entry_t *entry);

// Global file cache
extern file_cache_t *g_file_cache;

#endif // CACHE_H