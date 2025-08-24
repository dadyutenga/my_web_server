#include "../include/cache.h"
#include "../include/logging.h"
#include <sys/stat.h>

// Global file cache
file_cache_t *g_file_cache = NULL;

// Hash function for cache keys
unsigned int cache_hash(const char *key) {
    unsigned int hash = 5381;
    for (int i = 0; key[i]; i++) {
        hash = ((hash << 5) + hash) + key[i];
    }
    return hash;
}

// Create file cache
file_cache_t *cache_create(cache_config_t *config) {
    if (!config) {
        LOG_ERROR_MSG("Cache configuration is NULL");
        return NULL;
    }
    
    file_cache_t *cache = calloc(1, sizeof(file_cache_t));
    if (!cache) {
        LOG_ERROR_MSG("Failed to allocate file cache");
        return NULL;
    }
    
    cache->bucket_count = 1024;
    cache->buckets = calloc(cache->bucket_count, sizeof(cache_entry_t*));
    if (!cache->buckets) {
        LOG_ERROR_MSG("Failed to allocate cache buckets");
        free(cache);
        return NULL;
    }
    
    if (pthread_rwlock_init(&cache->lock, NULL) != 0) {
        LOG_ERROR_MSG("Failed to initialize cache lock");
        free(cache->buckets);
        free(cache);
        return NULL;
    }
    
    cache->config = *config;
    cache->current_size = 0;
    cache->entry_count = 0;
    cache->lru_head = NULL;
    cache->lru_tail = NULL;
    
    LOG_INFO_MSG("File cache created: max_size=%zu, max_entries=%zu", 
                 config->max_size, config->max_entries);
    
    return cache;
}

// Destroy file cache
void cache_destroy(file_cache_t *cache) {
    if (!cache) return;
    
    pthread_rwlock_wrlock(&cache->lock);
    
    // Free all cache entries
    for (int i = 0; i < cache->bucket_count; i++) {
        cache_entry_t *entry = cache->buckets[i];
        while (entry) {
            cache_entry_t *next = entry->next;
            free(entry->key);
            free(entry->data);
            free(entry->content_type);
            free(entry->etag);
            free(entry);
            entry = next;
        }
    }
    
    free(cache->buckets);
    pthread_rwlock_unlock(&cache->lock);
    pthread_rwlock_destroy(&cache->lock);
    free(cache);
    
    LOG_INFO_MSG("File cache destroyed");
}

// Touch cache entry (update LRU position)
void cache_entry_touch(cache_entry_t *entry) {
    if (!entry) return;
    
    entry->last_accessed = time(NULL);
}

// Reference cache entry
void cache_entry_ref(cache_entry_t *entry) {
    if (!entry) return;
    
    __sync_fetch_and_add(&entry->ref_count, 1);
    cache_entry_touch(entry);
}

// Unreference cache entry
void cache_entry_unref(cache_entry_t *entry) {
    if (!entry) return;
    
    if (__sync_sub_and_fetch(&entry->ref_count, 1) == 0) {
        // Entry can be freed when ref count reaches 0
        // In practice, you'd need more sophisticated cleanup
    }
}

// Move entry to front of LRU list
static void cache_lru_move_to_front(file_cache_t *cache, cache_entry_t *entry) {
    if (entry == cache->lru_head) return;
    
    // Remove from current position
    if (entry->prev) {
        entry->prev->next = entry->next;
    }
    if (entry->next) {
        entry->next->prev = entry->prev;
    }
    if (entry == cache->lru_tail) {
        cache->lru_tail = entry->prev;
    }
    
    // Move to front
    entry->prev = NULL;
    entry->next = cache->lru_head;
    if (cache->lru_head) {
        cache->lru_head->prev = entry;
    }
    cache->lru_head = entry;
    
    if (!cache->lru_tail) {
        cache->lru_tail = entry;
    }
}

// Add entry to LRU list
static void cache_lru_add(file_cache_t *cache, cache_entry_t *entry) {
    entry->prev = NULL;
    entry->next = cache->lru_head;
    
    if (cache->lru_head) {
        cache->lru_head->prev = entry;
    }
    cache->lru_head = entry;
    
    if (!cache->lru_tail) {
        cache->lru_tail = entry;
    }
}

// Remove entry from LRU list
static void cache_lru_remove(file_cache_t *cache, cache_entry_t *entry) {
    if (entry->prev) {
        entry->prev->next = entry->next;
    } else {
        cache->lru_head = entry->next;
    }
    
    if (entry->next) {
        entry->next->prev = entry->prev;
    } else {
        cache->lru_tail = entry->prev;
    }
    
    entry->prev = entry->next = NULL;
}

// Evict least recently used entry
void cache_evict_lru(file_cache_t *cache) {
    if (!cache || !cache->lru_tail) return;
    
    cache_entry_t *lru = cache->lru_tail;
    
    // Don't evict if still referenced
    if (lru->ref_count > 0) return;
    
    // Remove from LRU list
    cache_lru_remove(cache, lru);
    
    // Remove from hash bucket
    unsigned int bucket = cache_hash(lru->key) % cache->bucket_count;
    cache_entry_t **entry_ptr = &cache->buckets[bucket];
    
    while (*entry_ptr) {
        if (*entry_ptr == lru) {
            *entry_ptr = lru->next;
            break;
        }
        entry_ptr = &(*entry_ptr)->next;
    }
    
    // Update cache stats
    cache->current_size -= lru->data_size;
    cache->entry_count--;
    
    LOG_DEBUG_MSG("Evicted cache entry: %s", lru->key);
    
    // Free entry
    free(lru->key);
    free(lru->data);
    free(lru->content_type);
    free(lru->etag);
    free(lru);
}

// Get cache entry
cache_entry_t *cache_get(file_cache_t *cache, const char *key) {
    if (!cache || !key) return NULL;
    
    pthread_rwlock_rdlock(&cache->lock);
    
    unsigned int bucket = cache_hash(key) % cache->bucket_count;
    cache_entry_t *entry = cache->buckets[bucket];
    
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            // Check if entry has expired
            time_t now = time(NULL);
            if (entry->expires > 0 && now > entry->expires) {
                pthread_rwlock_unlock(&cache->lock);
                return NULL;
            }
            
            cache_entry_ref(entry);
            cache_lru_move_to_front(cache, entry);
            pthread_rwlock_unlock(&cache->lock);
            return entry;
        }
        entry = entry->next;
    }
    
    pthread_rwlock_unlock(&cache->lock);
    return NULL;
}

// Put entry in cache
int cache_put(file_cache_t *cache, const char *key, const char *data,
              size_t data_size, const char *content_type, int ttl) {
    
    if (!cache || !key || !data || data_size == 0) return -1;
    
    pthread_rwlock_wrlock(&cache->lock);
    
    // Check if we need to evict entries
    while ((cache->current_size + data_size > cache->config.max_size) ||
           (cache->entry_count >= cache->config.max_entries)) {
        cache_evict_lru(cache);
        if (!cache->lru_tail) break; // No more entries to evict
    }
    
    // Check if entry already exists
    unsigned int bucket = cache_hash(key) % cache->bucket_count;
    cache_entry_t *existing = cache->buckets[bucket];
    
    while (existing) {
        if (strcmp(existing->key, key) == 0) {
            // Update existing entry
            free(existing->data);
            free(existing->content_type);
            free(existing->etag);
            
            existing->data = malloc(data_size);
            if (!existing->data) {
                pthread_rwlock_unlock(&cache->lock);
                return -1;
            }
            
            memcpy(existing->data, data, data_size);
            existing->data_size = data_size;
            existing->content_type = content_type ? strdup(content_type) : NULL;
            existing->created = time(NULL);
            existing->expires = ttl > 0 ? existing->created + ttl : 0;
            
            cache_entry_touch(existing);
            cache_lru_move_to_front(cache, existing);
            
            pthread_rwlock_unlock(&cache->lock);
            return 0;
        }
        existing = existing->next;
    }
    
    // Create new entry
    cache_entry_t *entry = calloc(1, sizeof(cache_entry_t));
    if (!entry) {
        pthread_rwlock_unlock(&cache->lock);
        return -1;
    }
    
    entry->key = strdup(key);
    entry->data = malloc(data_size);
    if (!entry->key || !entry->data) {
        free(entry->key);
        free(entry->data);
        free(entry);
        pthread_rwlock_unlock(&cache->lock);
        return -1;
    }
    
    memcpy(entry->data, data, data_size);
    entry->data_size = data_size;
    entry->content_type = content_type ? strdup(content_type) : NULL;
    entry->created = time(NULL);
    entry->last_accessed = entry->created;
    entry->expires = ttl > 0 ? entry->created + ttl : 0;
    entry->ref_count = 0;
    
    // Generate ETag if enabled
    if (cache->config.enable_etag) {
        char etag[64];
        snprintf(etag, sizeof(etag), "\"%lx-%zx\"", 
                 (long)entry->created, data_size);
        entry->etag = strdup(etag);
    }
    
    // Add to hash bucket
    entry->next = cache->buckets[bucket];
    cache->buckets[bucket] = entry;
    
    // Add to LRU list
    cache_lru_add(cache, entry);
    
    // Update cache stats
    cache->current_size += data_size;
    cache->entry_count++;
    
    pthread_rwlock_unlock(&cache->lock);
    
    LOG_DEBUG_MSG("Cached entry: %s (%zu bytes)", key, data_size);
    return 0;
}

// Remove cache entry
void cache_remove(file_cache_t *cache, const char *key) {
    if (!cache || !key) return;
    
    pthread_rwlock_wrlock(&cache->lock);
    
    unsigned int bucket = cache_hash(key) % cache->bucket_count;
    cache_entry_t **entry_ptr = &cache->buckets[bucket];
    
    while (*entry_ptr) {
        cache_entry_t *entry = *entry_ptr;
        if (strcmp(entry->key, key) == 0) {
            // Remove from hash bucket
            *entry_ptr = entry->next;
            
            // Remove from LRU list
            cache_lru_remove(cache, entry);
            
            // Update cache stats
            cache->current_size -= entry->data_size;
            cache->entry_count--;
            
            // Free entry
            free(entry->key);
            free(entry->data);
            free(entry->content_type);
            free(entry->etag);
            free(entry);
            
            break;
        }
        entry_ptr = &entry->next;
    }
    
    pthread_rwlock_unlock(&cache->lock);
}

// Clear all cache entries
void cache_clear(file_cache_t *cache) {
    if (!cache) return;
    
    pthread_rwlock_wrlock(&cache->lock);
    
    for (int i = 0; i < cache->bucket_count; i++) {
        cache_entry_t *entry = cache->buckets[i];
        while (entry) {
            cache_entry_t *next = entry->next;
            free(entry->key);
            free(entry->data);
            free(entry->content_type);
            free(entry->etag);
            free(entry);
            entry = next;
        }
        cache->buckets[i] = NULL;
    }
    
    cache->current_size = 0;
    cache->entry_count = 0;
    cache->lru_head = NULL;
    cache->lru_tail = NULL;
    
    pthread_rwlock_unlock(&cache->lock);
    
    LOG_INFO_MSG("Cache cleared");
}

// Cleanup expired cache entries
void cache_cleanup_expired(file_cache_t *cache) {
    if (!cache) return;
    
    pthread_rwlock_wrlock(&cache->lock);
    
    time_t now = time(NULL);
    
    for (int i = 0; i < cache->bucket_count; i++) {
        cache_entry_t **entry_ptr = &cache->buckets[i];
        
        while (*entry_ptr) {
            cache_entry_t *entry = *entry_ptr;
            
            if (entry->expires > 0 && now > entry->expires && entry->ref_count == 0) {
                // Remove expired entry
                *entry_ptr = entry->next;
                
                cache_lru_remove(cache, entry);
                cache->current_size -= entry->data_size;
                cache->entry_count--;
                
                free(entry->key);
                free(entry->data);
                free(entry->content_type);
                free(entry->etag);
                free(entry);
            } else {
                entry_ptr = &entry->next;
            }
        }
    }
    
    pthread_rwlock_unlock(&cache->lock);
}

// Get cache statistics
cache_stats_t cache_get_stats(file_cache_t *cache) {
    cache_stats_t stats = {0};
    
    if (!cache) return stats;
    
    pthread_rwlock_rdlock(&cache->lock);
    
    stats.memory_used = cache->current_size;
    stats.entries = cache->entry_count;
    
    // Calculate hits/misses (simplified - would need counters in real implementation)
    
    pthread_rwlock_unlock(&cache->lock);
    
    return stats;
}

// Cache file
int cache_file(file_cache_t *cache, const char *filepath) {
    if (!cache || !filepath) return -1;
    
    struct stat st;
    if (stat(filepath, &st) != 0) {
        return -1;
    }
    
    if (!S_ISREG(st.st_mode) || st.st_size == 0) {
        return -1;
    }
    
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        return -1;
    }
    
    char *data = malloc(st.st_size);
    if (!data) {
        fclose(file);
        return -1;
    }
    
    if (fread(data, 1, st.st_size, file) != st.st_size) {
        free(data);
        fclose(file);
        return -1;
    }
    
    fclose(file);
    
    const char *content_type = get_mime_type(filepath);
    int result = cache_put(cache, filepath, data, st.st_size, 
                          content_type, cache->config.default_ttl);
    
    free(data);
    return result;
}

// Get cached file
cache_entry_t *cache_get_file(file_cache_t *cache, const char *filepath) {
    if (!cache || !filepath) return NULL;
    
    // Check if file is cached
    cache_entry_t *entry = cache_get(cache, filepath);
    if (!entry) return NULL;
    
    // Check if file has been modified
    if (cache_is_file_modified(filepath, entry->created)) {
        cache_entry_unref(entry);
        cache_remove(cache, filepath);
        return NULL;
    }
    
    return entry;
}

// Check if file has been modified since cached time
int cache_is_file_modified(const char *filepath, time_t cached_time) {
    struct stat st;
    if (stat(filepath, &st) != 0) {
        return 1; // Assume modified if we can't stat
    }
    
    return st.st_mtime > cached_time;
}

// Generate ETag for file
char *cache_generate_etag(const char *filepath, struct stat *st) {
    if (!filepath || !st) return NULL;
    
    char *etag = malloc(64);
    if (!etag) return NULL;
    
    snprintf(etag, 64, "\"%lx-%lx\"", 
             (long)st->st_mtime, (long)st->st_size);
    
    return etag;
}

// Check ETag in request
int cache_check_etag(connection_t *conn, const char *etag) {
    if (!conn || !etag) return 0;
    
    char *if_none_match = get_header_value(conn->request.headers, "If-None-Match");
    if (!if_none_match) return 0;
    
    int match = (strcmp(if_none_match, etag) == 0);
    free(if_none_match);
    
    return match;
}

// Check Last-Modified in request
int cache_check_last_modified(connection_t *conn, time_t last_modified) {
    if (!conn) return 0;
    
    char *if_modified_since = get_header_value(conn->request.headers, "If-Modified-Since");
    if (!if_modified_since) return 0;
    
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    
    if (strptime(if_modified_since, "%a, %d %b %Y %H:%M:%S GMT", &tm)) {
        time_t client_time = timegm(&tm);
        free(if_modified_since);
        return last_modified <= client_time;
    }
    
    free(if_modified_since);
    return 0;
}