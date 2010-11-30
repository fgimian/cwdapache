#include <apr_hash.h>
#include <apr_time.h>
#include <httpd.h>
#include <http_log.h>

typedef struct cache_entry_struct cache_entry_t;

struct cache_entry_struct {
    char *key;
    void *value;
    apr_time_t expiry;
    cache_entry_t *younger;
    cache_entry_t *older;
};

typedef struct {
    const char *name;
    apr_thread_mutex_t *mutex;
    apr_hash_t *table;
    cache_entry_t *oldest;
    cache_entry_t *youngest;
    apr_time_t max_age;
    unsigned int max_entries;
    void *(*copy_data)(void *data, apr_pool_t *p);
    void (*free_data)(void *data);
} cache_t;

cache_t *cache_create(const char *name, apr_pool_t *pool, apr_time_t max_age, unsigned int max_entries,
    void *(*copy_data)(void *data, apr_pool_t *p), void (*free_data)(void *data));

void *cache_get(cache_t *cache, const char *key, const request_rec *r);

void cache_put(cache_t *cache, const char *key, void *value, const request_rec *r);
