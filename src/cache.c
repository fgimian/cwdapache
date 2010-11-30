#include <apr_pools.h>

#include "util.h"

#include "cache.h"

static apr_status_t cache_destroy(void *data) {
}

cache_t *cache_create(const char *name, apr_pool_t *pool, apr_time_t max_age, unsigned int max_entries,
    void *(*copy_data)(void *data, apr_pool_t *p), void (*free_data)(void *data)) {
    cache_t *cache = log_palloc(pool, apr_pcalloc(pool, sizeof(cache_t)));
    if (cache == NULL) {
        return NULL;
    }
    if (apr_thread_mutex_create(&cache->mutex, APR_THREAD_MUTEX_DEFAULT, pool) != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_EMERG, 0, pool, "Could not create mutex");
        return NULL;
    }
    cache->table = log_palloc(pool, apr_hash_make(pool));
    if (cache->table == NULL) {
        return NULL;
    }
    cache->name = name;
    cache->max_age = max_age;
    cache->max_entries = max_entries;
    cache->copy_data = copy_data;
    cache->free_data = free_data;
    apr_pool_pre_cleanup_register(pool, cache, cache_destroy);
    return cache;
}

static void cache_clean(cache_t *cache, const request_rec *r) {
    while (cache->oldest != NULL
        && (apr_hash_count(cache->table) > cache->max_entries || cache->oldest->expiry < apr_time_now())) {
        cache_entry_t *oldest = cache->oldest;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cache '%s' expiry for '%s'", cache->name, (char *) oldest->key);
        apr_hash_set(cache->table, oldest->key, APR_HASH_KEY_STRING, NULL);
        cache->oldest = oldest->younger;
        if (cache->oldest == NULL) {
            cache->youngest == NULL;
        }
        cache->free_data(oldest->value);
        free(oldest->key);
        free(oldest);
    }
}

void *cache_get(cache_t *cache, const char *key, const request_rec *r) {
    if (apr_thread_mutex_lock(cache->mutex) != APR_SUCCESS) {
        return NULL;
    }
    cache_clean(cache, r);
    cache_entry_t *entry = apr_hash_get(cache->table, key, APR_HASH_KEY_STRING);
    void *result;
    if (entry == NULL) {
        result = NULL;
    } else {
        result = cache->copy_data(entry->value, r->pool);
    }
    apr_thread_mutex_unlock(cache->mutex);
    if (result == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cache '%s' miss for '%s'", cache->name, key);
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cache '%s' hit for '%s'", cache->name, key);
    }
    return result;
}

void cache_put(cache_t *cache, const char *key, void *value, const request_rec *r) {
    if (apr_thread_mutex_lock(cache->mutex) != APR_SUCCESS) {
        return;
    }
    cache_clean(cache, r);
    cache_entry_t *entry = apr_hash_get(cache->table, key, APR_HASH_KEY_STRING);
    if (entry == NULL) {
        entry = malloc(sizeof(cache_entry_t));
        if (entry == NULL) {
            apr_thread_mutex_unlock(cache->mutex);
            log_ralloc(r, entry);
            return;
        }
        entry->key = strdup(key);
        if (entry->key == NULL) {
            apr_thread_mutex_unlock(cache->mutex);
            free(entry);
            log_ralloc(r, entry->key);
            return;
        }
        apr_hash_set(cache->table, entry->key, APR_HASH_KEY_STRING, entry);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Creating new cache '%s' entry for '%s'", cache->name, key);
    } else {
        if (entry->younger != NULL) {
            entry->younger->older = entry->older;
            if (entry->older == NULL) {
                cache->oldest = entry->younger;
            } else {
                entry->older->younger = entry->younger;
            }
        }
        cache->free_data(entry->value);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Replacing cache '%s' entry for '%s'", cache->name, key);
    }
    entry->value = value;
    entry->expiry = apr_time_now() + cache->max_age;
    entry->younger = NULL;
    entry->older = cache->youngest;
    cache->youngest = entry;
    if (cache->oldest == NULL) {
        cache->oldest = entry;
    }
    apr_thread_mutex_unlock(cache->mutex);
}
