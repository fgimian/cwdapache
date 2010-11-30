#include "util.h"

#include <http_log.h>

void *log_ralloc(const request_rec *r, void *alloc) {
  if (alloc == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "Out of memory");
  }
  return alloc;
}

void *log_palloc(apr_pool_t *pool, void *alloc) {
  if (alloc == NULL) {
    ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, pool, "Out of memory");
  }
  return alloc;
}
