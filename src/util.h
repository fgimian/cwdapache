#include <apr.h>
#include <apr_tables.h>
#include <httpd.h>

#ifndef APR_ARRAY_IDX
#define APR_ARRAY_IDX(ary,i,type) (((type *)(ary)->elts)[i])
#endif

#ifndef APR_ARRAY_PUSH
#define APR_ARRAY_PUSH(ary,type) (*((type *)apr_array_push(ary)))
#endif

#ifndef APR_INT64_MAX
#ifdef INT64_MAX
#define APR_INT64_MAX   INT64_MAX
#else
#define APR_INT64_MAX   APR_INT64_C(0x7fffffffffffffff)
#endif
#endif

void *log_ralloc(const request_rec *r, void *alloc);

void *log_palloc(apr_pool_t *pool, void *alloc);
