/**
 * crowd_client.c
 *
 * Implementation for the Atlassian Crowd C Client
 */

/* Standard includes */
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/* libcurl includes */
#include <curl/curl.h>

/* libxml includes */
#include <libxml/parser.h>
#include <libxml/xmlIO.h>
#include <libxml/xmlreader.h>

/* Apache Portable Runtime includes */
#include <apr_strings.h>

/* Apache httpd includes */
#include <httpd.h>
#include <http_log.h>

#include "util.h"

#include "crowd_client.h"

#define STATUS_CODE_UNKNOWN -1
#define XML_PROLOG "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"

cache_t *auth_cache;
cache_t *groups_cache;
cache_t *cookie_config_cache;
cache_t *session_cache;

/*===========================
 * Initialisation & clean up
 *===========================*/

static xmlChar *xml_string(const char *string) {
    xmlChar *result = xmlCharStrdup(string);
    if (result == NULL) {
        fprintf(stderr, "Could not create XML string.");
        exit(1);
    }
    return result;
}

xmlChar *user_xml_name = NULL;
xmlChar *groups_xml_name = NULL;
xmlChar *group_xml_name = NULL;
xmlChar *name_xml_name = NULL;
xmlChar *token_xml_name = NULL;
xmlChar *session_xml_name = NULL;
xmlChar *cookie_config_xml_name = NULL;
xmlChar *secure_xml_name = NULL;
xmlChar *domain_xml_name = NULL;

/**
 * Must be called before the first use of the Crowd Client.
 */
void crowd_init() {
    user_xml_name = xml_string("user");
    groups_xml_name = xml_string("groups");
    group_xml_name = xml_string("group");
    name_xml_name = xml_string("name");
    token_xml_name = xml_string("token");
    session_xml_name = xml_string("session");
    cookie_config_xml_name = xml_string("cookie-config");
    secure_xml_name = xml_string("secure");
    domain_xml_name = xml_string("domain");
    if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
        fprintf(stderr, PACKAGE_STRING " failed to initialise libcurl.");
        exit(1);
    }
    xmlInitParser();
}

/**
 * Should be called after the final use of the Crowd Client.
 */
void crowd_cleanup() {
    // Don't clean up libxml2 or libcurl as their's no guarantee that we're
    // the only people in our process using them.
    free(user_xml_name);
    free(groups_xml_name);
    free(group_xml_name);
    free(name_xml_name);
    free(token_xml_name);
    free(session_xml_name);
    free(cookie_config_xml_name);
    free(secure_xml_name);
    free(domain_xml_name);
}

/**
 * Creates a crowd_config, populated with default values.
 *
 * @param p     The APR pool from which to allocate memory.
 * @returns     A pointer to the crowd_config, or NULL upon failure.
 */
crowd_config *crowd_create_config(apr_pool_t *p) {
    crowd_config *config = log_palloc(p, apr_pcalloc(p, sizeof(crowd_config)));
    if (config == NULL) {
        return NULL;
    }
    return config;
}

static void *copy_string(void *data, apr_pool_t *p){
    return log_palloc(p, apr_pstrdup(p, data));
}

typedef struct {
} cached_auth_t;

typedef struct {
    int count;
    char **groups;
} cached_groups_t;

static void *copy_groups(void *data, apr_pool_t *p){
    cached_groups_t *original = data;
    cached_groups_t *copy = log_palloc(p, apr_palloc(p, sizeof(cached_groups_t)));
    if (copy == NULL) {
        return NULL;
    }
    copy->groups = log_palloc(p, apr_palloc(p, original->count * sizeof(char *)));
    if (copy->groups == NULL) {
        return NULL;
    }
    int i;
    for (i = 0; i < original->count; i++) {
        copy->groups[i] = log_palloc(p, apr_pstrdup(p, original->groups[i]));
        if (copy->groups[i] == NULL) {
            return NULL;
        }
    }
    copy->count = original->count;
    return copy;
}

static void free_groups(void *value) {
    cached_groups_t *cached_groups = value;
    int i;
    for (i = 0; i < cached_groups->count; i++) {
        free(cached_groups->groups[i]);
    }
    free(cached_groups->groups);
    free(cached_groups);
}

static void *copy_cookie_config(void *data, apr_pool_t *p) {
    crowd_cookie_config_t *original = data;
    crowd_cookie_config_t *copy = log_palloc(p, apr_palloc(p, sizeof(crowd_cookie_config_t)));
    if (copy == NULL) {
        return NULL;
    }
    if (original->domain == NULL) {
    	copy->domain = NULL;
    } else {
		copy->domain = log_palloc(p, apr_pstrdup(p, original->domain));
		if (copy->domain == NULL) {
			return NULL;
		}
    }
    copy->cookie_name = log_palloc(p, apr_pstrdup(p, original->cookie_name));
    if (copy->cookie_name == NULL) {
        return NULL;
    }
    copy->secure = original->secure;
    return copy;
}

static void free_cookie_config(void *value) {
    crowd_cookie_config_t *cookie_config = value;
    free(cookie_config->domain);
    free(cookie_config->cookie_name);
    free(cookie_config);
}

bool crowd_cache_create(apr_pool_t *pool, apr_time_t max_age, unsigned int max_entries) {
    auth_cache = cache_create("auth", pool, max_age, max_entries, copy_string, free);
    if (auth_cache == NULL) {
        return false;
    }
    groups_cache = cache_create("groups", pool, max_age, max_entries, copy_groups, free_groups);
    if (groups_cache == NULL) {
        return false;
    }
    cookie_config_cache = cache_create("cookie config", pool, max_age, max_entries, copy_cookie_config, free_cookie_config);
    if (cookie_config_cache == NULL) {
        return false;
    }
    session_cache = cache_create("session", pool, max_age, max_entries, copy_string, free);
    if (session_cache == NULL) {
        return false;
    }
    return true;
}

/*===========================
 * HTTP request transmission
 *===========================*/

typedef struct
{
    const char *read_ptr;
    size_t remaining;
} read_data_t;

static void make_read_data(read_data_t *read_data, const char *payload) {
    read_data->read_ptr = payload;
    read_data->remaining = strlen(payload);
}

static size_t read_crowd_authentication_request(void *ptr, size_t size, size_t nmemb, void *stream)
{
    read_data_t *read_data = (read_data_t *)stream;
    if (read_data->remaining > 0) {
        size_t chunk_size = size * nmemb;
        if (chunk_size > read_data->remaining) {
            chunk_size = read_data->remaining;
        }
        memcpy(ptr, read_data->read_ptr, chunk_size);
        read_data->read_ptr += chunk_size;
        read_data->remaining -= chunk_size;
        return chunk_size;
    } else {
        return 0;
    }
}

/**
 * Encodes text so that it can appear within an XML CDATA section.
 *
 * This is done by replacing all occurrences of "]]>" with "]]]]><![CDATA[>"
 *
 * Note that the returned string does NOT include the initial opening or final closing CDATA sequences.
 */
static const char *cdata_encode(const request_rec *r, const char *text)
{
    const size_t length = strlen(text);
    if (length < 3) {
        return text;
    }
    size_t new_length = length;
    size_t i;
    for (i = 0; i < length - 2; i++) {
        if (!bcmp(text + i, "]]>", 3)) {
            new_length += 12;
            i += 2;
        }
    }
    if (new_length == length) {
        return text;
    }
    char *new_text = apr_palloc(r->pool, new_length + 1);
    char *dest = new_text;
    for (i = 0; i <= length; i++) {
        if (!bcmp(text + i, "]]>", 3)) {
            memcpy(dest, "]]]]><![CDATA[>", 15);
            dest += 15;
            i += 2;
        } else {
            *dest = text[i];
            dest++;
        }
    }
    return new_text;
}

static const char *make_url(const request_rec *r, const crowd_config *config, CURL *curl_easy, const char *user,
    const char *format) {
    char *url;
    if (user == NULL) {
        url = apr_psprintf(r->pool, format, config->crowd_url);
    } else {
        char *encoded_user = log_ralloc(r, curl_easy_escape(curl_easy, user, 0));
        if (encoded_user == NULL) {
            return NULL;
        }
        url = apr_psprintf(r->pool, format, config->crowd_url, encoded_user);
        curl_free(encoded_user);
    }
    log_ralloc(r, url);
    if (url == NULL) {
        return NULL;
    }
    return url;
}

static bool add_header(const request_rec *r, struct curl_slist **headers, const char *header) {
    struct curl_slist *new_headers = log_ralloc(r, curl_slist_append(*headers, header));
    if (new_headers == NULL) {
        return false;
    }
    *headers = new_headers;
    return true;
}


/*=======================
 * HTTP response receipt
 *=======================*/

typedef struct write_data_struct write_data_t;

struct write_data_struct
{
    const request_rec *r;
    int status_code;
    bool headers_done;
    apr_array_header_t *response_text;
    xmlTextReaderPtr xml_reader;
    bool body_done;
    bool body_valid;
    bool (**xml_node_handlers)(write_data_t *write_data, const xmlChar *text);
    void *extra;
};

static void xml_reader_error(void *arg, const char *msg, xmlParserSeverities severity __attribute__((unused)),
    xmlTextReaderLocatorPtr locator __attribute__((unused))) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, ((write_data_t *)arg)->r, "XML reader error: %s", msg);
}

static bool create_xml_reader(write_data_t *write_data) {
    write_data->xml_reader = log_ralloc(write_data->r, xmlReaderForMemory(write_data->response_text->elts, write_data->response_text->nelts * write_data->response_text->elt_size, NULL, NULL, 0) );
    if (write_data->xml_reader == NULL) {
        return false;
    }
    xmlTextReaderSetErrorHandler(write_data->xml_reader, xml_reader_error, write_data);
    return true;
}

static size_t write_crowd_response_header(void *ptr, size_t size, size_t nmemb, void *stream) {
    write_data_t *write_data = (write_data_t *)stream;
    if (write_data->headers_done) {
        /* A new header is starting, e.g. after re-direct */
        write_data->status_code = STATUS_CODE_UNKNOWN;
        write_data->headers_done = false;
        write_data->body_done = false;
        write_data->body_valid = false;
    }
    if (write_data->status_code == STATUS_CODE_UNKNOWN) {
        /* Parse the status code from the status line. */
        char *status_line = log_ralloc(write_data->r, apr_pstrmemdup(write_data->r->pool, ptr, size * nmemb));
        if (status_line == NULL) {
            return -1;
        }
        if (sscanf(status_line, "HTTP/%*u.%*u %u ", &(write_data->status_code)) != 1) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, write_data->r, "Failed to parse status line: '%s'", status_line);
            return -1;
        }
    } else if (size * nmemb == 2 && memcmp("\r\n", ptr, 2) == 0) {
        /* End of headers for this request */
        if (write_data->status_code == STATUS_CODE_UNKNOWN) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, write_data->r, "No headers in request.");
            return -1;
        }
        write_data->headers_done = TRUE;
    }
    return size * nmemb;
}

#define XML_READER_TYPE_MAX XML_READER_TYPE_XML_DECLARATION

const xmlChar *(*xml_text_accessors[XML_READER_TYPE_MAX + 1])(xmlTextReaderPtr xml_reader) = {
    [XML_READER_TYPE_ELEMENT] = xmlTextReaderConstLocalName,
    [XML_READER_TYPE_TEXT] = xmlTextReaderConstValue
};

static size_t write_response(void *ptr, size_t size, size_t nmemb, void *stream) {
    write_data_t *write_data = (write_data_t *)stream;
    size_t length = size * nmemb;
    if (write_data->status_code == HTTP_OK || write_data->status_code == HTTP_CREATED) {
        void *end = ptr + length;
    	while (ptr < end)
    		APR_ARRAY_PUSH(write_data->response_text, char) = *(char *)ptr++;
    }
    return length;
}

void parse_xml(write_data_t *write_data){
    bool done = false;
    do {
        switch (xmlTextReaderRead(write_data->xml_reader)) {
            int node_type;
            case 0:
                done = true;
                break;
            case 1:
                node_type = xmlTextReaderNodeType(write_data->xml_reader);
                // Ignore whitespace.
                if (node_type == XML_READER_TYPE_SIGNIFICANT_WHITESPACE) {
                    break;
                }
                if (node_type < 0 || node_type > XML_READER_TYPE_MAX) {
                    node_type = XML_READER_TYPE_NONE;
                }
                bool (*node_handler)(write_data_t *write_data, const xmlChar *local_name)
                    = write_data->xml_node_handlers[node_type];
                if (node_handler == NULL) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, write_data->r, "Unexpected node type: %d", node_type);
                    write_data->body_done = done = true;
                } else {
                    const xmlChar *(*text_accessor)(xmlTextReaderPtr xml_reader) = xml_text_accessors[node_type];
                    write_data->body_done = done = node_handler(write_data, text_accessor == NULL ? NULL
                        : text_accessor(write_data->xml_reader));
                }
                break;
            default:
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, write_data->r, "Failed to parse XML.");
                write_data->body_done = done = true;
        }
    } while (!done);
}

static bool expect_xml_element(write_data_t *write_data, const xmlChar *expected_local_name,
    const xmlChar *local_name) {
    if (!xmlStrEqual(expected_local_name, local_name)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, write_data->r, "Unrecognised element: %s", local_name);
        return false;
    }
    return true;
}

typedef bool (*xml_node_handler_t)(write_data_t *write_data, const xmlChar *text);

static xml_node_handler_t *make_xml_node_handlers(const request_rec *r) {
    apr_array_header_t *array
        = log_ralloc(r, apr_array_make(r->pool, XML_READER_TYPE_XML_DECLARATION + 1, sizeof(xml_node_handler_t)));
    if (array == NULL) {
        return NULL;
    }
    return (xml_node_handler_t *) array->elts;
}

static bool handle_end_of_data(write_data_t *write_data, const xmlChar *text __attribute__((unused))) {
    write_data->body_valid = true;
    return true;
}

static bool handle_ignored_elements(write_data_t *write_data, const xmlChar* text __attribute__((unused))) {
    if (!xmlTextReaderIsEmptyElement(write_data->xml_reader)) {
        int depth = 0;
        while (1) {
           int node_type = xmlTextReaderNodeType(write_data->xml_reader);
           if (node_type == XML_READER_TYPE_ELEMENT) {
              depth++;
           } else if (node_type == XML_READER_TYPE_END_ELEMENT) {
              if (--depth == 0) {
                 return false;
              }
           }
           if (!xmlTextReaderRead(write_data->xml_reader)) {
             return true;
           }
        }
    }
    return false;
}


/*===========================================
 * Overall HTTP request & response lifecycle
 *===========================================*/

static int crowd_request(const request_rec *r, const crowd_config *config, bool expect_bad_request,
    const char *(*make_url)(const request_rec *r, const crowd_config *config, CURL *curl_easy, const void *extra),
    const char *payload, bool (**xml_node_handlers)(write_data_t *write_data, const xmlChar *text), void *extra) {

    bool success = true;

    bool post = payload != NULL;

    read_data_t read_data;
    if (post) {
        make_read_data(&read_data, payload);
    }

    write_data_t write_data = {
        .r = r,
        .status_code = STATUS_CODE_UNKNOWN,
        .xml_node_handlers = xml_node_handlers,
        .response_text = apr_array_make(r->pool, 1, sizeof(char)),
        .extra = extra};

    success = write_data.response_text != NULL;

    struct curl_slist *headers = NULL;
    if (success) {
        success = add_header(r, &headers, "Accept: application/xml");
    }
    if (success && post) {
        success = add_header(r, &headers, "Content-Type: application/xml; charset=\"utf-8\"");
    }

    CURL *curl_easy = NULL;
    if (success) {
        curl_easy = curl_easy_init();
        if (curl_easy == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "Failed to initialise libcurl.");
            success = false;
        }
    }

    const char *url;
    if (success) {
        url = make_url(r, config, curl_easy, extra);
        if (url == NULL) {
            success = false;
        }
    }

#ifndef CURLOPT_USERNAME
    const char *userpwd;
    if (success) {
        userpwd = log_ralloc(r, apr_pstrcat(r->pool, config->crowd_app_name, ":", config->crowd_app_password, NULL));
    }
#endif

    if (success) {
        if (curl_easy_setopt(curl_easy, CURLOPT_HEADERFUNCTION, write_crowd_response_header)
            || curl_easy_setopt(curl_easy, CURLOPT_WRITEHEADER, &write_data)
            || curl_easy_setopt(curl_easy, CURLOPT_WRITEFUNCTION, write_response)
            || curl_easy_setopt(curl_easy, CURLOPT_WRITEDATA, &write_data)
            || curl_easy_setopt(curl_easy, CURLOPT_URL, url)
#ifdef CURLOPT_USERNAME
            || curl_easy_setopt(curl_easy, CURLOPT_USERNAME, config->crowd_app_name)
            || curl_easy_setopt(curl_easy, CURLOPT_PASSWORD, config->crowd_app_password)
#else
            || curl_easy_setopt(curl_easy, CURLOPT_USERPWD, userpwd)
#endif
            || curl_easy_setopt(curl_easy, CURLOPT_HTTPHEADER, headers)
            || curl_easy_setopt(curl_easy, CURLOPT_TIMEOUT, config->crowd_timeout)
            || curl_easy_setopt(curl_easy, CURLOPT_SSL_VERIFYPEER, config->crowd_ssl_verify_peer ? 1 : 0)
            /* yes, it's supposed to be dir -> CURLOPT_CAPATH and path -> CURLOPT_CAINFO; see http://curl.haxx.se/libcurl/c/curl_easy_setopt.html */
            || ((config->crowd_cert_path == NULL) ? 0 : curl_easy_setopt(curl_easy, CURLOPT_CAINFO, config->crowd_cert_path))
            || ((config->crowd_cert_dir  == NULL) ? 0 : curl_easy_setopt(curl_easy, CURLOPT_CAPATH, config->crowd_cert_dir))
            || (post && (curl_easy_setopt(curl_easy, CURLOPT_POST, 1)
            || curl_easy_setopt(curl_easy, CURLOPT_READFUNCTION, read_crowd_authentication_request)
            || curl_easy_setopt(curl_easy, CURLOPT_READDATA, &read_data)
            || curl_easy_setopt(curl_easy, CURLOPT_POSTFIELDSIZE, read_data.remaining)))) {
            ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "Failed to set curl options.");
            success = false;
        }
    }

    if (success) {
        CURLcode curl_code = curl_easy_perform(curl_easy);
        if (curl_code != CURLE_OK) {
            ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                "Failed to send authentication request (CURLcode %d - %s)", curl_code, curl_easy_strerror(curl_code));
            success = false;
        }
    }

    if (success) {
        if (!write_data.headers_done) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Headers incomplete.");
            success = false;
        }
    }

    if (success) {
        switch (write_data.status_code) {
            case HTTP_BAD_REQUEST:
                if (!expect_bad_request) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Unexpected status code: %d",
                        write_data.status_code);
                    success = false;
                }
                break;
            case HTTP_OK:
            case HTTP_CREATED:
                break;
            case HTTP_UNAUTHORIZED:
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    "Application failed to authenticate as '%s' to Crowd at '%s'.",
                    config->crowd_app_name, url);
                success = false;
                break;
            default:
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Unexpected status code: %d",
                    write_data.status_code);
                success = false;
        }
    }

    /* Clean up curl */
    if (curl_easy != NULL) {
        curl_easy_cleanup(curl_easy);
    }
    if (headers != NULL) {
        curl_slist_free_all(headers);
    }

    if (success && (write_data.status_code == HTTP_OK || write_data.status_code == HTTP_CREATED)) {

    	success = create_xml_reader(&write_data);

		if (success) {
			parse_xml(&write_data);
		}

		/* Clean up xml reader */
		if (write_data.xml_reader != NULL) {
			xmlFreeTextReader(write_data.xml_reader);
		}

		if (success && !write_data.body_valid) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Unrecognised response from Crowd.");
			success = false;
		}

    }

    return success ? write_data.status_code : -1;
}

static char *make_user_cache_key(const char *username, const request_rec *r, const crowd_config *config) {
    return log_ralloc(r, apr_psprintf(r->pool, "%s\037%s\037%s", username, config->crowd_app_name, config->crowd_url));
}

static char *make_app_cache_key(const request_rec *r, const crowd_config *config) {
    return log_ralloc(r, apr_psprintf(r->pool, "%s\037%s", config->crowd_app_name, config->crowd_url));
}

static char *make_session_cache_key(const char *token, const char *forwarded_for, const request_rec *r, const crowd_config *config) {
#if AP_MODULE_MAGIC_AT_LEAST(20080403,1)
    return log_ralloc(r, apr_psprintf(r->pool, "%s\037%s\037%s\037%s\037%s", token,
        forwarded_for == NULL ? "" : forwarded_for, r->connection->client_ip, config->crowd_app_name,
        config->crowd_url));
#else
    return log_ralloc(r, apr_psprintf(r->pool, "%s\037%s\037%s\037%s\037%s", token,
        forwarded_for == NULL ? "" : forwarded_for, r->connection->remote_ip, config->crowd_app_name,
        config->crowd_url));
#endif
}

/*==========================
 * Crowd user authentication
 *==========================*/

typedef struct {
    const char *user;
} authentication_data;

static const char *make_authenticate_url(const request_rec *r, const crowd_config *config, CURL *curl_easy,
    const void *extra) {
    const authentication_data *data = (const authentication_data *)extra;
    return make_url(r, config, curl_easy, data->user, "%srest/usermanagement/1/authentication?username=%s");
}

static bool handle_crowd_authentication_user_element(write_data_t *write_data, const xmlChar *text) {
    if (expect_xml_element(write_data, user_xml_name, text)) {
        write_data->body_valid = true;
    }
    return true;
}

/**
 * Authenticate a user with Crowd.
 *
 * @param r         The current Apache httpd request.
 * @param config    The configuration details of the Crowd Client.
 * @param user      The user name to authenticate.
 * @param password  The password to authenticate.
 * @returns a crowd_authenticate_result.
 */
crowd_authenticate_result crowd_authenticate(const request_rec *r, const crowd_config *config, const char *user,
    const char *password) {

    /* Check the cache */
    char *cache_key = NULL;
    if (auth_cache != NULL) {
        cache_key = make_user_cache_key(user, r, config);
        if (cache_key != NULL) {
            char *cached_password = cache_get(auth_cache, cache_key, r);
            if (cached_password != NULL && strcmp(password, cached_password) == 0) {
                return CROWD_AUTHENTICATE_SUCCESS;
            }
        }
    }

    const char *payload = log_ralloc(r, apr_pstrcat(r->pool,
        XML_PROLOG "<password><value><![CDATA[", cdata_encode(r, password), "]]></value></password>", NULL));
    if (payload == NULL) {
        return CROWD_AUTHENTICATE_EXCEPTION;
    }

    xml_node_handler_t *xml_node_handlers = make_xml_node_handlers(r);
    if (xml_node_handlers == NULL) {
        return CROWD_AUTHENTICATE_EXCEPTION;
    }
    xml_node_handlers[XML_READER_TYPE_ELEMENT] = handle_crowd_authentication_user_element;
    authentication_data data = {user};
    switch (crowd_request(r, config, true, make_authenticate_url, payload, xml_node_handlers, &data)) {
        case HTTP_OK:

            /* Cache successful results */
            if (auth_cache != NULL && cache_key != NULL) {
                char *cached_password = log_ralloc(r, strdup(password));
                if (cached_password != NULL) {
                    cache_put(auth_cache, cache_key, cached_password, r);
                }
            }

            return CROWD_AUTHENTICATE_SUCCESS;

        case HTTP_BAD_REQUEST:
            return CROWD_AUTHENTICATE_FAILURE;

        default:
            return CROWD_AUTHENTICATE_EXCEPTION;

    }

}

typedef struct {
    const request_rec *r;
    const char *forwarded_for;
} forwarded_for_data_t;

static const char *make_create_session_url(const request_rec *r, const crowd_config *config, CURL *curl_easy,
    const void *extra __attribute__((unused))) {
    return make_url(r, config, curl_easy, NULL, "%srest/usermanagement/1/session");
}

static int check_header(void *rec, const char *key, const char *value) {
    if (strcasecmp("X-Forwarded-For", key) == 0) {
        forwarded_for_data_t *data = rec;
        data->forwarded_for = log_ralloc(data->r, apr_pstrdup(data->r->pool, value));
        return 0;
    }
    return 1;
}

static bool handle_crowd_create_session_token_text(write_data_t *write_data, const xmlChar *text) {
    char **token = write_data->extra;
    if (*token != NULL) {
        *token = log_ralloc(write_data->r, apr_pstrcat(write_data->r->pool, *token, text, NULL));
    }
    return false;
}

static bool handle_crowd_create_session_token_element(write_data_t *write_data, const xmlChar *text) {
    if (expect_xml_element(write_data, token_xml_name, text)) {
        write_data->xml_node_handlers[XML_READER_TYPE_ELEMENT] = NULL;
        write_data->xml_node_handlers[XML_READER_TYPE_TEXT] = handle_crowd_create_session_token_text;
        write_data->xml_node_handlers[XML_READER_TYPE_END_ELEMENT] = handle_end_of_data;
        return false;
    } else {
        return true;
    }
}

static bool handle_crowd_create_session_session_element(write_data_t *write_data, const xmlChar *text) {
    if (expect_xml_element(write_data, session_xml_name, text)) {
        write_data->xml_node_handlers[XML_READER_TYPE_ELEMENT] = handle_crowd_create_session_token_element;
        return false;
    } else {
        return true;
    }
}

static const char *get_validation_factors(const request_rec *r, const char *forwarded_for) {
#if AP_MODULE_MAGIC_AT_LEAST(20080403,1)
    const char *payload_beginning = log_ralloc(r, apr_pstrcat(r->pool,
        "<validation-factors><validation-factor><name>remote_address</name><value>", r->connection->client_ip,
        "</value></validation-factor>", NULL));
#else
    const char *payload_beginning = log_ralloc(r, apr_pstrcat(r->pool,
        "<validation-factors><validation-factor><name>remote_address</name><value>", r->connection->remote_ip,
        "</value></validation-factor>", NULL));
#endif
    if (payload_beginning == NULL) {
        return NULL;
    }
    const char *payload_end = "</validation-factors>";
    char *payload;
    if (forwarded_for == NULL) {
        payload = apr_pstrcat(r->pool, payload_beginning, payload_end, NULL);
    } else {
        payload = apr_pstrcat(r->pool, payload_beginning,
            "<validation-factor><name>X-Forwarded-For</name><value><![CDATA[",
            cdata_encode(r, forwarded_for), "]]></value></validation-factor>", payload_end, NULL);

    }
    log_ralloc(r, payload);
    return payload;
}

const char *get_forwarded_for(const request_rec *r) {
    forwarded_for_data_t forwarded_for_data = { .r = r };
    apr_table_do(check_header, &forwarded_for_data, r->headers_in, NULL);
    return forwarded_for_data.forwarded_for;
}

/**
 * Authenticate a user with Crowd and create a new SSO session.
 *
 * @param r         The current Apache httpd request.
 * @param config    The configuration details of the Crowd Client.
 * @param user      The user name to authenticate.
 * @param password  The password to authenticate.
 * @param token     Pointer to variable to receive the session token upon successful authentication.
 * @returns a crowd_authenticate_result.
 */
crowd_authenticate_result crowd_create_session(const request_rec *r, const crowd_config *config, const char *user,
    const char *password, const char **token) {
    *token = "";
    const char *forwarded_for = get_forwarded_for(r);
    const char *validation_factors = get_validation_factors(r, forwarded_for);
    if (validation_factors == NULL) {
        return CROWD_AUTHENTICATE_EXCEPTION;
    }
    char *payload = log_ralloc(r, apr_pstrcat(r->pool, XML_PROLOG "<authentication-context><username><![CDATA[",
        cdata_encode(r, user), "]]></username><password><![CDATA[", cdata_encode(r, password), "]]></password>",
        validation_factors, "</authentication-context>", NULL));
    if (payload == NULL) {
        return CROWD_AUTHENTICATE_EXCEPTION;
    }
    xml_node_handler_t *xml_node_handlers = make_xml_node_handlers(r);
    if (xml_node_handlers == NULL) {
        return CROWD_AUTHENTICATE_EXCEPTION;
    }
    xml_node_handlers[XML_READER_TYPE_ELEMENT] = handle_crowd_create_session_session_element;
    switch (crowd_request(r, config, true, make_create_session_url, payload, xml_node_handlers, token)) {
        case HTTP_CREATED:

            /* Cache successful results */
            if (session_cache != NULL) {
                const char *cache_key = make_session_cache_key(*token, forwarded_for, r, config);
                if (cache_key != NULL) {
                    char *cached_user = log_ralloc(r, strdup(user));
                    if (cached_user != NULL) {
                        cache_put(session_cache, cache_key, cached_user, r);
                    }
                }
            }

            return CROWD_AUTHENTICATE_SUCCESS;

        case HTTP_BAD_REQUEST:
        case HTTP_FORBIDDEN:
            return CROWD_AUTHENTICATE_FAILURE;

        default:
            return CROWD_AUTHENTICATE_EXCEPTION;

    }
}

typedef struct {
    char *token;
    char **user;
} crowd_validate_session_data;

static const char *make_validate_session_url(const request_rec *r, const crowd_config *config, CURL *curl_easy,
    const void *extra) {
    const crowd_validate_session_data *data = extra;

    const char *urlWithoutToken = make_url(r, config, curl_easy, NULL, "%srest/usermanagement/1/session/");

    const char* escapedToken = curl_easy_escape(curl_easy, data->token, 0);
    if (escapedToken == NULL) {
        return NULL;
    }

    char *url = log_ralloc(r, apr_pstrcat(r->pool, urlWithoutToken, escapedToken, NULL));

    curl_free((void *)escapedToken);

    return url;
}

static bool handle_crowd_validate_session_user_element(write_data_t *write_data, const xmlChar* text) {
    crowd_validate_session_data *data = write_data->extra;
    if (!expect_xml_element(write_data, user_xml_name, text)) {
        return true;
    }
    xmlChar *user = xmlTextReaderGetAttribute(write_data->xml_reader, name_xml_name);
    if (user == NULL) {
        return true;
    }
    *data->user = log_ralloc(write_data->r, apr_pstrdup(write_data->r->pool, (char const*)user));
    if (*data->user != NULL) {
        return handle_end_of_data(write_data, text);
    }
    return true;
}

static bool handle_crowd_validate_session_token_end(write_data_t *write_data,
    const xmlChar *text __attribute__((unused))) {
    write_data->xml_node_handlers[XML_READER_TYPE_ELEMENT] = handle_crowd_validate_session_user_element;
    write_data->xml_node_handlers[XML_READER_TYPE_TEXT] = NULL;
    write_data->xml_node_handlers[XML_READER_TYPE_END_ELEMENT] = NULL;
    return false;
}

static bool handle_crowd_validate_session_token_text(write_data_t *write_data __attribute__((unused)),
    const xmlChar *text __attribute__((unused))) {
    return false;
}

static bool handle_crowd_validate_session_token_element(write_data_t *write_data,
    const xmlChar *text __attribute__((unused))) {
    write_data->xml_node_handlers[XML_READER_TYPE_ELEMENT] = NULL;
    write_data->xml_node_handlers[XML_READER_TYPE_TEXT] = handle_crowd_validate_session_token_text;
    write_data->xml_node_handlers[XML_READER_TYPE_END_ELEMENT] = handle_crowd_validate_session_token_end;
    return false;
}

static bool handle_crowd_validate_session_session_element(write_data_t *write_data, const xmlChar *text) {
    if (expect_xml_element(write_data, session_xml_name, text)) {
        write_data->xml_node_handlers[XML_READER_TYPE_ELEMENT] = handle_crowd_validate_session_token_element;
        return false;
    }
    return true;
}

/**
 * Validate an existing SSO session.
 *
 * @param r         The current Apache httpd request.
 * @param config    The configuration details of the Crowd Client.
 * @param token     The session token.
 * @returns a crowd_authenticate_result.
 */
crowd_authenticate_result crowd_validate_session(const request_rec *r, const crowd_config *config, char *token,
    char **user) {
    *user = NULL;
    const char *forwarded_for = get_forwarded_for(r);

    /* Check cache */
    char *cache_key = NULL;
    if (session_cache != NULL) {
        cache_key = make_session_cache_key(token, forwarded_for, r, config);
        if (cache_key != NULL) {
            *user = cache_get(session_cache, cache_key, r);
            if (*user != NULL) {
                return CROWD_AUTHENTICATE_SUCCESS;
            }
        }
    }

    const char *validation_factors = get_validation_factors(r, forwarded_for);
    if (validation_factors == NULL) {
        return CROWD_AUTHENTICATE_EXCEPTION;
    }
    char *payload = log_ralloc(r, apr_pstrcat(r->pool, XML_PROLOG, validation_factors, NULL));
    if (payload == NULL) {
        return CROWD_AUTHENTICATE_EXCEPTION;
    }
    xml_node_handler_t *xml_node_handlers = make_xml_node_handlers(r);
    if (xml_node_handlers == NULL) {
        return CROWD_AUTHENTICATE_EXCEPTION;
    }
    crowd_validate_session_data data = {token, user};
    xml_node_handlers[XML_READER_TYPE_ELEMENT] = handle_crowd_validate_session_session_element;
    switch (crowd_request(r, config, false, make_validate_session_url, payload, xml_node_handlers, &data)) {
        case HTTP_OK:

            /* Cache successful results */
            if (cache_key != NULL) {
                char *cached_user = log_ralloc(r, strdup(*user));
                if (cached_user != NULL) {
                    cache_put(session_cache, cache_key, cached_user, r);
                }
            }

            return CROWD_AUTHENTICATE_SUCCESS;

        case HTTP_BAD_REQUEST:
        case HTTP_NOT_FOUND:
            return CROWD_AUTHENTICATE_FAILURE;

        default:
            return CROWD_AUTHENTICATE_EXCEPTION;

    }
}

/*============================
 * Crowd user group retrieval
 *============================*/

typedef struct {
    const char *user;
    apr_array_header_t *user_groups;
    unsigned start_index;
} groups_data;

#define BATCH_SIZE 1000U

static const char *make_groups_url(const request_rec *r, const crowd_config *config, CURL *curl_easy,
    const void *extra) {
    const groups_data *data = (const groups_data *)extra;
    const char *url_template = log_ralloc(r, apr_psprintf(r->pool,
        "%%srest/usermanagement/1/user/group/nested?username=%%s&start-index=%u&max-results=%u",
        data->start_index, BATCH_SIZE));
    if (url_template == NULL) {
        return NULL;
    }
    return make_url(r, config, curl_easy, data->user, url_template);
}

static bool handle_crowd_groups_group_end(write_data_t *write_data, const xmlChar* text);

static bool handle_crowd_groups_group_element(write_data_t *write_data, const xmlChar* text) {
    if (!expect_xml_element(write_data, group_xml_name, text)) {
        return true;
    }
    xmlChar *groupName = xmlTextReaderGetAttribute(write_data->xml_reader, name_xml_name);
    if (groupName == NULL) {
        return true;
    }
    groupName = log_ralloc(write_data->r, apr_pstrdup(write_data->r->pool, (char const*)groupName));
    if (groupName == NULL) {
        return true;
    }
    APR_ARRAY_PUSH(((groups_data *) write_data->extra)->user_groups, const char *) = (char const*)groupName;
    write_data->xml_node_handlers[XML_READER_TYPE_ELEMENT] = handle_ignored_elements;
    write_data->xml_node_handlers[XML_READER_TYPE_END_ELEMENT] = handle_crowd_groups_group_end;
    return false;
}

static bool handle_crowd_groups_group_end(write_data_t *write_data, const xmlChar* text __attribute__((unused))) {
    write_data->xml_node_handlers[XML_READER_TYPE_ELEMENT] = handle_crowd_groups_group_element;
    write_data->xml_node_handlers[XML_READER_TYPE_END_ELEMENT] = handle_end_of_data;
    return false;
}

static bool handle_crowd_groups_groups_element(write_data_t *write_data, const xmlChar *text) {
    if (!expect_xml_element(write_data, groups_xml_name, text)) {
        return true;
    }
    if (xmlTextReaderIsEmptyElement(write_data->xml_reader)) {
        return handle_end_of_data(write_data, NULL);
    }
    write_data->xml_node_handlers[XML_READER_TYPE_ELEMENT] = handle_crowd_groups_group_element;
    write_data->xml_node_handlers[XML_READER_TYPE_END_ELEMENT] = handle_end_of_data;
    return false;
}

/**
 * Obtain the list of Crowd groups to which the specified user belongs.
 *
 * Nested groups are included in the result.
 *
 * @param username  The name of the user.
 * @param r         The current Apache httpd request.
 * @param config    The configuration details of the Crowd Client.
 * @returns An APR array of (char *) group names, or NULL upon failure.
 */
apr_array_header_t *crowd_user_groups(const char *username, const request_rec *r, const crowd_config *config) {
    apr_array_header_t *user_groups;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Memberships requested for '%s'", username);

    /* Check cache */
    char *cache_key = NULL;
    if (groups_cache != NULL) {
        cache_key = make_user_cache_key(username, r, config);
        if (cache_key != NULL) {
            cached_groups_t *cached_groups = cache_get(groups_cache, cache_key, r);
            if (cached_groups != NULL) {
                user_groups = log_ralloc(r, apr_array_make(r->pool, cached_groups->count, sizeof(char *)));
                if (user_groups == NULL) {
                    return NULL;
                }
                int i;
                for (i = 0; i < cached_groups->count; i++) {
                    APR_ARRAY_PUSH(user_groups, const char *) = apr_pstrdup(r->pool, cached_groups->groups[i]);
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cached group membership for '%s': %s", username, cached_groups->groups[i]);
                }
                return user_groups;
            }
        }
    }

    user_groups = log_ralloc(r, apr_array_make(r->pool, 0, sizeof(char *)));
    if (user_groups == NULL) {
        return NULL;
    }
    groups_data data = {username, user_groups, 0};
    do {
        xml_node_handler_t *xml_node_handlers = make_xml_node_handlers(r);
        if (xml_node_handlers == NULL) {
            return NULL;
        }
        xml_node_handlers[XML_READER_TYPE_ELEMENT] = handle_crowd_groups_groups_element;
        if (crowd_request(r, config, false, make_groups_url, NULL, xml_node_handlers, &data) != HTTP_OK) {
            return NULL;
        }
        data.start_index += BATCH_SIZE;
    } while ((unsigned)(user_groups->nelts) == data.start_index);

    /* Cache result */
    if (cache_key != NULL) {
        cached_groups_t *cached_groups = log_ralloc(r, malloc(sizeof(cached_groups_t)));
        if (cached_groups != NULL) {
            cached_groups->groups = log_ralloc(r, malloc(user_groups->nelts * sizeof(char *)));
            if (cached_groups->groups == NULL) {
                free(cached_groups);
            } else {
                int i;
                for (i = 0; i < user_groups->nelts; i++) {
                    cached_groups->groups[i] = log_ralloc(r, strdup(APR_ARRAY_IDX(user_groups, i, char *)));
                    if (cached_groups->groups[i] == NULL) {
                        for (i--; i >= 0; i--) {
                            free(cached_groups->groups[i]);
                        }
                        free(cached_groups->groups);
                        free(cached_groups);
                        return user_groups;
                    }
                }
                cached_groups->count = user_groups->nelts;
                cache_put(groups_cache, cache_key, cached_groups, r);
            }
        }
    }

    return user_groups;
}

static const char *make_cookie_config_url(const request_rec *r, const crowd_config *config, CURL *curl_easy,
    const void *extra __attribute__((unused))) {
    return make_url(r, config, curl_easy, NULL, "%srest/usermanagement/1/config/cookie");
}

typedef struct {
    crowd_cookie_config_t *result;
    char *secure;
} crowd_cookie_config_extra;

static bool handle_crowd_cookie_config_name_text(write_data_t *write_data, const xmlChar *text) {
    crowd_cookie_config_extra *extra = write_data->extra;
    extra->result->cookie_name = log_ralloc(write_data->r, apr_pstrcat(write_data->r->pool, extra->result->cookie_name,
        text, NULL));
    if (extra->result->cookie_name == NULL) {
        return true;
    }
    return false;
}

static bool handle_crowd_cookie_config_name_element(write_data_t *write_data, const xmlChar *text) {
    if (expect_xml_element(write_data, name_xml_name, text)) {
        write_data->xml_node_handlers[XML_READER_TYPE_ELEMENT] = NULL;
        write_data->xml_node_handlers[XML_READER_TYPE_TEXT] = handle_crowd_cookie_config_name_text;
        write_data->xml_node_handlers[XML_READER_TYPE_END_ELEMENT] = handle_end_of_data;
        return false;
    } else {
        return true;
    }
}

static bool handle_crowd_cookie_config_secure_text(write_data_t *write_data, const xmlChar *text) {
    crowd_cookie_config_extra *extra = write_data->extra;
    extra->secure = log_ralloc(write_data->r, apr_pstrcat(write_data->r->pool, extra->secure, text, NULL));
    if (extra->secure == NULL) {
        return true;
    }
    return false;
}

static bool handle_crowd_cookie_config_secure_end(write_data_t *write_data,
    const xmlChar *text __attribute__((unused))) {
    write_data->xml_node_handlers[XML_READER_TYPE_ELEMENT] = handle_crowd_cookie_config_name_element;
    write_data->xml_node_handlers[XML_READER_TYPE_TEXT] = NULL;
    write_data->xml_node_handlers[XML_READER_TYPE_END_ELEMENT] = NULL;
    return false;
}

static bool handle_crowd_cookie_config_secure_element(write_data_t *write_data, const xmlChar *text) {
    if (expect_xml_element(write_data, secure_xml_name, text)) {
        write_data->xml_node_handlers[XML_READER_TYPE_ELEMENT] = NULL;
        write_data->xml_node_handlers[XML_READER_TYPE_TEXT] = handle_crowd_cookie_config_secure_text;
        write_data->xml_node_handlers[XML_READER_TYPE_END_ELEMENT] = handle_crowd_cookie_config_secure_end;
        return false;
    } else {
        return true;
    }
}

static bool handle_crowd_cookie_config_domain_text(write_data_t *write_data, const xmlChar *text) {
    crowd_cookie_config_extra *extra = write_data->extra;
    extra->result->domain
        = log_ralloc(write_data->r, apr_pstrcat(write_data->r->pool, extra->result->domain, text, NULL));
    if (extra->result->domain == NULL) {
        return true;
    }
    return false;
}

static bool handle_crowd_cookie_config_domain_end(write_data_t *write_data,
    const xmlChar *text __attribute__((unused))) {
    write_data->xml_node_handlers[XML_READER_TYPE_ELEMENT] = handle_crowd_cookie_config_secure_element;
    write_data->xml_node_handlers[XML_READER_TYPE_TEXT] = NULL;
    write_data->xml_node_handlers[XML_READER_TYPE_END_ELEMENT] = NULL;
    return false;
}

static bool handle_crowd_cookie_config_domain_or_secure_element(write_data_t *write_data, const xmlChar *text) {
    if (xmlStrEqual(domain_xml_name, text)) {
        crowd_cookie_config_extra *extra = write_data->extra;
        extra->result->domain = "";
        write_data->xml_node_handlers[XML_READER_TYPE_ELEMENT] = NULL;
        write_data->xml_node_handlers[XML_READER_TYPE_TEXT] = handle_crowd_cookie_config_domain_text;
        write_data->xml_node_handlers[XML_READER_TYPE_END_ELEMENT] = handle_crowd_cookie_config_domain_end;
        return false;
    }
    return handle_crowd_cookie_config_secure_element(write_data, text);
}

static bool handle_crowd_cookie_config_cookie_config_element(write_data_t *write_data, const xmlChar *text) {
    if (expect_xml_element(write_data, cookie_config_xml_name, text)) {
        write_data->xml_node_handlers[XML_READER_TYPE_ELEMENT] = handle_crowd_cookie_config_domain_or_secure_element;
        return false;
    } else {
        return true;
    }
}

crowd_cookie_config_t *crowd_get_cookie_config(const request_rec *r, const crowd_config *config) {

    /* Check cache */
    char *cache_key = NULL;
    if (cookie_config_cache != NULL) {
        cache_key = make_app_cache_key(r, config);
        if (cache_key != NULL) {
            crowd_cookie_config_t *cookie_config = cache_get(cookie_config_cache, cache_key, r);
            if (cookie_config != NULL) {
                return cookie_config;
            }
        }
    }

    crowd_cookie_config_extra extra = {
        log_ralloc(r, apr_pcalloc(r->pool, sizeof(crowd_cookie_config_t))),
        ""
    };
    if (extra.result == NULL) {
        return NULL;
    }
    extra.result->domain = NULL;
    extra.result->cookie_name = "";
    xml_node_handler_t *xml_node_handlers = make_xml_node_handlers(r);
    if (xml_node_handlers == NULL) {
        return NULL;
    }
    xml_node_handlers[XML_READER_TYPE_ELEMENT] = handle_crowd_cookie_config_cookie_config_element;
    if (crowd_request(r, config, false, make_cookie_config_url, NULL, xml_node_handlers, &extra) != HTTP_OK) {
        return NULL;
    }
    if (strcmp("true", extra.secure) == 0) {
        extra.result->secure = true;
    } else if (strcmp("false", extra.secure) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Unrecognised 'secure' value from Crowd.");
        return NULL;
    }

    /* Cache result */
    if (cache_key != NULL) {
        crowd_cookie_config_t *cached = log_ralloc(r, malloc(sizeof(crowd_cookie_config_t)));
        if (cached != NULL) {
        	if (extra.result->domain != NULL) {
        		cached->domain = log_ralloc(r, strdup(extra.result->domain));
                if (cached->domain == NULL) {
                    free(cached);
                    return NULL;
                }
            } else {
                cached->domain = NULL;
            }
            cached->cookie_name = log_ralloc(r, strdup(extra.result->cookie_name));
            if (cached->cookie_name == NULL) {
                free(cached->domain);
                free(cached);
            } else {
                cached->secure = extra.result->secure;
                cache_put(cookie_config_cache, cache_key, cached, r);
            }
        }
    }

    return extra.result;
}
