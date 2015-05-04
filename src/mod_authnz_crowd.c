/* Standard headers */
#include <stdbool.h>
#include <string.h>

/* Apache Portable Runtime includes */
#include <apr_strings.h>
#include <apr_xlate.h>

/* Apache httpd includes */
#include <ap_provider.h>
#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>
#include <mod_auth.h>

#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include "../config.h"

#include "crowd_client.h"
#include "util.h"

#include "mod_authnz_crowd.h"

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));
static APR_OPTIONAL_FN_TYPE(ssl_is_https) *crowd_is_https = NULL;
#endif

static struct
{
    const char *cache_max_entries_string;
    const char *cache_max_age_string;
} authnz_crowd_process_config;

typedef struct
{
    bool authoritative;
    bool authoritative_set;
    const char *crowd_timeout_string;
    apr_array_header_t *basic_auth_xlates;  /* Character translations to be used when decoding Basic authentication
                                               credentials. */
    crowd_config *crowd_config;
    bool accept_sso;
    bool accept_sso_set;
    bool create_sso;
    bool create_sso_set;
    bool set_http_only;
    bool set_http_only_set;
    bool ssl_verify_peer_set;

} authnz_crowd_dir_config;

module AP_MODULE_DECLARE_DATA authnz_crowd_module;

static const char *dir_configs_key = "authnz_crowd_dir_configs_key";

/** Function to allow all modules to create per directory configuration
 *  structures.
 *  @param p The pool to use for all allocations.
 *  @param dir The directory currently being processed.
 *  @return The per-directory structure created
 */
static void *create_dir_config(apr_pool_t *p, char *dir)
{
    ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, p, "Creating Crowd config for '%s'", dir);
    authnz_crowd_dir_config *dir_config = log_palloc(p, apr_pcalloc(p, sizeof(authnz_crowd_dir_config)));
    if (dir_config == NULL) {
        exit(1);
    }
    dir_config->authoritative = true;
    dir_config->accept_sso = true;
    dir_config->create_sso = true;
    dir_config->set_http_only = false;
    dir_config->crowd_config = crowd_create_config(p);
    if (dir_config->crowd_config == NULL) {
        exit(1);
    }
    dir_config->crowd_config->crowd_cert_dir = NULL;
    dir_config->crowd_config->crowd_cert_path = NULL;
    dir_config->crowd_config->crowd_ssl_verify_peer = true;
    dir_config->basic_auth_xlates = log_palloc(p, apr_array_make(p, 0, sizeof(apr_xlate_t *)));
    if (dir_config->basic_auth_xlates == NULL) {
        exit(1);
    }

    // Add new config to list of this module's per-directory configs, for checking during the post-config phase.
    apr_array_header_t *dir_configs = NULL;
    apr_pool_userdata_get((void**)&dir_configs, dir_configs_key, p);
    if (dir_configs == NULL)  {
        dir_configs = log_palloc(p, apr_array_make(p, 0, sizeof(authnz_crowd_dir_config *)));
        if (dir_configs == NULL) {
            exit(1);
        }
        apr_pool_userdata_set(dir_configs, dir_configs_key, apr_pool_cleanup_null, p);
    }
    APR_ARRAY_PUSH(dir_configs, authnz_crowd_dir_config *) = dir_config;

    return dir_config;
}

static const char *set_once_error(const cmd_parms *parms)
{
    const char *error
        = log_palloc(parms->temp_pool, apr_psprintf(parms->temp_pool, "%s specified multiple times", parms->cmd->name));
    if (error == NULL) {
        error = "Out of memory";
    }
    return error;
}

static const char *set_once(const cmd_parms *parms, const char **location, const char *w)
{
    if (*location != NULL) {
        return set_once_error(parms);
    }
    *location = log_palloc(parms->temp_pool, apr_pstrdup(parms->pool, w));
    if (*location == NULL) {
        return "Out of memory";
    }
    return NULL;
}

static const char *set_flag_once(const cmd_parms *parms, bool *location, bool *set_location, int on) {
    if (*set_location) {
        return set_once_error(parms);
    }
    *location = on;
    *set_location = true;
    return NULL;
}

static const char *set_authz_crowd_authoritative(cmd_parms *parms, void *mconfig, int on)
{
    authnz_crowd_dir_config *config = (authnz_crowd_dir_config *) mconfig;
    return set_flag_once(parms, &(config->authoritative), &(config->authoritative_set), on);
}

static const char *set_crowd_app_name(cmd_parms *parms, void *mconfig, const char *w)
{
    authnz_crowd_dir_config *config = (authnz_crowd_dir_config *) mconfig;
    return set_once(parms, &(config->crowd_config->crowd_app_name), w);
}

static const char *set_crowd_app_password(cmd_parms *parms, void *mconfig, const char *w)
{
    authnz_crowd_dir_config *config = (authnz_crowd_dir_config *) mconfig;
    return set_once(parms, &(config->crowd_config->crowd_app_password), w);
}

static const char *add_basic_auth_conversion(const char *encoding, authnz_crowd_dir_config *config, apr_pool_t *pconf,
    apr_pool_t *ptemp)
{
    apr_xlate_t *conversion;
    if (apr_xlate_open(&conversion, "UTF-8", encoding, pconf) != APR_SUCCESS) {
        const char *error = log_palloc(ptemp, apr_psprintf(ptemp, "Encoding not supported: '%s'", encoding));
        if (error == NULL) {
            error = "Out of memory";
        }
        return error;
    }
    APR_ARRAY_PUSH(config->basic_auth_xlates, apr_xlate_t *) = conversion;
    return NULL;
}

static const char *set_crowd_basic_auth_encoding(cmd_parms *parms, void *mconfig, const char *w)
{
    authnz_crowd_dir_config *config = (authnz_crowd_dir_config *) mconfig;
    return add_basic_auth_conversion(w, config, parms->pool, parms->temp_pool);
}

static const char *set_crowd_timeout(cmd_parms *parms, void *mconfig, const char *w)
{
    authnz_crowd_dir_config *config = (authnz_crowd_dir_config *) mconfig;
    return set_once(parms, &(config->crowd_timeout_string), w);
}

static const char *set_crowd_cert_path(cmd_parms *parms, void *mconfig, const char *w)
{
    // Ignore empty filenames.  Will be reported as a missing parameter.
    if (*w == '\0') {
        return NULL;
    }

    authnz_crowd_dir_config *config = (authnz_crowd_dir_config *) mconfig;
    return set_once(parms, &(config->crowd_config->crowd_cert_path), w);
}

static const char *set_crowd_cert_dir(cmd_parms *parms, void *mconfig, const char *w)
{
    // Ignore empty filenames.  Will be reported as a missing parameter.
    if (*w == '\0') {
        return NULL;
    }

    authnz_crowd_dir_config *config = (authnz_crowd_dir_config *) mconfig;
    return set_once(parms, &(config->crowd_config->crowd_cert_dir), w);
}

static const char *set_crowd_url(cmd_parms *parms, void *mconfig, const char *w)
{
    // Ignore empty URLs.  Will be reported as a missing parameter.
    if (*w == '\0') {
        return NULL;
    }
    // Add a trailing slash if one does not already exist.
    if (w[strlen(w) - 1] != '/') {
        w = log_palloc(parms->temp_pool, apr_pstrcat(parms->temp_pool, w, "/", NULL));
        if (w == NULL) {
            return "Out of memory";
        }
    }

    authnz_crowd_dir_config *config = (authnz_crowd_dir_config *) mconfig;
    return set_once(parms, &(config->crowd_config->crowd_url), w);
}

static const char *set_crowd_cache_max_age(cmd_parms *parms, void *mconfig __attribute__((unused)),
    const char *w __attribute__((unused)))
{
    return set_once(parms, &(authnz_crowd_process_config.cache_max_age_string), w);
}

static const char *set_crowd_cache_max_entries(cmd_parms *parms, void *mconfig __attribute__((unused)), const char *w)
{
    return set_once(parms, &(authnz_crowd_process_config.cache_max_entries_string), w);
}

static const char *set_crowd_accept_sso(cmd_parms *parms, void *mconfig, int on)
{
    authnz_crowd_dir_config *config = (authnz_crowd_dir_config *) mconfig;
    return set_flag_once(parms, &(config->accept_sso), &(config->accept_sso_set), on);
}

static const char *set_crowd_create_sso(cmd_parms *parms, void *mconfig, int on)
{
    authnz_crowd_dir_config *config = (authnz_crowd_dir_config *) mconfig;
    return set_flag_once(parms, &(config->create_sso), &(config->create_sso_set), on);
}

static const char *set_crowd_set_http_only(cmd_parms *parms, void *mconfig, int on)
{
  authnz_crowd_dir_config *config = (authnz_crowd_dir_config *) mconfig;
  return set_flag_once(parms, &(config->set_http_only), &(config->set_http_only_set), on);
}

static const char *set_crowd_ssl_verify_peer(cmd_parms *parms, void *mconfig, int on)
{
    authnz_crowd_dir_config *config = (authnz_crowd_dir_config *) mconfig;
    return set_flag_once(parms, &(config->crowd_config->crowd_ssl_verify_peer), &(config->ssl_verify_peer_set), on);
}

static const char *set_crowd_groups_env_name(cmd_parms *parms, void *mconfig, const char *w)
{
    authnz_crowd_dir_config *config = (authnz_crowd_dir_config *) mconfig;
    return set_once(parms, &(config->crowd_config->groups_env_name), w);
}

static const command_rec commands[] =
{
    AP_INIT_FLAG("AuthzCrowdAuthoritative", set_authz_crowd_authoritative, NULL, OR_AUTHCFG,
        "'On' if Crowd should be considered authoritative for denying authorisation; "
        "'Off' if a lower-level provider can override authorisation denial by Crowd (default = On)"),
    AP_INIT_TAKE1("CrowdAppName", set_crowd_app_name, NULL, OR_AUTHCFG,
        "The name of this application, as configured in Crowd"),
    AP_INIT_TAKE1("CrowdAppPassword", set_crowd_app_password, NULL, OR_AUTHCFG,
        "The password of this application, as configured in Crowd"),
    AP_INIT_ITERATE("CrowdBasicAuthEncoding", set_crowd_basic_auth_encoding, NULL, OR_AUTHCFG,
        "The list of character encodings that will be used to interpret Basic authentication credentials "
        "(default is ISO-8859-1 only"),
    AP_INIT_TAKE1("CrowdTimeout", set_crowd_timeout, NULL, OR_AUTHCFG,
        "The maximum length of time, in seconds, to wait for a response from Crowd (default or 0 = no timeout)"),
    AP_INIT_TAKE1("CrowdURL", set_crowd_url, NULL, OR_AUTHCFG, "The base URL of the Crowd server"),
    AP_INIT_TAKE1("CrowdCertPath", set_crowd_cert_path, NULL, OR_AUTHCFG, "The path to the SSL certificate file to supply to curl for Crowd over SSL"),
    AP_INIT_TAKE1("CrowdCertDirectory", set_crowd_cert_dir, NULL, OR_AUTHCFG, "The path to the SSL certificate directory to supply to curl for Crowd over SSL (must be prep'd with OpenSSL's c_rehash utility)"),
    AP_INIT_TAKE1("CrowdCacheMaxAge", set_crowd_cache_max_age, NULL, RSRC_CONF,
        "The maximum length of time that successful results from Crowd can be cached, in seconds"
        " (default = 60 seconds)"),
    AP_INIT_TAKE1("CrowdCacheMaxEntries", set_crowd_cache_max_entries, NULL, RSRC_CONF,
        "The maximum number of successful results from Crowd that can be cached at any time"
        " (default = 500, 0 = disable cache)"),
    AP_INIT_FLAG("CrowdAcceptSSO", set_crowd_accept_sso, NULL, OR_AUTHCFG,
        "'On' if single-sign on cookies should be accepted; 'Off' otherwise (default = On)"),
    AP_INIT_FLAG("CrowdCreateSSO", set_crowd_create_sso, NULL, OR_AUTHCFG,
        "'On' if single-sign on cookies should be created; 'Off' otherwise (default = On)"),
    AP_INIT_FLAG("CrowdSetHttpOnly", set_crowd_set_http_only, NULL, OR_AUTHCFG,
        "'On' if single-sign on cookies should be created as HttpOnly; 'Off' otherwise (default = Off)"),
    AP_INIT_FLAG("CrowdSSLVerifyPeer", set_crowd_ssl_verify_peer, NULL, OR_AUTHCFG,
            "'On' if SSL certificate validation should occur when connecting to Crowd; 'Off' otherwise (default = On)"),
    AP_INIT_TAKE1("CrowdGroupsEnvName", set_crowd_groups_env_name, NULL, OR_AUTHCFG,
        "Name of the environment variable in which to store a space-delimited list of groups that the remote user belongs to"),
    {0}
};

static authnz_crowd_dir_config *get_config(request_rec *r) {
    authnz_crowd_dir_config *config
        = (authnz_crowd_dir_config *) ap_get_module_config(r->per_dir_config, &authnz_crowd_module);
    if (config == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "Configuration not found.");
    }
    return config;
}

typedef struct {
    request_rec *r;
    authnz_crowd_dir_config *config;
    char *cookie_name;
    size_t cookie_name_len;
    char *token;
} check_for_cookie_data_t;

/*
 * See top of file for declaration of crowd_is_https variable.
 * You must find https via this method because the mod_ssl
 * hook that sets the environment variable is not run until
 * after the check_user_id hooks.  The old method worked SOMETIMES
 * because Apache will re-use the same subprocess for pipelined
 * requests.
 */

static bool is_https(request_rec *r) {
  if(!crowd_is_https)
    crowd_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
  int https = 0;
  if(crowd_is_https && crowd_is_https(r->connection))
    https = 1;
  return (bool)https;
}

static int check_for_cookie(void *rec, const char *key, const char *value) {
    if (strcasecmp("Cookie", key) == 0) {
        check_for_cookie_data_t *data = rec;
        if (data->cookie_name == NULL) {
            crowd_cookie_config_t *cookie_config = crowd_get_cookie_config(data->r, data->config->crowd_config);
            if (cookie_config == NULL || cookie_config->cookie_name == NULL || (cookie_config->secure && !is_https(data->r))) {
                return 0;
            }
            data->cookie_name = log_ralloc(data->r, apr_pstrcat(data->r->pool, cookie_config->cookie_name, "=", NULL));
            if (data->cookie_name == NULL) {
                return 0;
            }
            data->cookie_name_len = strlen(data->cookie_name);
        }
        char *cookies = log_ralloc(data->r, apr_pstrdup(data->r->pool, value));
        if (cookies == NULL) {
            return 0;
        }
        apr_collapse_spaces(cookies, cookies);
        char *last;
        char *cookie = apr_strtok(cookies, ";,", &last);
        while (cookie != NULL) {
            if (strncasecmp(cookie, data->cookie_name, data->cookie_name_len) == 0) {
                data->token = log_ralloc(data->r, apr_pstrdup(data->r->pool, cookie + data->cookie_name_len));
                return 0;
            }
            cookie = apr_strtok(NULL, ";,", &last);
        }
    }
    return 1;
}

#define GRP_ENV_MAX_GROUPS 128
#define GRP_ENV_DELIMITER " "
#define GRP_ENV_DELIMITER_LEN (sizeof(GRP_ENV_DELIMITER) - sizeof(char))
static void crowd_set_groups_env_variable(request_rec *r) {
    authnz_crowd_dir_config *config = get_config(r);
    const char *group_env_name = config->crowd_config->groups_env_name;
    if (group_env_name == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "CrowdGroupsEnvName undefined; returning.");
        return;
    }

    apr_array_header_t *user_groups = authnz_crowd_user_groups(r->user, r);
    if (user_groups == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "While setting groups environment variable '%s' for remote user '%s': authnz_crowd_user_groups() returned NULL.", group_env_name, r->user);
        return;
    }

    apr_size_t ngrps = user_groups->nelts;
    if (ngrps <= 0) {
        apr_table_set(r->subprocess_env, group_env_name, "");
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Set groups environment variable '%s' for remote user '%s' to empty.", group_env_name, r->user);
        return;
    }

    if (ngrps > GRP_ENV_MAX_GROUPS) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "While setting groups environment variable '%s' for remote user '%s': Value will be clipped as number of groups (%d) exceeds GRP_ENV_MAX_GROUPS (%d).", group_env_name, r->user, ngrps, GRP_ENV_MAX_GROUPS);
        ngrps = GRP_ENV_MAX_GROUPS;
    }

    apr_size_t nvec = ngrps + (ngrps - 1); /* Groups + conjunctive delimiters */
    struct iovec *iov = apr_pcalloc(r->pool, sizeof(struct iovec) * nvec);
    int i, k;
    for (i = 0, k = 0; i < ngrps; i++) {
        if (i >= 1) {
            /* Join previous entry with a delimiter */
            iov[k].iov_base = GRP_ENV_DELIMITER;
            iov[k].iov_len = GRP_ENV_DELIMITER_LEN;
            k++;
        }

        void *grp = APR_ARRAY_IDX(user_groups, i, void *);
        iov[k].iov_base = grp;
        iov[k].iov_len = strlen(grp);
        k++;
    }

    const char *groups = apr_pstrcatv(r->pool, iov, nvec, NULL);
    if (groups == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "While setting groups environment variable '%s' for remote user '%s': apr_pstrcatv() returned NULL.", group_env_name, r->user);
        return;
    }

    apr_table_set(r->subprocess_env, group_env_name, groups);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Set groups environment variable '%s' for remote user '%s' to '%s'", group_env_name, r->user, groups);
}

static int check_user_id(request_rec *r) {
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "check_user_id");
    authnz_crowd_dir_config *config = get_config(r);
    if (config == NULL || !(config->accept_sso)) {
        return DECLINED;
    }
    check_for_cookie_data_t data = { .r = r, .config = config };
    apr_table_do(check_for_cookie, &data, r->headers_in, NULL);
    if (data.token == NULL) {
        return DECLINED;
    }
    if (crowd_validate_session(r, config->crowd_config, data.token, &r->user) == CROWD_AUTHENTICATE_SUCCESS) {
        r->ap_auth_type = "Crowd SSO";
        crowd_set_groups_env_variable(r);
        return OK;
    }
    return DECLINED;
}

#define XLATE_BUFFER_SIZE 256

static bool xlate_string(apr_xlate_t *xlate, const char *input, char *output) {
    apr_size_t input_left = strlen(input);
    apr_size_t output_left = XLATE_BUFFER_SIZE;
    if (apr_xlate_conv_buffer(xlate, input, &input_left, output, &output_left) != APR_SUCCESS
        || input_left != 0
        || apr_xlate_conv_buffer(xlate, NULL, NULL, output, &output_left) != APR_SUCCESS
        || output_left < 1) {
        return false;
    }
    return true;
}

/* Given a username and password, expected to return AUTH_GRANTED if we can validate this user/password combination. */
static authn_status authn_crowd_check_password(request_rec *r, const char *user, const char *password)
{
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "authn_crowd_check_password");
    authnz_crowd_dir_config *config = get_config(r);
    if (config == NULL) {
        return AUTH_GENERAL_ERROR;
    }

    apr_array_header_t *basic_auth_xlates = config->basic_auth_xlates;
    int i;
    for (i = 0; i < basic_auth_xlates->nelts; i++) {
        apr_xlate_t *xlate = APR_ARRAY_IDX(basic_auth_xlates, i, apr_xlate_t *);
        char xlated_user[XLATE_BUFFER_SIZE] = {};
        char xlated_password[XLATE_BUFFER_SIZE] = {};
        if (!xlate_string(xlate, user, xlated_user) || !xlate_string(xlate, password, xlated_password)) {
            ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "Failed to translate basic authentication credentials");
        } else {
            crowd_authenticate_result result = CROWD_AUTHENTICATE_NOT_ATTEMPTED;
            if (config->create_sso) {
                crowd_cookie_config_t *cookie_config = crowd_get_cookie_config(r, config->crowd_config);
                if (cookie_config != NULL && (!cookie_config->secure || is_https(r))) {
                    const char *token;
                    result = crowd_create_session(r, config->crowd_config, xlated_user, xlated_password, &token);
                    if (result == CROWD_AUTHENTICATE_SUCCESS && token != NULL) {
                        char *domain = "";
                        if (cookie_config->domain != NULL && cookie_config->domain[0] == '.') {
                            size_t domainlen = strlen(cookie_config->domain);
                            size_t hostlen = strlen(r->hostname);
                            if (hostlen > domainlen
                                && strcmp(cookie_config->domain, r->hostname + hostlen - domainlen) == 0) {
                                domain = apr_psprintf(r->pool, ";Domain=%s", cookie_config->domain);
                            }
                        }
                        char *cookie = log_ralloc(r,
                            apr_psprintf(r->pool, "%s=%s%s%s%s;Version=1;Path=/", cookie_config->cookie_name, token,
                            domain, cookie_config->secure ? ";Secure" : "", config->set_http_only ? ";HttpOnly" : ""));
                        if (cookie != NULL) {
                            apr_table_add(r->err_headers_out, "Set-Cookie", cookie);
                        }
                    }
                }
            }
            if (result == CROWD_AUTHENTICATE_NOT_ATTEMPTED) {
                result = crowd_authenticate(r, config->crowd_config, xlated_user, xlated_password);
            }
            switch (result) {
                case CROWD_AUTHENTICATE_SUCCESS:
                    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Authenticated '%s'.", xlated_user);
                    crowd_set_groups_env_variable(r);
                    return AUTH_GRANTED;
                case CROWD_AUTHENTICATE_FAILURE:
                    break;
                default:
                    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "Crowd authentication failed due to system exception");
                    return AUTH_GENERAL_ERROR;
            }
        }
    }

    return AUTH_DENIED;
}

static const authn_provider authn_crowd_provider =
{
    &authn_crowd_check_password,    /* Callback for HTTP Basic authentication */
};

static unsigned int parse_number(const char *string, const char *name, unsigned int min, unsigned int max,
    unsigned int default_value, server_rec *s) {
    if (string == NULL) {
        return default_value;
    }
    apr_int64_t value = apr_atoi64(string);
    if (errno != 0 || value < 0 || (apr_uint64_t)value > max || (apr_uint64_t)value < min) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, errno, s, "Could not parse %s: '%s'", name, string);
        exit(1);
    }
    return (unsigned int)value;
}

/* Called after configuration is set, to finalise it. */
static int post_config(apr_pool_t *pconf, apr_pool_t *plog __attribute__((unused)), apr_pool_t *ptemp, server_rec *s)
{

    /* Create the caches, if required. */
    unsigned cache_max_entries
        = parse_number(authnz_crowd_process_config.cache_max_entries_string, "CrowdCacheMaxEntries", 0, UINT_MAX, 500,
        s);
    if (cache_max_entries > 0) {
        apr_time_t cache_max_age
            = apr_time_from_sec(parse_number(authnz_crowd_process_config.cache_max_age_string, "CrowdCacheMaxAge", 1,
            UINT_MAX, 60, s));
        if (!crowd_cache_create(pconf, cache_max_age, cache_max_entries)) {
            exit(1);
        }
    }

    apr_array_header_t *dir_configs = NULL;
    apr_pool_userdata_get((void**)&dir_configs, dir_configs_key, pconf);
    if (dir_configs != NULL) {

        /* Iterate over each directory config */
        authnz_crowd_dir_config **dir_config;
        while ((dir_config = apr_array_pop(dir_configs)) != NULL) {

            /* If any of the configuration parameters are specified, ensure that all mandatory parameters are
               specified. */
            crowd_config *crowd_config = (*dir_config)->crowd_config;
            if ((crowd_config->crowd_app_name != NULL || crowd_config->crowd_app_password != NULL
                || crowd_config->crowd_url != NULL)
                && (crowd_config->crowd_app_name == NULL || crowd_config->crowd_app_password == NULL
                || crowd_config->crowd_url == NULL)) {
                ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                    "Missing CrowdAppName, CrowdAppPassword or CrowdURL for a directory.");
                exit(1);
            }

            /* Parse the timeout parameter, if specified */
            crowd_config->crowd_timeout
                = parse_number((*dir_config)->crowd_timeout_string, "CrowdTimeout", 0, UINT_MAX, 0, s);

            /* If no basic auth character encodings are specified, setup ISO-8859-1. */
            if (apr_is_empty_array((*dir_config)->basic_auth_xlates)) {
                const char *error = add_basic_auth_conversion("ISO-8859-1", *dir_config, pconf, ptemp);
                if (error != NULL) {
                    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                        "Could not configure default Basic Authentication translation.  %s", error);
                    exit(1);
                }
            }

        }
    }
    return OK;
}

apr_array_header_t *authnz_crowd_user_groups(const char *username, request_rec *r) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "authnz_crowd_user_groups");
    authnz_crowd_dir_config *config = get_config(r);
    if (config == NULL) {
        return NULL;
    }
    return crowd_user_groups(username, r, config->crowd_config);
}

/**
 * This hook is used to check to see if the resource being requested
 * is available for the authenticated user (r->user and r->ap_auth_type).
 * It runs after the access_checker and check_user_id hooks. Note that
 * it will *only* be called if Apache determines that access control has
 * been applied to this resource (through a 'Require' directive).
 *
 * @param r the current request
 * @return OK, DECLINED, or HTTP_...
 */
#if AP_MODULE_MAGIC_AT_LEAST(20080403,1)
static authz_status auth_group_checker(request_rec *r,
                 const char *require_line,
                 const void *parsed_require_args) {
    const char *t, *w;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_authnz_crowd:auth_group_checker");

    authnz_crowd_dir_config *config = get_config(r);
    if (config == NULL) {
        return AUTHZ_GENERAL_ERROR;
    }

    if (r->user == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "Authorisation requested, but no user provided.");
        return AUTHZ_DENIED_NO_USER;
    }

    apr_array_header_t *user_groups = NULL;

    /* Fetch groups only if actually needed. */
    if (user_groups == NULL) {
        user_groups = crowd_user_groups(r->user, r, config->crowd_config);
        if (user_groups == NULL) {
            return AUTHZ_GENERAL_ERROR;
        }
    }

    /* Iterate over the groups mentioned in the requirement. */
    t = require_line;
    while ((w = ap_getword_conf(r->pool, &t)) && w[0]) {
        int y;
        for (y = 0; y < user_groups->nelts; y++) {
            const char *user_group = APR_ARRAY_IDX(user_groups, y, const char *);
            ap_log_rerror(
                APLOG_MARK, APLOG_DEBUG, 0, r,
                "auth_group_checker: user_group=%s, required_group=%s",
                user_group, w
            );
            if (strcasecmp(user_group, w) == 0) {
                ap_log_rerror(
                    APLOG_MARK, APLOG_INFO, 0, r,
                    "Granted authorisation to '%s' on the basis of membership of '%s'.",
                    r->user, user_group
                );
                return AUTHZ_GRANTED;
            }
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Denied authorisation to '%s'.", r->user);
    return AUTHZ_DENIED;
}

static const authz_provider authz_crowd_group_provider =
{
    &auth_group_checker,
    NULL,
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_user_id(check_user_id, NULL, NULL, APR_HOOK_FIRST);
    ap_register_auth_provider(
        p,
        AUTHN_PROVIDER_GROUP,
        "crowd",
        AUTHN_PROVIDER_VERSION,
        &authn_crowd_provider, AP_AUTH_INTERNAL_PER_CONF
    );

    // Require crowd-group group1 group2 ...
    ap_register_auth_provider(
        p,
        AUTHZ_PROVIDER_GROUP,
        "crowd-group",
        AUTHZ_PROVIDER_VERSION,
        &authz_crowd_group_provider, AP_AUTH_INTERNAL_PER_CONF
    );
}
#else
static int auth_checker(request_rec *r) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "mod_authnz_crowd:auth_checker");

    authnz_crowd_dir_config *config = get_config(r);
    if (config == NULL) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r->user == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "Authorisation requested, but no user provided.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Iterate over requirements */
    const apr_array_header_t *requires = ap_requires(r);
    apr_array_header_t *user_groups = NULL;
    int x;
    for (x = 0; x < requires->nelts; x++) {

        require_line require = APR_ARRAY_IDX(requires, x, require_line);

        /* Ignore this requirement if it does not apply to the HTTP method used in the request. */
        if (!(require.method_mask & (AP_METHOD_BIT << r->method_number))) {
            continue;
        }

        const char *next_word = require.requirement;

        /* Only process group requirements */
        if (strcasecmp(ap_getword_white(r->pool, &next_word), "group") == 0) {

            /* Fetch groups only if actually needed. */
            if (user_groups == NULL) {
                user_groups = crowd_user_groups(r->user, r, config->crowd_config);
                if (user_groups == NULL) {
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
            }

            /* Iterate over the groups mentioned in the requirement. */
            while (*next_word != '\0') {
                const char *required_group = ap_getword_conf(r->pool, &next_word);
                /* Iterate over the user's groups. */
                int y;
                for (y = 0; y < user_groups->nelts; y++) {
                    const char *user_group = APR_ARRAY_IDX(user_groups, y, const char *);
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                        "auth_checker: user_group=%s, required_group=%s", user_group, required_group);
                    if (strcasecmp(user_group, required_group) == 0) {
                        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                            "Granted authorisation to '%s' on the basis of membership of '%s'.", r->user, user_group);
                        return OK;
                    }
                }

            }
        }

    }

    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Denied authorisation to '%s'.", r->user);
    return config->authoritative ? HTTP_UNAUTHORIZED : DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
    static const char * const pre_auth_checker[]={ "mod_authz_user.c", NULL };
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_user_id(check_user_id, NULL, NULL, APR_HOOK_FIRST);
    ap_register_provider(
        p,
        AUTHN_PROVIDER_GROUP,
        "crowd",
        "0",                    /* Version of callback interface, not the version of the implementation. */
        &authn_crowd_provider
    );
    ap_hook_auth_checker(auth_checker, pre_auth_checker, NULL, APR_HOOK_MIDDLE);
}
#endif

module AP_MODULE_DECLARE_DATA authnz_crowd_module =
{
    STANDARD20_MODULE_STUFF,
    create_dir_config,
    NULL,
    NULL,
    NULL,
    commands,
    register_hooks
};

/* Library initialisation and termination functions */
/* TODO: Another solution will likely be required for non-GCC platforms, e.g. Windows */

void init() __attribute__ ((constructor));

void init()
{
    crowd_init();
}

void term() __attribute__ ((destructor));

void term()
{
    crowd_cleanup();
}
