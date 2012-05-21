/**
 * crowd_client.h
 *
 * Header file for the Atlassian Crowd C Client
 */

#include "cache.h" 

/**
 * Configuration data structure for the Crowd Client
 */
typedef struct {
    const char *crowd_app_name;         /* Application name used to authenticate with Crowd */
    const char *crowd_app_password;     /* Application password used to authenticate with Crowd */
    const char *crowd_url;              /* Base URL of the Crowd server */
    long crowd_timeout;                 /* Crowd response timeout, in seconds, or 0 for no timeout */
    const char *groups_env_name;        /* Name of the environment variable in which to store a space-delimited list of groups that the remote user belongs to */
} crowd_config;

/**
 * Must be called before the first use of the Crowd Client.
 */
void crowd_init();

bool crowd_cache_create(apr_pool_t *pool, apr_time_t max_age, unsigned int max_entries);

/**
 * Should be called after the final use of the Crowd Client.
 */
void crowd_cleanup();

/**
 * Creates a crowd_config, populated with default values.
 *
 * @param p     The APR pool from which to allocate memory.
 * @returns     A pointer to the crowd_config, or NULL upon failure.
 */
crowd_config *crowd_create_config(apr_pool_t *p);

typedef enum {
    CROWD_AUTHENTICATE_NOT_ATTEMPTED,   /* Authentication has not yet been attempted. */
    CROWD_AUTHENTICATE_SUCCESS,         /* Authentication succeeded. */
    CROWD_AUTHENTICATE_FAILURE,         /* The given credentials could not be authenticated. */
    CROWD_AUTHENTICATE_EXCEPTION        /* A system failure prevented authentication from being attempted. */
} crowd_authenticate_result;

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
    const char *password);

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
    const char *password, const char **token);

/**
 * Validate an existing SSO session.
 *
 * @param r         The current Apache httpd request.
 * @param config    The configuration details of the Crowd Client.
 * @param token     The session token.
 * @param user     Pointer to variable to receive the user name upon successful validation.
 * @returns a crowd_authenticate_result.
 */
crowd_authenticate_result crowd_validate_session(const request_rec *r, const crowd_config *config, char *token,
    char **user);

/**
 * Obtain the list of Crowd groups to which the current user belongs.
 *
 * Nested groups are included in the result.
 *
 * @param username  The name of the user.
 * @param r         The current Apache httpd request.
 * @param config    The configuration details of the Crowd Client.
 * @returns An APR array of (char *) group names, or NULL upon failure.
 */
apr_array_header_t *crowd_user_groups(const char *username, const request_rec *r, const crowd_config *config);

typedef struct {
    char *domain;
    bool secure;
    char *cookie_name;
} crowd_cookie_config_t;

crowd_cookie_config_t *crowd_get_cookie_config(const request_rec *r, const crowd_config *config);

