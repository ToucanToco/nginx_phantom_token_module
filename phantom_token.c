/*
 *  Copyright 2017 Curity AB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>
#include <stdbool.h>
#include <assert.h>

#define UNENCODED_CLIENT_CREDENTIALS_BUF_LEN 1024

typedef struct
{
    ngx_str_t base64encoded_client_credential;
    ngx_str_t introspection_endpoint;
    ngx_str_t realm;
    ngx_array_t *scopes;
    ngx_str_t space_separated_scopes;
    ngx_flag_t enable;
} phantom_token_configuration_t;

typedef struct
{
    ngx_uint_t done;
    ngx_uint_t status;
    ngx_str_t jwt;
    ngx_str_t original_accept_header;
    ngx_str_t original_content_type_header;
    ngx_str_t original_sec_websocket_key;
    ngx_str_t original_sec_websocket_version;
} phantom_token_module_context_t;

static ngx_int_t post_configuration(ngx_conf_t *config);

static ngx_int_t handler(ngx_http_request_t *request);

static void *create_location_configuration(ngx_conf_t *config);

static char *merge_location_configuration(ngx_conf_t *main_config, void *parent, void *child);

static ngx_int_t introspection_response_handler(ngx_http_request_t *request, void *data,
                                                ngx_int_t introspection_subrequest_status_code);

static ngx_int_t write_error_response(ngx_http_request_t *request, ngx_int_t status, phantom_token_configuration_t *module_location_config);

/**
 * Adds a WWW-Authenticate header to the given request's output headers that conforms to <a href="https://tools.ietf.org/html/rfc6750">RFC 6750</>.
 *
 * After calling this method, a WWW-Authenticate header will be added that uses the Bearer scheme. If the realm and or
 * scopes were also configured, then these too will be included. For instance, if scopes are configured, then the
 * following output header will be added: <code> WWW-Authenticate: Bearer scope="scope1 scope2 scope3"</code>. If only
 * realm is configured, then a response header like this one would be added:
 * <code>WWW-Authenticate: Bearer realm="myGoodRealm"</code>. If both are configured, the two will be included and
 * separated by a comma, like this: <code>WWW-Authenticate: Bearer realm="myGoodRealm", scope="scope1 scope2 scope3"</code>.
 *
 * @param request the current request
 * @param realm the configured realm
 * @param space_separated_scopes the space-separated list of configured scopes
 * @param error an error code or NULL if none. Refer to
 * <a href="https://tools.ietf.org/html/rfc6750#section-3.1">RFC 6750 § 3.1</a> for standard values.
 *
 * @return <code>NGX_HTTP_UNAUTHORIZED</code>
 *
 * @example <code>WWW-Authenticate: Bearer realm="myGoodRealm", scope="scope1 scope2 scope3"</code>
 *
 * @see <a href="https://tools.ietf.org/html/rfc6750">RFC 6750</a>
 */
static ngx_int_t set_www_authenticate_header(ngx_http_request_t *request, phantom_token_configuration_t *module_location_config, char *error_code);

/**
 * Sets the base-64-encoded client ID and secret in the module's configuration setting structure.
 *
 * This method assumes the module's command where this setter function (<code>set</code>) is used has a
 * configuration (<code>conf</code>) of <code>NGX_HTTP_LOC_CONF_OFFSET<code> and an <code>offset</code> of
 * <code>base64encoded_client_credential</code>. If this is not the case, the result pointer <em>may</em> point to an
 * unexpected location and the handler may not be able to use the configured values. Also, the command should have a
 * type that includes <code>NGX_CONF_TAKE2</code>.
 *
 * @param config_setting the configuration setting that is being set
 * @param command the module's command where this slot setter function is being used
 * @param result a pointer to the location where the result will be stored; it should be a pointer to a
 * <code>ngx_str_t</code>.
 *
 * @return <code>NGX_CONF_OK</code> upon success; some other character string on failure.
 */
static char* set_client_credential_configuration_slot(ngx_conf_t *config_setting, ngx_command_t *command, void *result);

/**
 * Sets the base-64-encoded client ID and secret in the module's configuration
 * setting structure from a file.
 *
 * This method assumes the module's command where this setter function
 * (<code>set</code>) is used has a configuration (<code>conf</code>) of
 * <code>NGX_HTTP_LOC_CONF_OFFSET<code> and an <code>offset</code> of
 * <code>base64encoded_client_credential</code>. If this is not the case, the
 * result pointer <em>may</em> point to an unexpected location and the handler
 * may not be able to use the configured values. Also, the command should have a
 * type that includes <code>NGX_CONF_TAKE2</code>.
 *
 * @param config_setting the configuration setting that is being set
 * @param command the module's command where this slot setter function is being
 * used
 * @param result a pointer to the location where the result will be stored; it
 * should be a pointer to a <code>ngx_str_t</code>.
 *
 * @return <code>NGX_CONF_OK</code> upon success; some other character string on
 * failure.
 */
static char *set_client_credential_file_configuration_slot(
    ngx_conf_t *config_setting, ngx_command_t *command, void *result);

static ngx_str_t BEARER = ngx_string("Bearer ");
static ngx_str_t BEARER_UNDERSCORE = ngx_string("Bearer_");

static ngx_command_t phantom_token_module_directives[] = {
    {
        ngx_string("phantom_token"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
            NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(phantom_token_configuration_t, enable),
        NULL,
    },
    {
        ngx_string("phantom_token_client_credential"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
        set_client_credential_configuration_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(phantom_token_configuration_t,
                 base64encoded_client_credential),
        NULL,
    },
    {
        ngx_string("phantom_token_client_credential_file"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
        set_client_credential_file_configuration_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(phantom_token_configuration_t,
                 base64encoded_client_credential),
        NULL,
    },
    {
        ngx_string("phantom_token_introspection_endpoint"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(phantom_token_configuration_t, introspection_endpoint),
        NULL,
    },
    {
        ngx_string("phantom_token_realm"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(phantom_token_configuration_t, realm),
        NULL,
    },
    {
        ngx_string("phantom_token_scopes"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(phantom_token_configuration_t, space_separated_scopes),
        NULL,
    },
    {
        ngx_string("phantom_token_scope"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_array_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(phantom_token_configuration_t, scopes),
        NULL,
    },
    ngx_null_command /* command termination */
};

/* The module context. */
static ngx_http_module_t phantom_token_module_context =
{
    NULL, /* pre-configuration */
    post_configuration,

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    create_location_configuration,
    merge_location_configuration
};

/* Module definition. */
ngx_module_t ngx_curity_http_phantom_token_module =
{
    NGX_MODULE_V1,
    &phantom_token_module_context,
    phantom_token_module_directives,
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_table_elt_t *find_header_in(ngx_http_request_t *r, ngx_str_t key) {
    ngx_list_part_t *part;
    ngx_table_elt_t *h;
    ngx_uint_t i;

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0;; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            // Walk next part
            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len != key.len ||
            ngx_strncasecmp(h[i].key.data, key.data, key.len) != 0) {
            continue; // Continue if not matched
        }

        // Found
        return &h[i];
    }
    return NULL;
}

/**
 * Remove an element from the list and the part that contains it.
 *
 * Ref:
 * https://github.com/openresty/headers-more-nginx-module/blob/84a65d68687c9de5166fd49ddbbd68c6962234eb/src/ngx_http_headers_more_util.c#L265-L382
 */
ngx_int_t ngx_http_headers_more_rm_header_helper(ngx_list_t *l,
                                                 ngx_list_part_t *cur,
                                                 ngx_uint_t i) {
    ngx_table_elt_t *data;
    ngx_list_part_t *new, *part;

    data = cur->elts;

    if (i == 0) {
        cur->elts = (char *)cur->elts + l->size;
        cur->nelts--;

        if (cur == l->last) {
            if (cur->nelts == 0) {
#if 1
                part = &l->part;

                if (part == cur) {
                    cur->elts = (char *)cur->elts - l->size;
                    /* do nothing */

                } else {
                    while (part->next != cur) {
                        if (part->next == NULL) {
                            return NGX_ERROR;
                        }

                        part = part->next;
                    }

                    l->last = part;
                    part->next = NULL;
                    l->nalloc = part->nelts;
                }
#endif

            } else {
                l->nalloc--;
            }

            return NGX_OK;
        }

        if (cur->nelts == 0) {
            part = &l->part;

            if (part == cur) {
                assert(cur->next != NULL);

                if (l->last == cur->next) {
                    l->part = *(cur->next);
                    l->last = part;
                    l->nalloc = part->nelts;

                } else {
                    l->part = *(cur->next);
                }

            } else {
                while (part->next != cur) {
                    if (part->next == NULL) {
                        return NGX_ERROR;
                    }

                    part = part->next;
                }

                part->next = cur->next;
            }

            return NGX_OK;
        }

        return NGX_OK;
    }

    if (i == cur->nelts - 1) {
        cur->nelts--;

        if (cur == l->last) {
            l->nalloc = cur->nelts;
        }

        return NGX_OK;
    }

    new = ngx_palloc(l->pool, sizeof(ngx_list_part_t));
    if (new == NULL) {
        return NGX_ERROR;
    }

    new->elts = &data[i + 1];
    new->nelts = cur->nelts - i - 1;
    new->next = cur->next;

    cur->nelts = i;
    cur->next = new;
    if (cur == l->last) {
        l->last = new;
        l->nalloc = new->nelts;
    }

    return NGX_OK;
}

/**
 * Set the header with the given key from the list.
 *
 * Ref:
 * https://github.com/nginx/nginx/blob/d31305653701bd99e8e5e6aa48094599a08f9f12/src/core/ngx_list.h#L55-L78
 * https://github.com/openresty/headers-more-nginx-module/blob/84a65d68687c9de5166fd49ddbbd68c6962234eb/src/ngx_http_headers_more_headers_in.c#L220-L221
 */
static ngx_int_t set_header_helper(ngx_http_request_t *r, ngx_str_t key,
                                   ngx_str_t value,
                                   ngx_table_elt_t **output_header) {
    ngx_list_part_t *part;
    ngx_table_elt_t *h, *matched;
    ngx_uint_t rc;
    ngx_uint_t i;

    matched = NULL;

retry:

    part = &r->headers_in.headers.part;
    h = part->elts;

    // Replace logic
    for (i = 0;; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            // Walk next part
            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len == key.len &&
            ngx_strncasecmp(h[i].key.data, key.data, key.len) == 0) {
            goto matched;
        }

        /* not matched */

        continue;

    matched:

        // If value is 0, remove the header. If there are duplicates, remove
        // them all.
        if (value.len == 0 || (matched && matched != &h[i])) {
            rc = ngx_http_headers_more_rm_header_helper(&r->headers_in.headers,
                                                        part, i);

            assert(
                !(r->headers_in.headers.part.next == NULL &&
                  r->headers_in.headers.last != &r->headers_in.headers.part));

            if (rc == NGX_OK) {
                if (output_header) { // If output_header is set to old header,
                                     // this clears it.
                    *output_header = NULL;
                }
                goto retry; // Make sure to clean all occurrences.
            }

            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "Replacing header with the same key %V", &key);
        h[i].value = value;
        if (output_header) {
            *output_header = &h[i];
        }
        if (matched == NULL) {
            matched = &h[i];
        }
    }

    if (matched) {
        return NGX_OK;
    }

    if (value.len == 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "Removed header %V", &key);
        return NGX_OK;
    }

    if (r->headers_in.headers.last == NULL) {
        /* must be 400 bad request */
        return NGX_OK;
    }

    // Add logic (field was not found)
    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    h->hash = 1;
    h->key = key;
    h->value = value;
#if defined(nginx_version) && nginx_version >= 1023000
    h->next = NULL;
#endif
    h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
    if (h->lowcase_key == NULL) {
        return NGX_ERROR;
    }
    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

    if (output_header) {
        *output_header = h;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "Added header "
                   "with key %V",
                   &key);

    return NGX_OK;
}

static void clear_header_helper(ngx_http_request_t *r, ngx_str_t key) {
    ngx_str_t value = ngx_null_string;
    set_header_helper(r, key, value, NULL);
}

/**
 * Sets the request's Accept header to the given value.
 *
 * @param request the request to which the header value will be set
 * @param value the value to set
 * @return NGX_OK if no error has occurred; NGX_ERROR if an error occurs.
 */
static ngx_int_t set_accept_header_value(ngx_http_request_t *request,
                                         ngx_str_t value) {
    static ngx_str_t accept = ngx_string("Accept");
    ngx_uint_t found =
        set_header_helper(request, accept, value, &request->headers_in.accept);
    if (found != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Failed to set header accept: %V", &value);
        return NGX_ERROR;
    }

    // If last == part, we need to update the number of elements
    if (request->headers_in.headers.part.next == NULL) {
        request->headers_in.headers.part.nelts =
            request->headers_in.headers.last->nelts;
    }

    return NGX_OK;
}

static ngx_int_t handler(ngx_http_request_t *request)
{
    phantom_token_configuration_t *module_location_config = ngx_http_get_module_loc_conf(
            request, ngx_curity_http_phantom_token_module);

    // Return OK if the module is not active
    if (!module_location_config->enable)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->connection->log, 0, "Module disabled");

        return NGX_DECLINED;
    }

    // OPTIONS requests from SPAs can never contain an authorization header so return a standard 204
    if (request->method == NGX_HTTP_OPTIONS)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->connection->log, 0, "Not processing OPTIONS request");
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->connection->log, 0, "Handling request to convert token to JWT");

    if (module_location_config->base64encoded_client_credential.len == 0)
    {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
                      "Module not configured properly: missing client ID and secret");

        return NGX_DECLINED;
    }

    ngx_str_t encoded_client_credentials = module_location_config->base64encoded_client_credential;

    if (module_location_config->introspection_endpoint.len == 0)
    {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
                      "Module not configured properly: missing introspection endpoint");

        return NGX_DECLINED;
    }

    phantom_token_module_context_t *module_context = ngx_http_get_module_ctx(request, ngx_curity_http_phantom_token_module);

    // On callback.
    if (module_context != NULL)
    {
        if (module_context->done)
        {
            // return appropriate status
            if (module_context->status == NGX_HTTP_OK)
            {
                // Introspection was successful. Replace the incoming Authorization header with one that has the JWT.
                static ngx_str_t authorization = ngx_string("Authorization");
                set_header_helper(request, authorization, module_context->jwt,
                                  &request->headers_in.authorization);

                ngx_log_error(NGX_LOG_NOTICE, request->connection->log, 0,
                              "Introspection request from %V succeeded",
                              &request->uri);

                if (module_context->original_content_type_header.data == NULL)
                {
                    static ngx_str_t ct = ngx_string("Content-Type");
                    clear_header_helper(request, ct);

                    // If last == part, we need to update the number of elements
                    if (request->headers_in.headers.part.next == NULL) {
                        request->headers_in.headers.part.nelts =
                            request->headers_in.headers.last->nelts;
                    }
                }
                else
                {
                    request->headers_in.content_type->value = module_context->original_content_type_header;
                }

                if (request->headers_in.accept == NULL)
                {
                    ngx_int_t result;
                    static ngx_str_t accept_value = ngx_string("*/*");

                    if ((result = set_accept_header_value(
                                      request, accept_value) != NGX_OK)) {
                        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                                      "Failed to set Accept header value");
                        return result;
                    }
                }
                else
                {
                    request->headers_in.accept->value = module_context->original_accept_header;
                }

                if (module_context->original_sec_websocket_key.len > 0) {
                    ngx_int_t result;
                    static ngx_str_t sec_websocket_key =
                        ngx_string("Sec-WebSocket-Key");
                    if ((result = set_header_helper(
                             request, sec_websocket_key,
                             module_context->original_sec_websocket_key,
                             NULL)) != NGX_OK) {
                        ngx_log_error(
                            NGX_LOG_ERR, request->connection->log, 0,
                            "Failed to set header Sec-WebSocket-Key: %V",
                            &module_context->original_sec_websocket_key);
                        return result;
                    }
                }

                if (module_context->original_sec_websocket_version.len > 0) {
                    ngx_int_t result;
                    static ngx_str_t sec_websocket_version =
                        ngx_string("Sec-WebSocket-Version");
                    if ((result = set_header_helper(
                             request, sec_websocket_version,
                             module_context->original_sec_websocket_version,
                             NULL)) != NGX_OK) {
                        ngx_log_error(
                            NGX_LOG_ERR, request->connection->log, 0,
                            "Failed to set header Sec-WebSocket-Version: %V",
                            &module_context->original_sec_websocket_version);
                        return result;
                    }
                }

                return NGX_OK;
            }
            else if (module_context->status == NGX_HTTP_NO_CONTENT)
            {
                ngx_log_error(
                    NGX_LOG_ERR, request->connection->log, 0,
                    "Introspection request from %V failed with no content: %d",
                    &request->connection->addr_text, module_context->status);
                return set_www_authenticate_header(request, module_location_config, NULL);
            }
            else if (module_context->status == NGX_HTTP_SERVICE_UNAVAILABLE)
            {
                ngx_log_error(
                    NGX_LOG_ERR, request->connection->log, 0,
                    "Introspection request failed with service unavailable: %d",
                    module_context->status);
                return write_error_response(request, NGX_HTTP_SERVICE_UNAVAILABLE, module_location_config);
            }
            else if (module_context->status >= NGX_HTTP_INTERNAL_SERVER_ERROR || module_context->status == NGX_HTTP_NOT_FOUND
                || module_context->status == NGX_HTTP_UNAUTHORIZED || module_context->status == NGX_HTTP_FORBIDDEN)
            {
                ngx_log_error(
                    NGX_LOG_ERR, request->connection->log, 0,
                    "Introspection request from %V failed with status code "
                    "(server responded): %d",
                    &request->connection->addr_text, module_context->status);
                return write_error_response(request, NGX_HTTP_BAD_GATEWAY, module_location_config);
            }

            ngx_log_error(
                NGX_LOG_ERR, request->connection->log, 0,
                "Introspection request from %V failed with status code "
                "(unknown error, see nginx error_logs): %d",
                &request->connection->addr_text, module_context->status);
            return write_error_response(request, NGX_HTTP_INTERNAL_SERVER_ERROR, module_location_config);
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->connection->log, 0,
                       "Called again without having received the response from Curity");

        return NGX_AGAIN;
    }

    ngx_str_t bearer_token = ngx_null_string;
    // Check if it's websocket
    if (request->headers_in.upgrade &&
        request->headers_in.upgrade->value.len > 0 &&
        !ngx_strncasecmp(request->headers_in.upgrade->value.data,
                         (u_char *)"websocket", 9)) {

        ngx_log_error(NGX_LOG_NOTICE, request->connection->log, 0,
                      "GraphQL WebSocket introspection request from %V",
                      &request->uri);

        // Get bearer from Sec-Websocket-Protocol header
        static ngx_str_t sec_websocket_protocol =
            ngx_string("Sec-WebSocket-Protocol");
        ngx_table_elt_t *sec_websocket_protocol_header =
            find_header_in(request, sec_websocket_protocol);
        if (sec_websocket_protocol_header == NULL) {
            // No Sec-WebSocket-Protocol header found
            ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
                          "No Sec-WebSocket-Protocol header found, "
                          "not eligible for introspection");
            return set_www_authenticate_header(request, module_location_config,
                                               NULL);
        }

        if (sec_websocket_protocol_header->value.len == 0) {
            // Empty Sec-WebSocket-Protocol header found
            ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
                          "Empty Sec-WebSocket-Protocol header found, not eligible for introspection");
            return set_www_authenticate_header(request, module_location_config,
                                               NULL);
        }

        // Sec-WebSocket-Protocol is a multi value comma separated header, search for "Bearer_"
        // Loop over the header value length
        bearer_token.data = ngx_strcasestrn(
            (u_char *)sec_websocket_protocol_header->value.data,
            (char *)BEARER_UNDERSCORE.data, BEARER_UNDERSCORE.len - 1);
        bearer_token.len =
            sec_websocket_protocol_header->value.len -
            (bearer_token.data - sec_websocket_protocol_header->value.data);
    } else if (request->headers_in.authorization && request->headers_in.authorization->value.len > 0) {
        bearer_token.data = ngx_strcasestrn(
            (u_char *)request->headers_in.authorization->value.data,
            (char *)BEARER.data, BEARER.len - 1);
        bearer_token.len =
            request->headers_in.authorization->value.len -
            (bearer_token.data - request->headers_in.authorization->value.data);
    }

    if (bearer_token.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Authorization header does not contain a bearer token");

        return set_www_authenticate_header(request, module_location_config,
                                           NULL);
    }

    // Skip "Bearer "
    bearer_token.data += BEARER.len;
    bearer_token.len -= BEARER.len;

    // Remove any extra whitespace after the "Bearer " part of the authorization request header
    while (isspace(*bearer_token.data)) {
        bearer_token.data++;
        bearer_token.len--;
    }

    // Read until the next comma or space or nothing
    ngx_uint_t i = 0;
    while (i < bearer_token.len && !isspace(bearer_token.data[i]) &&
           bearer_token.data[i] != ',') {
        i++;
    }
    bearer_token.len = i;

    module_context = ngx_pcalloc(request->pool, sizeof(phantom_token_module_context_t));

    if (module_context == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Failed to allocate memory for module context");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_post_subrequest_t *introspection_request_callback = ngx_pcalloc(request->pool, sizeof(ngx_http_post_subrequest_t));

    if (introspection_request_callback == NULL)
    {
        ngx_log_error(
            NGX_LOG_ERR, request->connection->log, 0,
            "Failed to allocate memory for introspection request callback");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    introspection_request_callback->handler = introspection_response_handler;
    introspection_request_callback->data = module_context;
    ngx_http_request_t *introspection_request;

    if (ngx_http_subrequest(request, &module_location_config->introspection_endpoint, NULL, &introspection_request,
                            introspection_request_callback, NGX_HTTP_SUBREQUEST_WAITED) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Failed to create subrequest to introspection endpoint");
        write_error_response(request, NGX_HTTP_INTERNAL_SERVER_ERROR, module_location_config);
    }

    // extract access token from header
    u_char *introspect_body_data =
        ngx_pcalloc(request->pool,
                    6 + bearer_token.len); // len("token=") + bearer_token.len

    if (introspect_body_data == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Failed to allocate memory for introspection body data");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_t *introspection_body = ngx_pcalloc(request->pool, sizeof(ngx_str_t));

    if (introspection_body == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Failed to allocate memory for introspection body");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_snprintf(introspect_body_data, 6 + bearer_token.len, "token=%V",
                 &bearer_token);

    introspection_body->data = introspect_body_data;
    introspection_body->len = 6 + bearer_token.len;

    introspection_request->request_body =
        ngx_pcalloc(request->pool, sizeof(ngx_http_request_body_t));
    if (introspection_request->request_body == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Failed to allocate memory for introspection request");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_request_body_t *introspection_request_body =
        ngx_pcalloc(request->pool, sizeof(ngx_http_request_body_t));
    if (introspection_request_body == NULL)
    {
        ngx_log_error(
            NGX_LOG_ERR, request->connection->log, 0,
            "Failed to allocate memory for introspection request body");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_buf_t *introspection_request_body_buffer =
        ngx_calloc_buf(request->pool);
    if (introspection_request_body_buffer == NULL)
    {
        ngx_log_error(
            NGX_LOG_ERR, request->connection->log, 0,
            "Failed to allocate memory for introspection request body buffer");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    introspection_request_body_buffer->start = introspection_request_body_buffer->pos = introspection_body->data;
    introspection_request_body_buffer->end = introspection_request_body_buffer->last = introspection_body->data +
            introspection_body->len;

    introspection_request_body_buffer->temporary = true;

    introspection_request_body->bufs = ngx_alloc_chain_link(request->pool);
    if (introspection_request_body->bufs == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Failed to allocate memory for introspection request "
                      "body chain link");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    introspection_request_body->bufs->buf = introspection_request_body_buffer;
    introspection_request_body->bufs->next = NULL;
    introspection_request_body->buf = introspection_request_body_buffer;
    introspection_request->request_body = introspection_request_body;
    introspection_request->headers_in.content_length_n = ngx_buf_size(introspection_request_body_buffer);

#if (NGX_HTTP_HEADERS)
    if (request->headers_in.accept == NULL)
    {
        ngx_int_t result;
        static ngx_str_t application_jwt = ngx_string("application/jwt");
        if ((result = set_accept_header_value(introspection_request,
                                              application_jwt) != NGX_OK)) {
            return result;
        }
    }
    else
    {
        module_context->original_accept_header = request->headers_in.accept->value;
    }

    ngx_str_set(&introspection_request->headers_in.accept->value, "application/jwt");
#endif

    if (request->headers_in.content_type == NULL)
    {
        static ngx_str_t ct = ngx_string("Content-Type");
        static ngx_str_t ct_value =
            ngx_string("application/x-www-form-urlencoded");
        ngx_uint_t found =
            set_header_helper(introspection_request, ct, ct_value,
                              &introspection_request->headers_in.content_type);
        if (found != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                          "Failed to set header content-type: "
                          "application/x-www-form-urlencoded");
            return NGX_ERROR;
        }

        // Update the number of headers
        if (introspection_request->headers_in.headers.part.next == NULL) {
            introspection_request->headers_in.headers.part.nelts =
                introspection_request->headers_in.headers.last->nelts;
        }
    }
    else
    {
        module_context->original_content_type_header = request->headers_in.content_type->value;
        ngx_str_set(&request->headers_in.content_type->value, "application/x-www-form-urlencoded");
    }

    introspection_request->header_only = true;

    // Change subrequest method to POST
    introspection_request->method = NGX_HTTP_POST;
    ngx_str_set(&introspection_request->method_name, "POST");

    // set authorization credentials header to Basic base64encoded_client_credential
    size_t authorization_header_data_len = encoded_client_credentials.len + sizeof("Basic ") - 1;
    u_char *authorization_header_data =
        ngx_pcalloc(request->pool, authorization_header_data_len);
    if (authorization_header_data == NULL)
    {
        ngx_log_error(
            NGX_LOG_ERR, request->connection->log, 0,
            "Failed to allocate memory for authorization header data");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_snprintf(authorization_header_data, authorization_header_data_len,
                 "Basic %V", &encoded_client_credentials);

    static ngx_str_t authorization = ngx_string("Authorization");
    ngx_str_t authorization_value = {authorization_header_data_len,
                                     authorization_header_data};

    // Save related websocket headers to not lose after subrequest
    static ngx_str_t sec_websocket_key = ngx_string("Sec-WebSocket-Key");
    ngx_table_elt_t *elt;
    if ((elt = find_header_in(request, sec_websocket_key)) != NULL) {
        module_context->original_sec_websocket_key = elt->value;
    }

    static ngx_str_t sec_websocket_version =
        ngx_string("Sec-WebSocket-Version");
    if ((elt = find_header_in(request, sec_websocket_version)) != NULL) {
        module_context->original_sec_websocket_version = elt->value;
    }

    set_header_helper(introspection_request, authorization, authorization_value,
                      &introspection_request->headers_in.authorization);

    ngx_http_set_ctx(request, module_context,
                     ngx_curity_http_phantom_token_module);

    return NGX_AGAIN;
}

static ngx_int_t introspection_response_handler(ngx_http_request_t *request, void *data,
                                                ngx_int_t introspection_subrequest_status_code)
{
    phantom_token_module_context_t *module_context = (phantom_token_module_context_t*)data;
    ngx_str_t cache_data = ngx_null_string;
    u_char *jwt_start = NULL;
    size_t jwt_len = 0;
    size_t bearer_jwt_len = 0;
    u_char *p = NULL;
    size_t body_buffer_size = 0;
    bool read_response = false;

    module_context->status = request->headers_out.status;

    // fail early for not 200 response
    if (request->headers_out.status != NGX_HTTP_OK)
    {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Subrequest to %V failed with response code: %d",
                      &request->uri, request->headers_out.status);
        module_context->done = 1;

        return introspection_subrequest_status_code;
    }

#if (NGX_HTTP_CACHE)
    // When caching is enabled, the introspection response is read from the cache, including the first request with a new opaque access token
    if (request->cache && !request->cache->buf)
    {
        // We have a cache but it's not primed
        ngx_http_file_cache_open(request);
    }

    if (request->cache && request->cache->buf && request->cache->valid_sec > 0)
    {
        cache_data.len = request->cache->length;
        cache_data.data = ngx_pnalloc(request->pool, cache_data.len);

        if (cache_data.data != NULL)
        {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->connection->log, 0,
                           "Reading from cache");
            ngx_read_file(&request->cache->file, cache_data.data, cache_data.len, request->cache->body_start);

            jwt_start = cache_data.data;
        }
    }
    else
    {
        read_response = true;
    }

#else
    read_response = true;
#endif

    jwt_len = request->headers_out.content_length_n;
    bearer_jwt_len = BEARER.len + jwt_len;

    // When caching is not used, the introspection response is read directly.
    // This method only receives a single response buffer per introspection request, which needs to contain the full JWT.
    if (read_response)
    {
        // We use proxy_pass to call the introspection endpoint, so the ngx_http_proxy_module provides the response to the subrequest.
        // The response is returned as an upstream buffer that NGINX prepares when it calls ngx_http_parse_header_line.
        // This sets request->header_end and points request->upstream->buffer.pos past headers to the body content.
        // - https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_proxy_module.c#L1905
        // - https://github.com/nginx/nginx/blob/master/src/http/ngx_http_parse.c#L816
        jwt_start = request->upstream->buffer.pos;

        // With default configuration, the total buffer memory size is 4KB and the response header size might be 332 bytes.
        // The ngx_buf_size macro returns the body size only: the size of the JWT or a partial size of the JWT, like 3764 bytes.
        // If the JWT content length is greater than the body buffer size, we must avoid reading past the end of the buffer.
        body_buffer_size = ngx_buf_size((
            &request->upstream->buffer)); // Double parenthesis because of macro
                                          // expansion issue for nginx 1.18.0.
        if (jwt_len > body_buffer_size)
        {
            // The standard solution to truncated responses, commonly used for long headers, is to configure an increased proxy_buffer_size.
            // The customer needs to configure a larger value for the introspection location, such as with the following configuration.
            // For a large JWT you might then get a body_buffer_size of 6535, even though the total buffer memory size is 16KB.
            //
            //  location curity {
            //    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
            //    proxy_buffer_size 16k;
            //    proxy_buffers 4 16k;
            // }

            ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "The introspection response buffer is too small to contain the JWT: increase the proxy_buffer_size configuration setting");
            module_context->done = 1;
            module_context->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return introspection_subrequest_status_code;
        }
    }

    if (jwt_start == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Failed to obtain JWT from introspection response or, if "
                      "applicable, cache");

        module_context->done = 1;
        module_context->status = NGX_HTTP_UNAUTHORIZED;

        return introspection_subrequest_status_code;
    }

    module_context->jwt.len = bearer_jwt_len;
    module_context->jwt.data = ngx_pnalloc(request->pool, bearer_jwt_len);

    if (module_context->jwt.data == NULL)
    {
        module_context->done = 1;
        module_context->status = NGX_HTTP_UNAUTHORIZED;

        return introspection_subrequest_status_code;
    }

    p = ngx_copy(module_context->jwt.data, BEARER.data, BEARER.len);
    ngx_memcpy(p, jwt_start, jwt_len);
    if (cache_data.len > 0)
    {
        ngx_pfree(request->pool, cache_data.data);
    }

    module_context->done = 1;

    return introspection_subrequest_status_code;
}

static ngx_int_t post_configuration(ngx_conf_t *config)
{
    ngx_http_core_main_conf_t *main_config = ngx_http_conf_get_module_main_conf(config, ngx_http_core_module);
    ngx_http_handler_pt *h = ngx_array_push(&main_config->phases[NGX_HTTP_ACCESS_PHASE].handlers);

    if (h == NULL)
    {
        return NGX_ERROR;
    }

    *h = handler;

    return NGX_OK;
}

static void *create_location_configuration(ngx_conf_t *config)
{
    phantom_token_configuration_t *location_config = ngx_pcalloc(config->pool, sizeof(phantom_token_configuration_t));

    if (location_config == NULL)
    {
        return NGX_CONF_ERROR;
    }

    location_config->enable = NGX_CONF_UNSET_UINT;
    location_config->scopes = NGX_CONF_UNSET_PTR;

    return location_config;
}

static char *merge_location_configuration(ngx_conf_t *main_config, void *parent, void *child)
{
    phantom_token_configuration_t *parent_config = parent, *child_config = child;

    ngx_conf_merge_off_value(child_config->enable, parent_config->enable, 0)
    ngx_conf_merge_str_value(child_config->introspection_endpoint, parent_config->introspection_endpoint, "")
    ngx_conf_merge_str_value(child_config->realm, parent_config->realm, "api")
    ngx_conf_merge_ptr_value(child_config->scopes, parent_config->scopes, NULL)
    ngx_conf_merge_str_value(child_config->space_separated_scopes, parent_config->space_separated_scopes, "")
    ngx_conf_merge_str_value(child_config->base64encoded_client_credential,
                             parent_config->base64encoded_client_credential, "")

    if (child_config->scopes != NULL && child_config->space_separated_scopes.len == 0)
    {
        // Flatten scopes into a space-separated list
        ngx_str_t *scope = child_config->scopes->elts;
        size_t space_separated_scopes_data_size = child_config->scopes->nelts;
        ngx_uint_t i;

        for (i = 0; i < child_config->scopes->nelts; i++)
        {
            space_separated_scopes_data_size += scope[i].len;
        }

        u_char *space_separated_scopes_data = ngx_pcalloc(main_config->pool, space_separated_scopes_data_size);

        if (space_separated_scopes_data == NULL)
        {
            return NGX_CONF_ERROR;
        }

        u_char *p = space_separated_scopes_data;

        for (i = 0; i < child_config->scopes->nelts; i++)
        {
            p = ngx_cpymem(p, scope[i].data, scope[i].len);
            *p = ' ';
            p++;
        }

        *(p - 1) = '\0';

        child_config->space_separated_scopes.data = space_separated_scopes_data;
        child_config->space_separated_scopes.len = ngx_strlen(space_separated_scopes_data);

        assert(child_config->space_separated_scopes.len <= space_separated_scopes_data_size);
    }

    return NGX_CONF_OK;
}

static char* set_client_credential_configuration_slot(ngx_conf_t *config_setting, ngx_command_t *command, void *result)
{
    ngx_str_t *base64encoded_client_credential = result;
    ngx_str_t *args = config_setting->args->elts;
    ngx_str_t client_id = args[1], client_secret = args[2]; // sub 0 is the directive itself

    if (client_id.len > 0 && client_secret.len > 0)
    {
        u_char unencoded_client_credentials_data[UNENCODED_CLIENT_CREDENTIALS_BUF_LEN];
        u_char *p = ngx_snprintf(unencoded_client_credentials_data, sizeof(unencoded_client_credentials_data), "%V:%V",
                                 &client_id, &client_secret);
        ngx_str_t unencoded_client_credentials = { p - unencoded_client_credentials_data,
                                                   unencoded_client_credentials_data };

        base64encoded_client_credential->data = ngx_palloc(
                config_setting->pool, ngx_base64_encoded_length(unencoded_client_credentials.len));

        if (base64encoded_client_credential->data == NULL)
        {
            return NGX_CONF_ERROR;
        }

        ngx_encode_base64(base64encoded_client_credential, &unencoded_client_credentials);

        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, config_setting, 0, "invalid client ID and/or secret");

    return "invalid_client_credential";
}

static char *set_client_credential_file_configuration_slot(
    ngx_conf_t *config_setting, ngx_command_t *command, void *result) {
    ngx_str_t *base64encoded_client_credential = result;
    ngx_str_t *args = config_setting->args->elts;
    ngx_str_t client_id = args[1], client_secret_file = args[2];

    u_char *path = client_secret_file.data;
    ngx_file_t file;
    ngx_file_info_t fi;

    if (client_id.len == 0) {
        return "invalid_client_credential";
    }

    file.fd = ngx_open_file(path, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_ERR, config_setting, ngx_errno,
                           "unable to open file %s", path);
        return NGX_CONF_ERROR;
    }

    if (ngx_fd_info(file.fd, &fi)) {
        ngx_conf_log_error(NGX_LOG_ERR, config_setting, ngx_errno,
                           "unable to stat file %s", path);
        goto failed;
    }

    size_t size = ngx_file_size(&fi);
    if (size == 0) {
        ngx_conf_log_error(NGX_LOG_ERR, config_setting, 0, "file %s is empty",
                           path);
        goto failed;
    }

    u_char *buf = ngx_pnalloc(config_setting->pool, size);
    if (buf == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, config_setting, 0,
                           "could not allocate buf");
        goto failed;
    }

    ssize_t n = ngx_read_file(&file, buf, size, 0);
    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_CRIT, config_setting, ngx_errno,
                           "file %s read error", path);
        goto failed;
    }
    if ((size_t)n != size) {
        ngx_conf_log_error(NGX_LOG_CRIT, config_setting, 0,
                           "file %s returned only %z bytes instead of %uz",
                           path, n, size);
        goto failed;
    }

    // Trim newline
    if (n > 0 && buf[n - 1] == '\n') {
        buf[--n] = '\0';
    }
    ngx_str_t client_secret = {n, buf};

    u_char
        unencoded_client_credentials_data[UNENCODED_CLIENT_CREDENTIALS_BUF_LEN];
    u_char *p = ngx_snprintf(unencoded_client_credentials_data,
                             sizeof(unencoded_client_credentials_data), "%V:%V",
                             &client_id, &client_secret);
    ngx_str_t unencoded_client_credentials = {
        p - unencoded_client_credentials_data,
        unencoded_client_credentials_data};

    base64encoded_client_credential->data =
        ngx_palloc(config_setting->pool,
                   ngx_base64_encoded_length(unencoded_client_credentials.len));

    if (base64encoded_client_credential->data == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_encode_base64(base64encoded_client_credential,
                      &unencoded_client_credentials);

    ngx_conf_log_error(NGX_LOG_INFO, config_setting, 0,
                       "loaded client secret file");

    return NGX_CONF_OK;

failed:
    if (file.fd != NGX_INVALID_FILE &&
        ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_ALERT, config_setting, ngx_errno,
                           "unable to close file %s", path);
    }
    return "invalid_client_credential";
}

static ngx_int_t set_www_authenticate_header(ngx_http_request_t *request, phantom_token_configuration_t *module_location_config, char *error_code)
{
    request->headers_out.www_authenticate = ngx_list_push(&request->headers_out.headers);

    if (request->headers_out.www_authenticate == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    static const char REALM_PREFIX[] = "realm=\"";
    static const size_t REALM_PREFIX_SIZE = sizeof(REALM_PREFIX) - 1;

    static const char TOKEN_SUFFIX[] = "\"";
    static const size_t TOKEN_SUFFIX_SIZE = sizeof(TOKEN_SUFFIX) - 1;

    static const char TOKEN_SEPARATER[] = ", ";
    static const size_t TOKEN_SEPARATER_SIZE = sizeof(TOKEN_SEPARATER) - 1;

    static const char SCOPE_PREFIX[] = "scope=\"";
    static const size_t SCOPE_PREFIX_SIZE = sizeof(SCOPE_PREFIX) - 1;

    static const u_char ERROR_CODE_PREFIX[] = "error=\"";
    static const size_t ERROR_CODE_PREFIX_SIZE = sizeof(ERROR_CODE_PREFIX) - 1;

    size_t bearer_data_size =
        BEARER.len + sizeof('\0'); // Add one for the nul byte
    bool realm_provided = module_location_config->realm.len > 0;
    bool scopes_provided = module_location_config->space_separated_scopes.len > 0;
    bool error_code_provided = error_code != NULL;
    bool append_one_comma = false, append_two_commas = false;
    size_t error_code_len = 0;

    if (realm_provided)
    {
        bearer_data_size += REALM_PREFIX_SIZE + module_location_config->realm.len + TOKEN_SUFFIX_SIZE;
    }

    if (scopes_provided)
    {
        bearer_data_size += SCOPE_PREFIX_SIZE + module_location_config->space_separated_scopes.len + TOKEN_SUFFIX_SIZE;
    }

    if (error_code_provided)
    {
        error_code_len = ngx_strlen(error_code);
        bearer_data_size += ERROR_CODE_PREFIX_SIZE + error_code_len + TOKEN_SUFFIX_SIZE;
    }

    if ((realm_provided && scopes_provided) || (realm_provided && error_code_provided) || (scopes_provided && error_code_provided))
    {
        bearer_data_size += TOKEN_SEPARATER_SIZE;
        append_one_comma = true;

        if (realm_provided && scopes_provided && error_code_provided)
        {
            bearer_data_size += TOKEN_SEPARATER_SIZE;
            append_two_commas = true;
        }
    }

    u_char *bearer_data = ngx_pnalloc(request->pool, bearer_data_size);

    if (bearer_data == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u_char *p = ngx_cpymem(bearer_data, BEARER.data, BEARER.len);

    if (realm_provided)
    {
        p = ngx_cpymem(p, REALM_PREFIX, REALM_PREFIX_SIZE);
        p = ngx_cpymem(p, module_location_config->realm.data, module_location_config->realm.len);
        p = ngx_cpymem(p, TOKEN_SUFFIX, TOKEN_SUFFIX_SIZE);

        if (append_one_comma)
        {
            p = ngx_cpymem(p, TOKEN_SEPARATER, TOKEN_SEPARATER_SIZE);
        }
    }

    if (scopes_provided)
    {
        p = ngx_cpymem(p, SCOPE_PREFIX, SCOPE_PREFIX_SIZE);
        p = ngx_cpymem(p, module_location_config->space_separated_scopes.data, module_location_config->space_separated_scopes.len);
        p = ngx_cpymem(p, TOKEN_SUFFIX, TOKEN_SUFFIX_SIZE);

        if (append_one_comma || append_two_commas)
        {
            p = ngx_cpymem(p, TOKEN_SEPARATER, TOKEN_SEPARATER_SIZE);
        }
    }

    if (error_code_provided)
    {
        p = ngx_cpymem(p, ERROR_CODE_PREFIX, ERROR_CODE_PREFIX_SIZE);
        p = ngx_cpymem(p, error_code, error_code_len);
        p = ngx_cpymem(p, TOKEN_SUFFIX, TOKEN_SUFFIX_SIZE);
    }

    if (!scopes_provided && !realm_provided && !error_code_provided)
    {
        // Only 'Bearer' is being sent. Replace the space at the end of BEARER with a null byte.
        *(p - 1) = '\0';
    }
    else
    {
        *p = '\0';
    }

    request->headers_out.www_authenticate->hash = 1;
    ngx_str_set(&request->headers_out.www_authenticate->key, "WWW-Authenticate");
    request->headers_out.www_authenticate->value.data = bearer_data;
    request->headers_out.www_authenticate->value.len = ngx_strlen(bearer_data);

    assert(request->headers_out.www_authenticate->value.len <= bearer_data_size);

    return write_error_response(request, NGX_HTTP_UNAUTHORIZED, module_location_config);
}

/*
 * Add the error response as a JSON object that is easier to handle than the default HTML response that NGINX returns
 * http://nginx.org/en/docs/dev/development_guide.html#http_response_body
 */
static ngx_int_t write_error_response(ngx_http_request_t *request, ngx_int_t status, phantom_token_configuration_t *module_location_config)
{
    ngx_int_t rc;
    ngx_str_t code;
    ngx_str_t message;
    u_char json_error_data[256];
    ngx_chain_t output;
    ngx_buf_t *body = NULL;
    const char *error_format = NULL;
    size_t error_len = 0;

    if (request->method == NGX_HTTP_HEAD)
    {
        return status;
    }

    body = ngx_calloc_buf(request->pool);
    if (body == NULL)
    {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0, "Failed to allocate memory for error body");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    else
    {
        if (status == NGX_HTTP_UNAUTHORIZED)
        {
            ngx_str_set(&code, "unauthorized_request");
            ngx_str_set(&message, "Access denied due to missing, invalid or "
                                  "expired credentials.");
        } else if (status >= 400 && status < 500) {
            ngx_str_set(&code, "client_error");
            ngx_str_set(&message,
                        "Problem encountered processing the request.");
        } else if (status == NGX_HTTP_SERVICE_UNAVAILABLE) {
            ngx_str_set(&code, "service_unavailable");
            ngx_str_set(
                &message,
                "Service unavailable. Please contact the administrator.");
        } else {
            ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                          "Internal server error encountered when processing "
                          "the request.");
            ngx_str_set(&code, "server_error");
            ngx_str_set(
                &message,
                "Internal server error encountered when "
                "processing the request. Please contact the administrator.");
        }

        /* The string length calculation replaces the two '%V' markers with their actual values */
        error_format = "{\"code\":\"%V\",\"message\":\"%V\"}";
        error_len = ngx_strlen(error_format) + code.len + message.len - 4;
        ngx_snprintf(json_error_data, sizeof(json_error_data) - 1, error_format, &code, &message);
        json_error_data[error_len] = 0;

        request->headers_out.status = status;
        request->headers_out.content_length_n = error_len;
        ngx_str_set(&request->headers_out.content_type, "application/json");

        rc = ngx_http_send_header(request);
        if (rc == NGX_ERROR || rc > NGX_OK || request->header_only) {
            return rc;
        }

        body->pos = json_error_data;
        body->last = json_error_data + error_len;
        body->memory = 1;
        body->last_buf = 1;
        body->last_in_chain = 1;
        output.buf = body;
        output.next = NULL;

        /* Return an error result, which also requires finalize_request to be called, to prevent a 'header already sent' warning in logs
           https://forum.nginx.org/read.php?29,280514,280521#msg-280521 */
        rc = ngx_http_output_filter(request, &output);
        ngx_http_finalize_request(request, rc);
        return NGX_DONE;
    }
}
