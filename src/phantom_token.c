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
#include "phantom_token.h"
#include "phantom_token_utils.h"

typedef struct
{
    ngx_uint_t done;
    ngx_uint_t status;
    ngx_str_t jwt;
} phantom_token_module_context_t;

static ngx_int_t post_configuration(ngx_conf_t *config);

static void *create_location_configuration(ngx_conf_t *config);

static char *merge_location_configuration(ngx_conf_t *main_config, void *parent, void *child);

static ngx_int_t handler(ngx_http_request_t *request);

static ngx_int_t introspection_response_handler(ngx_http_request_t *request, void *data, ngx_int_t introspection_subrequest_status_code);

static ngx_command_t phantom_token_module_directives[] =
{
    {
        ngx_string("phantom_token"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(phantom_token_configuration_t, enable),
        NULL
    },
    {
        ngx_string("phantom_token_introspection_endpoint"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(phantom_token_configuration_t, introspection_endpoint),
        NULL
    },
    {
        ngx_string("phantom_token_realm"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(phantom_token_configuration_t, realm),
        NULL
    },
    {
        ngx_string("phantom_token_scopes"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(phantom_token_configuration_t, space_separated_scopes),
        NULL
    },
    {
        ngx_string("phantom_token_scope"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_array_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(phantom_token_configuration_t, scopes),
        NULL
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

const char BEARER[] = "Bearer ";
const size_t BEARER_SIZE = sizeof(BEARER) - 1;

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

/**
 * The main handler logic
 */
ngx_int_t handler(ngx_http_request_t *request)
{
    phantom_token_configuration_t *module_location_config = ngx_http_get_module_loc_conf(
            request,
            ngx_curity_http_phantom_token_module);

    // Return immediately if the module is not active
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

    if (module_location_config->introspection_endpoint.len == 0)
    {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
            "Module not configured properly: missing introspection endpoint");

        return NGX_DECLINED;
    }

    phantom_token_module_context_t *module_context = ngx_http_get_module_ctx(request, ngx_curity_http_phantom_token_module);

    if (module_context != NULL)
    {
        if (module_context->done)
        {
            if (module_context->status == NGX_HTTP_OK)
            {
                // Introspection was successful. Replace the incoming
                // Authorization header with one that has the JWT.
                static ngx_str_t authorization = ngx_string("Authorization");
                set_header_helper(request, authorization, module_context->jwt,
                                  &request->headers_in.authorization);
                return NGX_OK;
            }
            else if (module_context->status == NGX_HTTP_NO_CONTENT)
            {
                ngx_log_error(
                    NGX_LOG_ERR, request->connection->log, 0,
                    "Introspection request from %V failed with no content: %d",
                    &request->connection->addr_text, module_context->status);
                return utils_set_www_authenticate_header(request, module_location_config, NULL);
            }
            else if (module_context->status == NGX_HTTP_SERVICE_UNAVAILABLE)
            {
                ngx_log_error(
                    NGX_LOG_ERR, request->connection->log, 0,
                    "Introspection request failed with service unavailable: %d",
                    module_context->status);
                return utils_write_error_response(request, NGX_HTTP_SERVICE_UNAVAILABLE, module_location_config);
            }
            else if (module_context->status >= NGX_HTTP_INTERNAL_SERVER_ERROR ||
                     module_context->status == NGX_HTTP_NOT_FOUND ||
                     module_context->status == NGX_HTTP_UNAUTHORIZED ||
                     module_context->status == NGX_HTTP_FORBIDDEN)
            {
                ngx_log_error(
                    NGX_LOG_ERR, request->connection->log, 0,
                    "Introspection request from %V failed with status code "
                    "(server responded): %d",
                    &request->connection->addr_text, module_context->status);
                return utils_write_error_response(request, NGX_HTTP_BAD_GATEWAY, module_location_config);
            }

            ngx_log_error(
                NGX_LOG_ERR, request->connection->log, 0,
                "Introspection request from %V failed with status code "
                "(unknown error, see nginx error_logs): %d",
                &request->connection->addr_text, module_context->status);
            return utils_write_error_response(request, NGX_HTTP_INTERNAL_SERVER_ERROR, module_location_config);
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->connection->log, 0,
            "Called again without having received the introspection response");

        return NGX_AGAIN;
    }

    // return unauthorized when no authorization header is present
    if (!request->headers_in.authorization || request->headers_in.authorization->value.len <= 0)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->connection->log, 0, "Authorization header not present");
        return utils_set_www_authenticate_header(request, module_location_config, NULL);
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
            return utils_set_www_authenticate_header(
                request, module_location_config, NULL);
        }

        if (sec_websocket_protocol_header->value.len == 0) {
            // Empty Sec-WebSocket-Protocol header found
            ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
                          "Empty Sec-WebSocket-Protocol header found, not "
                          "eligible for introspection");
            return utils_set_www_authenticate_header(
                request, module_location_config, NULL);
        }

        // Sec-WebSocket-Protocol is a multi value comma separated header,
        // search for "Bearer_" Loop over the header value length
        bearer_token.data =
            ngx_strcasestrn((u_char *)sec_websocket_protocol_header->value.data,
                            (char *)BEARER, BEARER_SIZE - 1);
        bearer_token.len =
            sec_websocket_protocol_header->value.len -
            (bearer_token.data - sec_websocket_protocol_header->value.data);
    } else if (request->headers_in.authorization &&
               request->headers_in.authorization->value.len > 0) {
        bearer_token.data = ngx_strcasestrn(
            (u_char *)request->headers_in.authorization->value.data,
            (char *)BEARER, BEARER_SIZE - 1);
        bearer_token.len =
            request->headers_in.authorization->value.len -
            (bearer_token.data - request->headers_in.authorization->value.data);
    }

    if (bearer_token.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Authorization header does not contain a bearer token");

        return utils_set_www_authenticate_header(request,
                                                 module_location_config, NULL);
    }

    // Skip "Bearer "
    bearer_token.data += BEARER_SIZE;
    bearer_token.len -= BEARER_SIZE;

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
        utils_log_memory_allocation_error(request, "module_context");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_post_subrequest_t *introspection_request_callback = ngx_pcalloc(request->pool, sizeof(ngx_http_post_subrequest_t));
    if (introspection_request_callback == NULL)
    {
        utils_log_memory_allocation_error(request, "introspection_request_callback");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    introspection_request_callback->handler = introspection_response_handler;
    introspection_request_callback->data = module_context;
    ngx_http_request_t *introspection_request;

    if (ngx_http_subrequest(
            request, &module_location_config->introspection_endpoint, NULL,
            &introspection_request, introspection_request_callback,
            NGX_HTTP_SUBREQUEST_WAITED) != NGX_OK) {
        return utils_write_error_response(request, NGX_HTTP_INTERNAL_SERVER_ERROR, module_location_config);
    }

    // extract access token from header
    u_char *introspect_body_data =
        ngx_pcalloc(request->pool,
                    6 + bearer_token.len); // len("token=") + bearer_token.len
    if (introspect_body_data == NULL)
    {
        utils_log_memory_allocation_error(request, "introspect_body_data");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_t *introspection_body = ngx_pcalloc(request->pool, sizeof(ngx_str_t));
    if (introspection_body == NULL)
    {
        utils_log_memory_allocation_error(request, "introspection_body");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_snprintf(introspect_body_data, 6 + bearer_token.len, "token=%V",
                 &bearer_token);

    introspection_body->data = introspect_body_data;
    introspection_body->len = 6 + bearer_token.len;

    ngx_http_request_body_t *introspection_request_body = ngx_pcalloc(request->pool, sizeof(ngx_http_request_body_t));
    if (introspection_request_body == NULL)
    {
        utils_log_memory_allocation_error(request, "introspection_request_body");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_buf_t *introspection_request_body_buffer = ngx_calloc_buf(request->pool);
    if (introspection_request_body_buffer == NULL)
    {
        utils_log_memory_allocation_error(request, "introspection_request_body_buffer");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    introspection_request_body_buffer->start = introspection_request_body_buffer->pos = introspection_body->data;
    introspection_request_body_buffer->end = introspection_request_body_buffer->last = introspection_body->data +
            introspection_body->len;

    introspection_request_body_buffer->temporary = true;

    introspection_request_body->bufs = ngx_alloc_chain_link(request->pool);
    if (introspection_request_body->bufs == NULL)
    {
        utils_log_memory_allocation_error(request, "introspection_request_body->bufs");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    introspection_request_body->bufs->buf = introspection_request_body_buffer;
    introspection_request_body->bufs->next = NULL;
    introspection_request_body->buf = introspection_request_body_buffer;
    introspection_request->request_body = introspection_request_body;
    introspection_request->headers_in.content_length_n = ngx_buf_size(introspection_request_body_buffer);

    // Don't send the incoming request's body in the introspection request
    introspection_request->header_only = true;

    // Change subrequest method to POST
    introspection_request->method = NGX_HTTP_POST;
    ngx_str_set(&introspection_request->method_name, "POST");

    ngx_http_set_ctx(request, module_context, ngx_curity_http_phantom_token_module);
    return NGX_AGAIN;
}

/**
 * The main logic to handle the introspection response
 */
static ngx_int_t introspection_response_handler(
    ngx_http_request_t *request,
    void *data,
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

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, request->connection->log, 0, "auth request done status = %d",
                   request->headers_out.status);

    module_context->status = request->headers_out.status;

    // Fail early for not 200 response
    if (request->headers_out.status != NGX_HTTP_OK)
    {
        // Log any error except 204 expiry responses, which are expected
        if (request->headers_out.status != NGX_HTTP_NO_CONTENT) {
            ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Introspection subrequest returned response code: %d", request->headers_out.status);
        }

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
    bearer_jwt_len = BEARER_SIZE + jwt_len;

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
        body_buffer_size = ngx_buf_size((&request->upstream->buffer));
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
            "Failed to obtain JWT access token from introspection response or cache");

        module_context->done = 1;
        module_context->status = NGX_HTTP_UNAUTHORIZED;

        return introspection_subrequest_status_code;
    }

    module_context->jwt.len = bearer_jwt_len;
    module_context->jwt.data = ngx_pnalloc(request->pool, bearer_jwt_len);
    if (module_context->jwt.data == NULL)
    {
        utils_log_memory_allocation_error(request, "module_context->jwt.data");

        module_context->done = 1;
        module_context->status = NGX_HTTP_UNAUTHORIZED;
        return introspection_subrequest_status_code;
    }

    p = ngx_copy(module_context->jwt.data, BEARER, BEARER_SIZE);
    ngx_memcpy(p, jwt_start, jwt_len);

    if (cache_data.len > 0)
    {
        ngx_pfree(request->pool, cache_data.data);
    }

    module_context->done = 1;

    return introspection_subrequest_status_code;
}
