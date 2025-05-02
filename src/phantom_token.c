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
#include "phantom_token_headers_more.h"
#include "phantom_token_utils.h"

#define UNENCODED_CLIENT_CREDENTIALS_BUF_LEN 255

typedef struct
{
    ngx_uint_t done;
    ngx_uint_t status;
    ngx_str_t jwt;
    ngx_str_t original_accept_header;
    ngx_str_t original_content_type_header;
} phantom_token_module_context_t;

static ngx_int_t post_configuration(ngx_conf_t *config);

static void *create_location_configuration(ngx_conf_t *config);

static char *merge_location_configuration(ngx_conf_t *main_config, void *parent, void *child);

static char* set_client_credential_configuration_slot(ngx_conf_t *config_setting, ngx_command_t *command, void *result);

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
        ngx_string("phantom_token_client_credential"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
        set_client_credential_configuration_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(phantom_token_configuration_t, base64encoded_client_credential),
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

static ngx_str_t ACCEPT_HEADER_NAME = ngx_string("Accept");
static ngx_str_t CONTENT_TYPE_HEADER_NAME = ngx_string("Content-Type");
static ngx_str_t AUTHORIZATION_HEADER_NAME = ngx_string("Authorization");

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

/**
 * The main handler logic
 */
ngx_int_t handler(ngx_http_request_t *request)
{
    phantom_token_configuration_t *module_location_config = ngx_http_get_module_loc_conf(
            request,
            ngx_curity_http_phantom_token_module);

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
        return NGX_HTTP_NO_CONTENT;
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

    if (module_context != NULL)
    {
        if (module_context->done)
        {
            if (module_context->status == NGX_HTTP_OK)
            {
                // Introspection was successful - replace the incoming authorization header with one that has the JWT
                if (headers_more_set_header_in(request, AUTHORIZATION_HEADER_NAME, module_context->jwt, &request->headers_in.authorization) != NGX_OK)
                {
                    utils_log_upstream_set_header_error(request, AUTHORIZATION_HEADER_NAME);
                    return utils_write_error_response(request, NGX_HTTP_INTERNAL_SERVER_ERROR, module_location_config);
                }

                if (module_context->original_content_type_header.data == NULL)
                {
                    // Clear the content-type header used for introspection
                    if (headers_more_clear_header_in(request, CONTENT_TYPE_HEADER_NAME) != NGX_OK)
                    {
                        utils_log_upstream_set_header_error(request, CONTENT_TYPE_HEADER_NAME);
                        return utils_write_error_response(request, NGX_HTTP_INTERNAL_SERVER_ERROR, module_location_config);
                    }
                }
                else
                {
                    // Restore the content-type header from before introspection
                    if (headers_more_set_header_in(request, CONTENT_TYPE_HEADER_NAME, module_context->original_content_type_header, &request->headers_in.content_type) != NGX_OK)
                    {
                        utils_log_upstream_set_header_error(request, CONTENT_TYPE_HEADER_NAME);
                        return utils_write_error_response(request, NGX_HTTP_INTERNAL_SERVER_ERROR, module_location_config);
                    }
                }

                if (request->headers_in.accept == NULL)
                {
                    // The phantom token module has always added a default value here
                    ngx_str_t accept_value = ngx_string("*/*");
                    if (headers_more_set_header_in(request, ACCEPT_HEADER_NAME, accept_value, &request->headers_in.accept) != NGX_OK)
                    {
                        utils_log_upstream_set_header_error(request, ACCEPT_HEADER_NAME);
                        return utils_write_error_response(request, NGX_HTTP_INTERNAL_SERVER_ERROR, module_location_config);
                    }
                }
                else
                {
                    // Restore the accept header from before introspection
                    if (headers_more_set_header_in(request, ACCEPT_HEADER_NAME, module_context->original_accept_header, &request->headers_in.accept) != NGX_OK)
                    {
                        utils_log_upstream_set_header_error(request, ACCEPT_HEADER_NAME);
                        return utils_write_error_response(request, NGX_HTTP_INTERNAL_SERVER_ERROR, module_location_config);
                    }
                }

                return NGX_OK;
            }
            else if (module_context->status == NGX_HTTP_NO_CONTENT)
            {
                return utils_set_www_authenticate_header(request, module_location_config, NULL);
            }
            else if (module_context->status == NGX_HTTP_SERVICE_UNAVAILABLE)
            {
                return utils_write_error_response(request, NGX_HTTP_SERVICE_UNAVAILABLE, module_location_config);
            }
            else if (module_context->status >= NGX_HTTP_INTERNAL_SERVER_ERROR ||
                     module_context->status == NGX_HTTP_NOT_FOUND ||
                     module_context->status == NGX_HTTP_UNAUTHORIZED ||
                     module_context->status == NGX_HTTP_FORBIDDEN)
            {
                return utils_write_error_response(request, NGX_HTTP_BAD_GATEWAY, module_location_config);
            }

            return utils_write_error_response(request, NGX_HTTP_INTERNAL_SERVER_ERROR, module_location_config);
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->connection->log, 0,
            "Called again without having received the introspection response");

        return NGX_AGAIN;
    }

    // return unauthorized when no authorization header is present
    if (!request->headers_in.authorization || request->headers_in.authorization->value.len <= 0)
    {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0, "Authorization header not found");
        return utils_set_www_authenticate_header(request, module_location_config, NULL);
    }

    u_char *bearer_token_pos;

    if ((bearer_token_pos = ngx_strcasestrn((u_char*)request->headers_in.authorization->value.data,
        (char*)BEARER, BEARER_SIZE - 1)) == NULL)
    {
        // return unauthorized when Authorization header is not Bearer
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0, "Authorization header does not contain a bearer token");
        return utils_set_www_authenticate_header(request, module_location_config, NULL);
    }

    bearer_token_pos += BEARER_SIZE;

    // Remove any extra whitespace after the "Bearer " part of the authorization request header
    while (isspace(*bearer_token_pos))
    {
        bearer_token_pos++;
    }

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
        request,
        &module_location_config->introspection_endpoint,
        NULL, 
        &introspection_request,
        introspection_request_callback, 
        NGX_HTTP_SUBREQUEST_WAITED) != NGX_OK)
    {
        return utils_write_error_response(request, NGX_HTTP_INTERNAL_SERVER_ERROR, module_location_config);
    }

    // extract access token from header
    u_char *introspect_body_data = ngx_pcalloc(request->pool, request->headers_in.authorization->value.len);
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

    ngx_snprintf(introspect_body_data, request->headers_in.authorization->value.len, "token=%s", bearer_token_pos);

    introspection_body->data = introspect_body_data;
    introspection_body->len = ngx_strlen(introspection_body->data);

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

#if (NGX_HTTP_HEADERS)

    if (request->headers_in.accept != NULL)
    {
        module_context->original_accept_header = request->headers_in.accept->value;
    }

    ngx_str_t application_jwt = ngx_string("application/jwt");
    if (headers_more_set_header_in(introspection_request, ACCEPT_HEADER_NAME, application_jwt, &introspection_request->headers_in.accept) != NGX_OK)
    {
        utils_log_subrequest_set_header_error(request, ACCEPT_HEADER_NAME);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

#endif

    if (request->headers_in.content_type != NULL)
    {
        module_context->original_content_type_header = request->headers_in.content_type->value;
    }

    ngx_str_t form_url_encoded = ngx_string("application/x-www-form-urlencoded");
    if (headers_more_set_header_in(introspection_request, CONTENT_TYPE_HEADER_NAME, form_url_encoded, &introspection_request->headers_in.content_type) != NGX_OK)
    {
        utils_log_subrequest_set_header_error(request, CONTENT_TYPE_HEADER_NAME);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    introspection_request->header_only = true;

    // Change subrequest method to POST
    introspection_request->method = NGX_HTTP_POST;
    ngx_str_set(&introspection_request->method_name, "POST");

    // set authorization credentials header to Basic base64encoded_client_credential
    size_t authorization_header_data_len = encoded_client_credentials.len + sizeof("Basic ") - 1;
    u_char *authorization_header_data = ngx_pcalloc(request->pool, authorization_header_data_len);

    if (authorization_header_data == NULL)
    {
        utils_log_memory_allocation_error(request, "authorization_header_data");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_snprintf(authorization_header_data, authorization_header_data_len, "Basic %V", &encoded_client_credentials);

    ngx_str_t authorization_value = {authorization_header_data_len, authorization_header_data};
    if (headers_more_set_header_in(introspection_request, AUTHORIZATION_HEADER_NAME, authorization_value, &introspection_request->headers_in.authorization) != NGX_OK)
    {
        utils_log_subrequest_set_header_error(request, AUTHORIZATION_HEADER_NAME);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // If current is the last buffer, make sure its number of elements are up to date so that any added headers are sent
    if (introspection_request->headers_in.headers.part.next == NULL && 
        introspection_request->headers_in.headers.part.nelts < introspection_request->headers_in.headers.last->nelts)
    {
        introspection_request->headers_in.headers.part.nelts = introspection_request->headers_in.headers.last->nelts;
    }

    // If the below condition is true, current is not the last buffer, so move to last to ensure that any added headers are sent
    if (introspection_request->headers_in.headers.part.nelts > introspection_request->headers_in.headers.last->nelts)
    {
        introspection_request->headers_in.headers.part.next = introspection_request->headers_in.headers.last;
    }

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
        body_buffer_size = ngx_buf_size(&request->upstream->buffer);
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