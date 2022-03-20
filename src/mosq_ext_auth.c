#include "mosq_ext_auth/mosq_ext_auth.h"

#include <string.h>

#include "mosq_ext_auth/auth_handler.h"
#include "mosq_ext_auth/util.h"

#include "cJSON.h"

MOSQ_EXT_AUTH_EXPORT int mosquitto_plugin_version(int supported_version_count, const int *supported_versions) {
    for(int i = 0; i < supported_version_count; i++) {
        if(supported_versions[i] == 5) {
            return 5;
        }
    }

    return -1;
}

MOSQ_EXT_AUTH_EXPORT int mosquitto_plugin_init(
        mosquitto_plugin_id_t *plugin_id,
        void **userdata,
        struct mosquitto_opt *options,
        int option_count
) {
    mosquitto_log_printf(MOSQ_LOG_INFO, "mosq-ext-auth initializing...");

    cJSON_Hooks hooks = {
            mosquitto_malloc,
            mosquitto_free
    };
    cJSON_InitHooks(&hooks);

    *userdata = mosquitto_malloc(sizeof(mosq_ext_auth_userdata_t));
    if(!*userdata) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "mosq-ext-auth out of memory!");
        return MOSQ_ERR_NOMEM;
    }

    mosq_ext_auth_userdata_t *data = *userdata;
    data->plugin_id = plugin_id;
    data->http_auth_endpoint = NULL;
    data->http_auth_kind = MOSQ_AUTH_EXT_HTTP_BASIC;
    data->curl = NULL;
    data->header_list = NULL;
    data->users = mosq_ext_auth_create_user_database();

    for(int i = 0; i < option_count; i++) {
        struct mosquitto_opt *option = &options[i];

        if(strcmp("http_auth_endpoint", option->key) == 0) {
            data->http_auth_endpoint = option->value;
            mosquitto_log_printf(MOSQ_LOG_DEBUG, "HTTP basic auth endpoint set to %s", data->http_auth_endpoint);

            data->curl = curl_easy_init();
            if(!data->curl) {
                mosquitto_log_printf(MOSQ_LOG_ERR, "Failed to initialize CURL!");
                return MOSQ_ERR_UNKNOWN;
            }
        } else if(strcmp("http_auth_kind", option->key) == 0) {
            if(strcmp("http_basic", option->value) == 0) {
                mosquitto_log_printf(MOSQ_LOG_DEBUG, "Setting HTTP auth method to basic HTTP auth");
                data->http_auth_kind = MOSQ_AUTH_EXT_HTTP_BASIC;
            } else if(strcmp("post_json", option->value) == 0) {
                mosquitto_log_printf(MOSQ_LOG_DEBUG, "Setting HTTP auth method to post JSON auth");
                data->http_auth_kind = MOSQ_AUTH_EXT_POST_JSON;
            } else {
                mosquitto_log_printf(
                        MOSQ_LOG_WARNING,
                        "Ignoring unknown HTTP auth kind %s, only http_basic and post_json are valid!",
                        option->value
                );
            }
        } else if(strcmp("http_header", option->key) == 0) {
            mosquitto_log_printf(MOSQ_LOG_DEBUG, "Adding HTTP header %s", option->value);
            data->header_list = curl_slist_append(data->header_list, option->value);
        } else if(strcmp("user_file", option->key) == 0) {
            mosquitto_log_printf(MOSQ_LOG_INFO, "Attempting to import users from %s", option->value);
            mosq_ext_auth_import_user_database_from_file(data->users, option->value);
        } else {
            mosquitto_log_printf(MOSQ_LOG_WARNING, "Ignoring unknown option %s for mosq-ext-auth!", option->key);
        }
    }

    MOSQ_AUTH_EXT_CHECK(
            mosquitto_callback_register(plugin_id, MOSQ_EVT_BASIC_AUTH, mosq_ext_auth_callback, NULL, data),
            "Failed to register basic auth callback"
    );

    return 0;
}

MOSQ_EXT_AUTH_EXPORT int mosquitto_plugin_cleanup(
        void *userdata,
        struct mosquitto_opt *options,
        int option_count
) {
    mosquitto_log_printf(MOSQ_LOG_INFO, "mosq-ext-auth shutting down...");

    mosq_ext_auth_userdata_t *data = userdata;
    mosq_ext_auth_delete_user_database(data->users);

    if(data->header_list) {
        curl_slist_free_all(data->header_list);
    }

    if(data->curl) {
        curl_easy_cleanup(data->curl);
    }

    MOSQ_AUTH_EXT_CHECK(
            mosquitto_callback_unregister(data->plugin_id, MOSQ_EVT_BASIC_AUTH, mosq_ext_auth_callback, NULL),
            "Failed to unregister basic auth callback"
    );

    mosquitto_free(data);

    return 0;
}
