#include "mosq_ext_auth/auth/http_auth.h"

#include <string.h>
#include <cJSON.h>

static size_t http_recv_callback(char *data, size_t unit_size, size_t unit_count, void *userdata) {
    size_t byte_size = unit_size * unit_count;
    return byte_size;
}

int mosq_ext_auth_do_http_auth(const char *username, const char *password, mosq_ext_auth_userdata_t *data) {
    if(!data->http_auth_endpoint) {
        mosquitto_log_printf(MOSQ_LOG_WARNING, "Failing HTTP auth as http_auth_endpoint is not set!");
        return MOSQ_ERR_AUTH_CONTINUE;
    }

    if(data->http_auth_kind == MOSQ_AUTH_EXT_HTTP_BASIC && strstr(username, ":")) {
        mosquitto_log_printf(MOSQ_LOG_WARNING, "Username %s contains colons, not attempting HTTP basic auth!", username);
        mosquitto_log_printf(MOSQ_LOG_WARNING, "In order to authenticate users with colons, create user entries in the configuration or use post_json auth!");
        return MOSQ_ERR_AUTH_CONTINUE;
    }


    curl_easy_reset(data->curl);
    curl_easy_setopt(data->curl, CURLOPT_URL, data->http_auth_endpoint);
    curl_easy_setopt(data->curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(data->curl, CURLOPT_WRITEFUNCTION, http_recv_callback);
    curl_easy_setopt(data->curl, CURLOPT_WRITEDATA, NULL);

    char *username_password_buffer = NULL;
    struct curl_slist *new_header_list = NULL;
    char *post_fields = NULL;

    if(data->http_auth_kind == MOSQ_AUTH_EXT_HTTP_BASIC) {
        username_password_buffer = mosquitto_malloc(strlen(username) + 1 + strlen(password) + 1);
        sprintf(username_password_buffer, "%s:%s", username, password);

        curl_easy_setopt(data->curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(data->curl, CURLOPT_USERPWD, username_password_buffer);

        if(data->header_list) {
            curl_easy_setopt(data->curl, CURLOPT_HTTPHEADER, data->header_list);
        }

        mosquitto_free(username_password_buffer);

    } else if(data->http_auth_kind == MOSQ_AUTH_EXT_POST_JSON) {
        struct curl_slist *old_header_list = data->header_list;

        while(old_header_list) {
            new_header_list = curl_slist_append(new_header_list, old_header_list->data);
            old_header_list = old_header_list->next;
        }

        new_header_list = curl_slist_append(new_header_list, "Content-Type: application/json");

        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "username", username);
        cJSON_AddStringToObject(obj, "password", password);

        post_fields = cJSON_PrintUnformatted(obj);
        cJSON_Delete(obj);

        curl_easy_setopt(data->curl, CURLOPT_POST, 1L);
        curl_easy_setopt(data->curl, CURLOPT_POSTFIELDS, post_fields);
        curl_easy_setopt(data->curl, CURLOPT_HTTPHEADER, new_header_list);
    }

    CURLcode result = curl_easy_perform(data->curl);

    if(username_password_buffer) {
        mosquitto_free(username_password_buffer);
    }

    if(post_fields) {
        mosquitto_free(post_fields);
    }

    if(new_header_list) {
        curl_slist_free_all(new_header_list);
    }

    if(result != CURLE_OK) {
        const char *msg = curl_easy_strerror(result);
        mosquitto_log_printf(MOSQ_LOG_WARNING, "HTTP request to %s failed: %s", data->http_auth_endpoint, msg);
        return MOSQ_ERR_AUTH_CONTINUE;
    }

    long http_code;
    curl_easy_getinfo(data->curl, CURLINFO_RESPONSE_CODE, &http_code);
    mosquitto_log_printf(
            MOSQ_LOG_DEBUG,
            "HTTP basic auth at %s resulted in http code %d",
            data->http_auth_endpoint,
            http_code
    );

    return (http_code >= 200 && http_code <= 300) ? MOSQ_ERR_SUCCESS : MOSQ_ERR_AUTH_CONTINUE;
}
