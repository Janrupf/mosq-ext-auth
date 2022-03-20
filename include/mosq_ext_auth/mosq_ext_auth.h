#pragma once

#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

#include <curl/curl.h>

#include "mosq_ext_auth/user_database.h"

#if WIN32
#   define MOSQ_EXT_AUTH_EXPORT mosq_plugin_EXPORT
#else
#   define MOSQ_EXT_AUTH_EXPORT mosq_plugin_EXPORT __attribute__((visibility("default"), unused))
#endif

enum mosq_auth_ext_auth_kind {
    MOSQ_AUTH_EXT_HTTP_BASIC,
    MOSQ_AUTH_EXT_POST_JSON
};

typedef enum mosq_auth_ext_auth_kind mosq_auth_ext_auth_kind_t;

struct mosq_auth_ext_userdata {
    mosquitto_plugin_id_t *plugin_id;

    char *http_auth_endpoint;
    mosq_auth_ext_auth_kind_t http_auth_kind;
    CURL *curl;
    struct curl_slist *header_list;

    mosq_ext_auth_user_database_t *users;
};

typedef struct mosq_auth_ext_userdata mosq_ext_auth_userdata_t;
