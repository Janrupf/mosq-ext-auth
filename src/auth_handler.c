#include "mosq_ext_auth/auth_handler.h"

#include <mosquitto.h>
#include <mosquitto_broker.h>

#include "mosq_ext_auth/util.h"
#include "mosq_ext_auth/auth/http_auth.h"

int mosq_ext_auth_callback(int event, void *event_data, void *userdata) {
    struct mosquitto_evt_basic_auth *evt = event_data;
    mosq_ext_auth_userdata_t *data = userdata;

    mosquitto_log_printf(MOSQ_LOG_DEBUG, "User %s:%s authenticating", evt->username, evt->password);

    if(mosq_ext_auth_authenticate_user_against_database(data->users, evt->username, evt->password)) {
        mosquitto_log_printf(MOSQ_LOG_DEBUG, "Authenticated %s using user database.", evt->username);
        return MOSQ_ERR_SUCCESS;
    }

    int result;
    MOSQ_AUTH_EXT_CHECK_RES(
            &result,
            mosq_ext_auth_do_http_auth(evt->username, evt->password, data),
            "Internal error while performing http auth"
    );

    if(result == MOSQ_ERR_SUCCESS) {
        mosquitto_log_printf(MOSQ_LOG_DEBUG, "Authenticated %s using HTTP auth.", evt->username);
        return result;
    }

    return MOSQ_ERR_PLUGIN_DEFER;
}
