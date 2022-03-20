#include "mosq_ext_auth/util.h"

#include <mosquitto.h>
#include <mosquitto_broker.h>

void mosq_ext_auth_report_error(
        int level,
        const char *file,
        int line,
        const char *expression,
        const char *msg,
        int error_code
) {
    const char *error_msg = mosquitto_strerror(error_code);

    mosquitto_log_printf(
            level,
            "%s:%d: %s %s -> %s",
            file,
            line,
            msg,
            expression,
            error_msg
    );
}
