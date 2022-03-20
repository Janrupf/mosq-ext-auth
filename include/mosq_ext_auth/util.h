#pragma once

#define MOSQ_AUTH_EXT_CHECK(x, msg) \
    do {                       \
        int err = (x);         \
        if(err != MOSQ_ERR_SUCCESS && err != MOSQ_ERR_AUTH_CONTINUE) { \
            mosq_ext_auth_report_error(MOSQ_LOG_ERR, __FILE__, __LINE__, #x, msg, err);                   \
            return err; \
        }\
    } while(0)

#define MOSQ_AUTH_EXT_CHECK_RES(res, x, msg) \
    do {                       \
        int err = (x);         \
        if(err != MOSQ_ERR_SUCCESS && err != MOSQ_ERR_AUTH_CONTINUE) { \
            mosq_ext_auth_report_error(MOSQ_LOG_ERR, __FILE__, __LINE__, #x, msg, err);                   \
            return err; \
        }                                    \
        *res = err;                                         \
    } while(0)

void mosq_ext_auth_report_error(
        int level,
        const char *file,
        int line,
        const char *expression,
        const char *msg,
        int error_code
);
