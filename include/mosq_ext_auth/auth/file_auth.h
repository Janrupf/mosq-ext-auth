#pragma once

#include "mosq_ext_auth/mosq_ext_auth.h"

int mosq_ext_auth_do_file_auth(const char *username, const char *password, mosq_ext_auth_userdata_t *data);
