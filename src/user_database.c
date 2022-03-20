#include "mosq_ext_auth/user_database.h"

#include <string.h>
#include <stdio.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include <mosquitto.h>
#include <mosquitto_broker.h>

#include <cJSON.h>

static unsigned char *hash_password(
        mosq_ext_auth_user_database_t *database,
        const char *pass
) {
    unsigned char *hash = mosquitto_malloc(EVP_MAX_MD_SIZE);
    const EVP_MD *digest = EVP_get_digestbyname("sha512");
    PKCS5_PBKDF2_HMAC(
            pass,
            (int) strlen(pass),
            database->salt,
            1024,
            10,
            digest,
            EVP_MAX_MD_SIZE,
            hash
    );

    return hash;
}

static mosq_ext_auth_user_database_entry_t *create_entry(
        mosq_ext_auth_user_database_t *database,
        const char *username,
        const char *password
) {
    mosq_ext_auth_user_database_entry_t *entry = mosquitto_malloc(sizeof(mosq_ext_auth_user_database_entry_t));
    entry->username = mosquitto_strdup(username);
    entry->password = hash_password(database, password);
    entry->next = NULL;

    return entry;
}


static void add_user(mosq_ext_auth_user_database_t *database, const char *username, const char *password) {
    mosquitto_log_printf(
            MOSQ_LOG_DEBUG,
            "Adding user %s to database",
            username
    );

    mosq_ext_auth_user_database_entry_t *entry = create_entry(database, username, password);

    if(!database->last) {
        database->first = entry;
        database->last = entry;
    } else {
        database->last->next = entry;
        database->last = entry;
    }
}

static void add_users(mosq_ext_auth_user_database_t *database, const char *file, cJSON *doc) {
    if(!cJSON_IsArray(doc)) {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Json in %s is not an array", file);
        return;
    }

    cJSON *entry;
    cJSON_ArrayForEach(entry, doc) {
        if(!cJSON_IsObject(entry)) {
            mosquitto_log_printf(MOSQ_LOG_WARNING, "Skipping invalid entry which is not an object in %s", file);
            continue;
        }

        if(!cJSON_HasObjectItem(entry, "username")) {
            mosquitto_log_printf(MOSQ_LOG_WARNING, "Skipping invalid entry which is missing the username key in %s", file);
            continue;
        }

        cJSON *username = cJSON_GetObjectItemCaseSensitive(entry, "username");
        if(!cJSON_IsString(username)) {
            mosquitto_log_printf(MOSQ_LOG_WARNING, "Skipping invalid entry where username is not a string in %s", file);
            continue;
        }

        if(!cJSON_HasObjectItem(entry, "password")) {
            mosquitto_log_printf(MOSQ_LOG_WARNING, "Skipping invalid entry which is missing the password key in %s", file);
            continue;
        }

        cJSON *password = cJSON_GetObjectItemCaseSensitive(entry, "password");
        if(!cJSON_IsString(password)) {
            mosquitto_log_printf(MOSQ_LOG_WARNING, "Skipping invalid entry where password is not a string in %s", file);
            continue;
        }

        add_user(database, cJSON_GetStringValue(username), cJSON_GetStringValue(password));
    }
}

mosq_ext_auth_user_database_t *mosq_ext_auth_create_user_database() {
    mosq_ext_auth_user_database_t *database = mosquitto_malloc(sizeof(mosq_ext_auth_user_database_t));
    if (RAND_bytes(&database->salt[0], 1024) != 1) {
        const char *error = ERR_error_string(ERR_get_error(), NULL);

        mosquitto_log_printf(
                MOSQ_LOG_ERR,
                "Failed to initialize user database as OpenSSL rng failed: %s",
                error
        );

        return NULL;
    }

    database->first = NULL;

    return database;
}

void mosq_ext_auth_delete_user_database(mosq_ext_auth_user_database_t *database) {
    if(database) {
        for(mosq_ext_auth_user_database_entry_t *entry = database->first; entry != NULL; entry = entry->next) {
            mosquitto_free(entry->username);
            mosquitto_free(entry->password);
        }

        mosquitto_free(database);
    }
}

int mosq_ext_auth_authenticate_user_against_database(
        mosq_ext_auth_user_database_t *database,
        const char *username,
        const char *password
) {
    if(database) {
        for(mosq_ext_auth_user_database_entry_t *entry = database->first; entry != NULL; entry = entry->next) {
            mosquitto_log_printf(
                    MOSQ_LOG_DEBUG,
                    "Checking if user %s matches %s",
                    username,
                    entry->username
            );

            if(strcmp(username, entry->username) == 0) {
                unsigned char *hash = hash_password(database, password);

                if(memcmp(hash, entry->password, EVP_MAX_MD_SIZE) == 0) {
                    return 1;
                } else {
                    mosquitto_log_printf(
                            MOSQ_LOG_DEBUG,
                            "User %s found in database, but passwords don't match",
                            username
                    );
                }
            }
        }

        mosquitto_log_printf(
                MOSQ_LOG_DEBUG,
                "User %s not found in database",
                username
        );
    } else {
        mosquitto_log_printf(
                MOSQ_LOG_WARNING,
                "Failing authentication against user database as database does not exist"
        );
    }

    return 0;
}

void mosq_ext_auth_import_user_database_from_file(mosq_ext_auth_user_database_t *database, const char *file) {
    FILE *f = fopen(file, "r");
    if(!f) {
        const char *error = strerror(errno);
        mosquitto_log_printf(
                MOSQ_LOG_ERR,
                "Failed to open user database file %s: %s",
                file,
                error
        );

        return;
    }

    fseek(f, 0, SEEK_END);
    off_t length = ftello(f);
    fseek(f, 0, SEEK_SET);

    char *buffer = mosquitto_malloc(length);
    size_t res = fread(buffer, 1, length, f);
    if(res != length) {
        const char *error = strerror(errno);
        mosquitto_log_printf(
                MOSQ_LOG_ERR,
                "Failed to read user database file %s: %s",
                file,
                error
        );
    } else {
        cJSON *doc = cJSON_Parse(buffer);
        if(doc) {
            add_users(database, file, doc);
            cJSON_Delete(doc);
        } else {
            const char *error = cJSON_GetErrorPtr();
            mosquitto_log_printf(
                    MOSQ_LOG_ERR,
                    "Failed to parse user database file %s: %s",
                    file,
                    error
            );
        }
    }

    mosquitto_free(buffer);
    fclose(f);
}
