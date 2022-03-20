#pragma once

struct mosq_ext_auth_user_database_entry {
    char *username;
    unsigned char *password;
    struct mosq_ext_auth_user_database_entry *next;
};

typedef struct mosq_ext_auth_user_database_entry mosq_ext_auth_user_database_entry_t;

struct mosq_ext_auth_user_database {
    unsigned char salt[1024];
    mosq_ext_auth_user_database_entry_t *first;
    mosq_ext_auth_user_database_entry_t *last;
};

typedef struct mosq_ext_auth_user_database mosq_ext_auth_user_database_t;

mosq_ext_auth_user_database_t *mosq_ext_auth_create_user_database();
void mosq_ext_auth_delete_user_database(mosq_ext_auth_user_database_t *database);
int mosq_ext_auth_authenticate_user_against_database(
        mosq_ext_auth_user_database_t *database,
        const char *username,
        const char *password
);

void mosq_ext_auth_import_user_database_from_file(mosq_ext_auth_user_database_t *database, const char *file);
