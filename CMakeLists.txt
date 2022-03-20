#################
# Project setup #
#################
cmake_minimum_required(VERSION 3.15)
project(mosq_ext_auth C)

#####################
# Set CMake options #
#####################
set(CMAKE_C_STANDARD 11)

#####################
# Find dependencies #
#####################
find_package(PkgConfig REQUIRED)
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)

pkg_check_modules(LIB_MOSQUITTO REQUIRED IMPORTED_TARGET libmosquitto)
pkg_check_modules(LIB_CJSON REQUIRED IMPORTED_TARGET libcjson)

########################
# Source configuration #
########################
set(MOSQ_EXT_AUTH_SOURCE
        src/auth/http_auth.c

        src/auth_handler.c
        src/mosq_ext_auth.c
        src/user_database.c
        src/util.c)

set(MOSQ_EXT_AUTH_INCLUDE_DIR "${CMAKE_CURRENT_LIST_DIR}/include")

###############
# Add targets #
###############
add_library(mosq_ext_auth SHARED ${MOSQ_EXT_AUTH_SOURCE})
target_link_libraries(mosq_ext_auth PUBLIC
        PkgConfig::LIB_MOSQUITTO
        PkgConfig::LIB_CJSON
        CURL::libcurl
        OpenSSL::Crypto
)
set_target_properties(mosq_ext_auth PROPERTIES
        C_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
)
target_include_directories(mosq_ext_auth PUBLIC ${MOSQ_EXT_AUTH_INCLUDE_DIR})
