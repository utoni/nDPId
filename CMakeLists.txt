cmake_minimum_required(VERSION 3.12.4)
project(nDPId C)
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
find_package(PkgConfig REQUIRED)

option(ENABLE_SANITIZER "Enable ASAN/LSAN/UBSAN." OFF)
option(ENABLE_SANITIZER_THREAD "Enable TSAN (does not work together with ASAN)." OFF)
option(ENABLE_MEMORY_PROFILING "Enable dynamic memory tracking." OFF)
option(ENABLE_ZLIB "Enable zlib support for nDPId (experimental)." OFF)
option(BUILD_EXAMPLES "Build C examples." ON)
option(BUILD_NDPI "Clone and build nDPI from github." OFF)
option(NDPI_NO_PKGCONFIG "Do not use pkgconfig to search for libnDPI." OFF)

set(STATIC_LIBNDPI_INSTALLDIR "" CACHE STRING "Path to a installation directory of libnDPI e.g. /opt/libnDPI/usr")
set(CROSS_COMPILE_TRIPLET "" CACHE STRING "Host triplet used to enable cross compiling.")

add_executable(nDPId nDPId.c utils.c)
add_executable(nDPIsrvd nDPIsrvd.c utils.c)
add_executable(nDPId-test nDPId-test.c utils.c)

add_custom_target(daemon)
add_custom_command(
    TARGET  daemon
    COMMAND "${CMAKE_SOURCE_DIR}/scripts/daemon.sh" "$<TARGET_FILE:nDPId>" "$<TARGET_FILE:nDPIsrvd>"
    DEPENDS nDPId nDPIsrvd
)

if(NOT CROSS_COMPILE_TRIPLET STREQUAL "")
    set(CMAKE_C_COMPILER_TARGET ${CROSS_COMPILE_TRIPLET})
    set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
    set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
    set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
    set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
endif()

if(BUILD_NDPI)
    message(WARNING "Building nDPI from source is an experimental feature "
                    "used for development/testing purposes.\n"
                    "The build process may fail at any time.")
    enable_testing()
    add_test(NAME run_tests
             COMMAND "${CMAKE_SOURCE_DIR}/test/run_tests.sh"
                     "${CMAKE_SOURCE_DIR}/libnDPI"
                     "$<TARGET_FILE:nDPId-test>")
endif()

execute_process(
    COMMAND git describe --tags
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    OUTPUT_VARIABLE GIT_VERSION ERROR_QUIET)
string(STRIP "${GIT_VERSION}" GIT_VERSION)
if(GIT_VERSION STREQUAL "" OR NOT IS_DIRECTORY "${CMAKE_SOURCE_DIR}/.git")
    if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "")
        set(GIT_VERSION "1.5-pre")
    else()
        set(GIT_VERSION "1.5-release")
    endif()
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(NDPID_DEFS -DJSMN_STATIC=1 -DJSMN_STRICT=1)
if(ENABLE_MEMORY_PROFILING)
    add_definitions("-DENABLE_MEMORY_PROFILING=1"
                    "-Duthash_malloc=nDPIsrvd_uthash_malloc"
                    "-Duthash_free=nDPIsrvd_uthash_free")
endif()

if(ENABLE_ZLIB)
    set(ZLIB_DEFS "-DENABLE_ZLIB=1")
    pkg_check_modules(ZLIB REQUIRED zlib)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g3 -fno-omit-frame-pointer -fno-inline")
endif()

if(ENABLE_SANITIZER AND ENABLE_SANITIZER_THREAD)
    message(STATUS_FATAL "ENABLE_SANITIZER and ENABLE_SANITIZER_THREAD can not be used together!")
endif()

if(ENABLE_SANITIZER)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize=undefined -fno-sanitize=alignment -fsanitize=enum -fsanitize=leak")
endif()

if(ENABLE_SANITIZER_THREAD)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=undefined -fno-sanitize=alignment -fsanitize=enum -fsanitize=thread")
endif()

if(STATIC_LIBNDPI_INSTALLDIR STREQUAL "" AND BUILD_NDPI)
    include(ExternalProject)
    ExternalProject_Add(
        libnDPI
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libnDPI
        DOWNLOAD_COMMAND ""
        CONFIGURE_COMMAND env
            CFLAGS=${CMAKE_C_FLAGS}
            LDFLAGS=${CMAKE_MODULE_LINKER_FLAGS}
            CROSS_COMPILE_TRIPLET=${CROSS_COMPILE_TRIPLET}
            MAKE_PROGRAM=make
            DEST_INSTALL=${CMAKE_BINARY_DIR}/libnDPI
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/get-and-build-libndpi.sh
        BUILD_BYPRODUCTS ${CMAKE_BINARY_DIR}/libnDPI/lib/libndpi.a
        BUILD_COMMAND ""
        INSTALL_COMMAND ""
        BUILD_IN_SOURCE 1)

    add_custom_target(clean-libnDPI
        COMMAND rm -rf ${CMAKE_BINARY_DIR}/libnDPI ${CMAKE_BINARY_DIR}/libnDPI-prefix
    )

    set(STATIC_LIBNDPI_INSTALLDIR "${CMAKE_BINARY_DIR}/libnDPI")
    add_dependencies(nDPId libnDPI)
    add_dependencies(nDPId-test libnDPI)
endif()

if(NOT STATIC_LIBNDPI_INSTALLDIR STREQUAL "" OR BUILD_NDPI OR NDPI_NO_PKGCONFIG)
    option(NDPI_WITH_GCRYPT "Link static libndpi library against libgcrypt." ON)
    option(NDPI_WITH_PCRE "Link static libndpi library against libpcre." OFF)
    option(NDPI_WITH_MAXMINDDB "Link static libndpi library against libmaxminddb." OFF)

    if(NDPI_WITH_GCRYPT)
        find_package(GCRYPT "1.4.2" REQUIRED)
    endif()

    if(NDPI_WITH_PCRE)
        pkg_check_modules(PCRE REQUIRED libpcre>=8.39)
    endif()

    if(NDPI_WITH_MAXMINDDB)
        pkg_check_modules(MAXMINDDB REQUIRED libmaxminddb)
    endif()
endif()

if(NOT STATIC_LIBNDPI_INSTALLDIR STREQUAL "" OR BUILD_NDPI)
    set(STATIC_LIBNDPI_INC "${STATIC_LIBNDPI_INSTALLDIR}/include/ndpi")
    set(STATIC_LIBNDPI_LIB "${STATIC_LIBNDPI_INSTALLDIR}/lib/libndpi.a")
else()
    if(NOT NDPI_NO_PKGCONFIG)
        pkg_check_modules(NDPI REQUIRED libndpi>=3.5.0)

        set(STATIC_LIBNDPI_INC "")
        set(STATIC_LIBNDPI_LIB "")
    else()
        set(LIBNDPI_INC "" CACHE STRING "/usr/include/ndpi")
        set(LIBNDPI_LIB "" CACHE STRING "/usr/lib/libndpi.a")

        set(STATIC_LIBNDPI_INC "${LIBNDPI_INC}")
        set(STATIC_LIBNDPI_LIB "${LIBNDPI_LIB}")
    endif()
endif()

find_package(PCAP "1.8.1" REQUIRED)
target_compile_options(nDPId PRIVATE "-pthread")
target_compile_definitions(nDPId PRIVATE -DGIT_VERSION=\"${GIT_VERSION}\" ${NDPID_DEFS} ${ZLIB_DEFS})
target_include_directories(nDPId PRIVATE "${STATIC_LIBNDPI_INC}" "${NDPI_INCLUDEDIR}" "${NDPI_INCLUDEDIR}/ndpi")
target_link_libraries(nDPId "${STATIC_LIBNDPI_LIB}" "${pkgcfg_lib_NDPI_ndpi}"
                            "${pkgcfg_lib_PCRE_pcre}" "${pkgcfg_lib_MAXMINDDB_maxminddb}" "${pkgcfg_lib_ZLIB_z}"
                            "${GCRYPT_LIBRARY}" "${GCRYPT_ERROR_LIBRARY}" "${PCAP_LIBRARY}"
                            "-pthread")

target_compile_definitions(nDPIsrvd PRIVATE -DGIT_VERSION=\"${GIT_VERSION}\" ${NDPID_DEFS})
target_include_directories(nDPIsrvd PRIVATE
                           "${CMAKE_SOURCE_DIR}"
                           "${CMAKE_SOURCE_DIR}/dependencies"
                           "${CMAKE_SOURCE_DIR}/dependencies/jsmn"
                           "${CMAKE_SOURCE_DIR}/dependencies/uthash/src")

target_include_directories(nDPId-test PRIVATE
                           "${CMAKE_SOURCE_DIR}"
                           "${CMAKE_SOURCE_DIR}/dependencies"
                           "${CMAKE_SOURCE_DIR}/dependencies/jsmn"
                           "${CMAKE_SOURCE_DIR}/dependencies/uthash/src")
target_compile_options(nDPId-test PRIVATE "-Wno-unused-function" "-pthread")
target_compile_definitions(nDPId-test PRIVATE ${NDPID_DEFS} ${ZLIB_DEFS})
target_include_directories(nDPId-test PRIVATE "${STATIC_LIBNDPI_INC}" "${NDPI_INCLUDEDIR}" "${NDPI_INCLUDEDIR}/ndpi")
target_compile_definitions(nDPId-test PRIVATE "-D_GNU_SOURCE=1" "-DNO_MAIN=1" "-Dsyslog=mock_syslog_stderr")
target_link_libraries(nDPId-test "${STATIC_LIBNDPI_LIB}" "${pkgcfg_lib_NDPI_ndpi}"
                                 "${pkgcfg_lib_PCRE_pcre}" "${pkgcfg_lib_MAXMINDDB_maxminddb}" "${pkgcfg_lib_ZLIB_z}"
                                 "${GCRYPT_LIBRARY}" "${GCRYPT_ERROR_LIBRARY}" "${PCAP_LIBRARY}"
                                 "-pthread")

if(BUILD_EXAMPLES)
    add_executable(nDPIsrvd-collectd examples/c-collectd/c-collectd.c)
    target_compile_definitions(nDPIsrvd-collectd PRIVATE ${NDPID_DEFS})
    target_include_directories(nDPIsrvd-collectd PRIVATE
                               "${CMAKE_SOURCE_DIR}"
                               "${CMAKE_SOURCE_DIR}/dependencies"
                               "${CMAKE_SOURCE_DIR}/dependencies/jsmn"
                               "${CMAKE_SOURCE_DIR}/dependencies/uthash/src")

    add_executable(nDPIsrvd-captured examples/c-captured/c-captured.c utils.c)
    target_compile_definitions(nDPIsrvd-captured PRIVATE ${NDPID_DEFS})
    target_include_directories(nDPIsrvd-captured PRIVATE
                               "${CMAKE_SOURCE_DIR}"
                               "${CMAKE_SOURCE_DIR}/dependencies"
                               "${CMAKE_SOURCE_DIR}/dependencies/jsmn"
                               "${CMAKE_SOURCE_DIR}/dependencies/uthash/src")
    target_link_libraries(nDPIsrvd-captured "${PCAP_LIBRARY}")

    add_executable(nDPIsrvd-json-dump examples/c-json-stdout/c-json-stdout.c)
    target_include_directories(nDPIsrvd-json-dump PRIVATE
                               "${CMAKE_SOURCE_DIR}"
                               "${CMAKE_SOURCE_DIR}/dependencies/jsmn")

    install(TARGETS nDPIsrvd-collectd nDPIsrvd-captured nDPIsrvd-json-dump DESTINATION bin)
endif()

install(TARGETS nDPId DESTINATION sbin)
install(TARGETS nDPIsrvd nDPId-test DESTINATION bin)
install(FILES dependencies/nDPIsrvd.py DESTINATION share/nDPId)
install(FILES examples/py-flow-info/flow-info.py DESTINATION bin RENAME nDPIsrvd-flow-info.py)

message(STATUS "--------------------------")
message(STATUS "nDPId GIT_VERSION........: ${GIT_VERSION}")
message(STATUS "CROSS_COMPILE_TRIPLET....: ${CROSS_COMPILE_TRIPLET}")
message(STATUS "CMAKE_BUILD_TYPE.........: ${CMAKE_BUILD_TYPE}")
message(STATUS "CMAKE_C_FLAGS............: ${CMAKE_C_FLAGS}")
message(STATUS "NDPID_DEFS...............: ${NDPID_DEFS}")
message(STATUS "ENABLE_SANITIZER.........: ${ENABLE_SANITIZER}")
message(STATUS "ENABLE_SANITIZER_THREAD..: ${ENABLE_SANITIZER_THREAD}")
message(STATUS "ENABLE_MEMORY_PROFILING..: ${ENABLE_MEMORY_PROFILING}")
message(STATUS "ENABLE_ZLIB..............: ${ENABLE_ZLIB}")
if(NOT BUILD_NDPI AND NOT STATIC_LIBNDPI_INSTALLDIR STREQUAL "")
message(STATUS "STATIC_LIBNDPI_INSTALLDIR: ${STATIC_LIBNDPI_INSTALLDIR}")
endif()
message(STATUS "BUILD_NDPI...............: ${BUILD_NDPI}")
message(STATUS "NDPI_NO_PKGCONFIG........: ${NDPI_NO_PKGCONFIG}")
if(NDPI_NO_PKGCONFIG)
message(STATUS "LIBNDPI_INC..............: ${LIBNDPI_INC}")
message(STATUS "LIBNDPI_LIB..............: ${LIBNDPI_LIB}")
endif()
if(NOT STATIC_LIBNDPI_INSTALLDIR STREQUAL "" OR BUILD_NDPI OR NDPI_NO_PKGCONFIG)
message(STATUS "--------------------------")
message(STATUS "- STATIC_LIBNDPI_INC....: ${STATIC_LIBNDPI_INC}")
message(STATUS "- STATIC_LIBNDPI_LIB....: ${STATIC_LIBNDPI_LIB}")
message(STATUS "- NDPI_WITH_GCRYPT......: ${NDPI_WITH_GCRYPT}")
message(STATUS "- NDPI_WITH_PCRE........: ${NDPI_WITH_PCRE}")
message(STATUS "- NDPI_WITH_MAXMINDDB...: ${NDPI_WITH_MAXMINDDB}")
endif()
message(STATUS "--------------------------")
