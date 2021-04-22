cmake_minimum_required(VERSION 3.12.4)
project(nDPId C)
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
find_package(PkgConfig REQUIRED)

option(ENABLE_SANITIZER "Enable ASAN/LSAN/UBSAN." OFF)
option(ENABLE_SANITIZER_THREAD "Enable TSAN (does not work together with ASAN)." OFF)
option(ENABLE_MEMORY_PROFILING "Enable dynamic memory tracking." OFF)
option(BUILD_EXAMPLES "Build C examples." ON)
option(BUILD_NDPI "Clone and build nDPI from github." OFF)

set(STATIC_LIBNDPI_INSTALLDIR "" CACHE STRING "Path to a installation directory of libnDPI e.g. /opt/libnDPI/usr")

add_executable(nDPId nDPId.c utils.c)
add_executable(nDPIsrvd nDPIsrvd.c utils.c)
add_executable(nDPId-test nDPId-test.c utils.c)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -DJSMN_STATIC=1 -DJSMN_STRICT=1")
set(BUILD_NDPI_CONFIGURE_OPTS "")

if(ENABLE_MEMORY_PROFILING)
    set(MEMORY_PROFILING_CFLAGS "-DENABLE_MEMORY_PROFILING=1"
                                "-Duthash_malloc=nDPIsrvd_uthash_malloc"
                                "-Duthash_free=nDPIsrvd_uthash_free")
else()
    set(MEMORY_PROFILING_CFLAGS "")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g3 -fno-omit-frame-pointer -fno-inline")
endif()

if(ENABLE_SANITIZER AND ENABLE_SANITIZER_THREAD)
    message(STATUS_FATAL "ENABLE_SANITIZER and ENABLE_SANITIZER_THREAD can not be used together!")
endif()

if(ENABLE_SANITIZER)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize=undefined -fsanitize=enum -fsanitize=leak")
    set(BUILD_NDPI_CONFIGURE_OPTS "${BUILD_NDPI_CONFIGURE_OPTS} --with-sanitizer")
endif()

if(ENABLE_SANITIZER_THREAD)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=undefined -fsanitize=enum -fsanitize=thread")
endif()

if(BUILD_NDPI)
    include(ExternalProject)
    ExternalProject_Add(
        libnDPI
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libnDPI
        CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/libnDPI/autogen.sh
                          --prefix=${CMAKE_CURRENT_BINARY_DIR}/libnDPI
                          ${BUILD_NDPI_CONFIGURE_OPTS}
        BUILD_COMMAND make
        BUILD_IN_SOURCE 1)

    set(STATIC_LIBNDPI_INSTALLDIR "${CMAKE_BINARY_DIR}/libnDPI")
    add_dependencies(nDPId libnDPI)
    add_dependencies(nDPId-test libnDPI)
endif()

if(NOT STATIC_LIBNDPI_INSTALLDIR STREQUAL "" OR BUILD_NDPI)
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

    set(STATIC_LIBNDPI_INC "${STATIC_LIBNDPI_INSTALLDIR}/include/ndpi")
    set(STATIC_LIBNDPI_LIB "${STATIC_LIBNDPI_INSTALLDIR}/lib/libndpi.a")
else()
    pkg_check_modules(NDPI REQUIRED libndpi>=3.5.0)
    set(STATIC_LIBNDPI_INC "")
    set(STATIC_LIBNDPI_LIB "")
endif()

find_package(PCAP "1.8.1" REQUIRED)
target_compile_options(nDPId PRIVATE ${MEMORY_PROFILING_CFLAGS} "-pthread")
target_include_directories(nDPId PRIVATE "${STATIC_LIBNDPI_INC}" "${NDPI_INCLUDEDIR}" "${NDPI_INCLUDEDIR}/ndpi")
target_link_libraries(nDPId "${STATIC_LIBNDPI_LIB}" "${pkgcfg_lib_NDPI_ndpi}"
                            "${pkgcfg_lib_PCRE_pcre}" "${pkgcfg_lib_MAXMINDDB_maxminddb}"
                            "${GCRYPT_LIBRARY}" "${PCAP_LIBRARY}"
                            "-pthread")

target_compile_options(nDPId PRIVATE ${MEMORY_PROFILING_CFLAGS})
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
target_compile_options(nDPId-test PRIVATE ${MEMORY_PROFILING_CFLAGS} "-Wno-unused-function" "-pthread")
target_include_directories(nDPId-test PRIVATE "${STATIC_LIBNDPI_INC}" "${NDPI_INCLUDEDIR}" "${NDPI_INCLUDEDIR}/ndpi")
target_compile_definitions(nDPId-test PRIVATE "-D_GNU_SOURCE=1" "-DNO_MAIN=1" "-Dsyslog=mock_syslog_stderr")
target_link_libraries(nDPId-test "${STATIC_LIBNDPI_LIB}" "${pkgcfg_lib_NDPI_ndpi}"
                                 "${pkgcfg_lib_PCRE_pcre}" "${pkgcfg_lib_MAXMINDDB_maxminddb}"
                                 "${GCRYPT_LIBRARY}" "${PCAP_LIBRARY}"
                                 "-pthread")

if(BUILD_EXAMPLES)
    add_executable(nDPIsrvd-collectd examples/c-collectd/c-collectd.c)
    target_compile_options(nDPIsrvd-collectd PRIVATE ${MEMORY_PROFILING_CFLAGS})
    target_include_directories(nDPIsrvd-collectd PRIVATE
                               "${CMAKE_SOURCE_DIR}"
                               "${CMAKE_SOURCE_DIR}/dependencies"
                               "${CMAKE_SOURCE_DIR}/dependencies/jsmn"
                               "${CMAKE_SOURCE_DIR}/dependencies/uthash/src")

    add_executable(nDPIsrvd-captured examples/c-captured/c-captured.c utils.c)
    target_compile_options(nDPIsrvd-captured PRIVATE ${MEMORY_PROFILING_CFLAGS})
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
message(STATUS "CMAKE_BUILD_TYPE.........: ${CMAKE_BUILD_TYPE}")
message(STATUS "CMAKE_C_FLAGS............: ${CMAKE_C_FLAGS}")
if(ENABLE_MEMORY_PROFILING)
message(STATUS "MEMORY_PROFILING_CFLAGS..: ${MEMORY_PROFILING_CFLAGS}")
endif()
message(STATUS "ENABLE_SANITIZER.........: ${ENABLE_SANITIZER}")
message(STATUS "ENABLE_SANITIZER_THREAD..: ${ENABLE_SANITIZER_THREAD}")
message(STATUS "ENABLE_MEMORY_PROFILING..: ${ENABLE_MEMORY_PROFILING}")
if(NOT BUILD_NDPI)
message(STATUS "STATIC_LIBNDPI_INSTALLDIR: ${STATIC_LIBNDPI_INSTALLDIR}")
if(NOT STATIC_LIBNDPI_INSTALLDIR STREQUAL "")
message(STATUS "`- STATIC_LIBNDPI_INC....: ${STATIC_LIBNDPI_INC}")
message(STATUS "`- STATIC_LIBNDPI_LIB....: ${STATIC_LIBNDPI_LIB}")
message(STATUS "`- NDPI_WITH_GCRYPT......: ${NDPI_WITH_GCRYPT}")
message(STATUS "`- NDPI_WITH_PCRE........: ${NDPI_WITH_PCRE}")
message(STATUS "`- NDPI_WITH_MAXMINDDB...: ${NDPI_WITH_MAXMINDDB}")
endif()
endif()
message(STATUS "BUILD_NDPI...............: ${BUILD_NDPI}")
message(STATUS "--------------------------")
