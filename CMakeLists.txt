cmake_minimum_required(VERSION 3.12.4)
project(nDPId C)
if("${PROJECT_SOURCE_DIR}" STREQUAL "${PROJECT_BINARY_DIR}")
    message(FATAL_ERROR "In-source builds are not allowed.\n"
                        "Please remove ${PROJECT_SOURCE_DIR}/CMakeCache.txt\n"
                        "and\n"
                        "${PROJECT_SOURCE_DIR}/CMakeFiles\n"
                        "Create a build directory somewhere and run CMake again.")
endif()
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
find_package(PkgConfig REQUIRED)

set(CPACK_PACKAGE_CONTACT "toni@impl.cc")
set(CPACK_DEBIAN_PACKAGE_NAME "nDPId")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_PACKAGE_VERSION_MAJOR 1)
set(CPACK_PACKAGE_VERSION_MINOR 5)
set(CPACK_PACKAGE_VERSION_PATCH 0)

include(CPack)
include(CheckFunctionExists)

if(NOT MATH_FUNCTION_EXISTS AND NOT NEED_LINKING_AGAINST_LIBM)
    CHECK_FUNCTION_EXISTS(log2f MATH_FUNCTION_EXISTS)
    if(NOT MATH_FUNCTION_EXISTS)
        unset(MATH_FUNCTION_EXISTS CACHE)
      list(APPEND CMAKE_REQUIRED_LIBRARIES m)
      CHECK_FUNCTION_EXISTS(log2f MATH_FUNCTION_EXISTS)
      if(MATH_FUNCTION_EXISTS)
          set(NEED_LINKING_AGAINST_LIBM TRUE CACHE BOOL "" FORCE)
      else()
          message(FATAL_ERROR "Failed making the log2f() function available")
      endif()
  endif()
endif()

if(NEED_LINKING_AGAINST_LIBM)
    set(LIBM_LIB "-lm")
else()
    set(LIBM_LIB "")
endif()

option(ENABLE_COVERAGE "Generate a code coverage report using lcov/genhtml." OFF)
option(ENABLE_SANITIZER "Enable ASAN/LSAN/UBSAN." OFF)
option(ENABLE_SANITIZER_THREAD "Enable TSAN (does not work together with ASAN)." OFF)
option(ENABLE_MEMORY_PROFILING "Enable dynamic memory tracking." OFF)
option(ENABLE_ZLIB "Enable zlib support for nDPId (experimental)." OFF)
option(BUILD_EXAMPLES "Build C examples." ON)
option(BUILD_NDPI "Clone and build nDPI from github." OFF)
if(BUILD_NDPI)
    unset(NDPI_NO_PKGCONFIG CACHE)
    unset(STATIC_LIBNDPI_INSTALLDIR CACHE)
else()
    option(NDPI_NO_PKGCONFIG "Do not use pkgconfig to search for libnDPI." OFF)
    if(NDPI_NO_PKGCONFIG)
        set(STATIC_LIBNDPI_INSTALLDIR "/opt/libnDPI/usr" CACHE STRING "Path to a installation directory of libnDPI e.g. /opt/libnDPI/usr")
        if(STATIC_LIBNDPI_INSTALLDIR STREQUAL "")
            message(FATAL_ERROR "STATIC_LIBNDPI_INSTALLDIR can not be an empty string within your configuration!")
        endif()
    else()
        unset(STATIC_LIBNDPI_INSTALLDIR CACHE)
    endif()
endif()

if(STATIC_LIBNDPI_INSTALLDIR OR BUILD_NDPI OR NDPI_NO_PKGCONFIG)
    option(NDPI_WITH_GCRYPT "Link static libndpi library against libgcrypt." ON)
    option(NDPI_WITH_PCRE "Link static libndpi library against libpcre." OFF)
    option(NDPI_WITH_MAXMINDDB "Link static libndpi library against libmaxminddb." OFF)
else()
    unset(NDPI_WITH_GCRYPT CACHE)
    unset(NDPI_WITH_PCRE CACHE)
    unset(NDPI_WITH_MAXMINDDB CACHE)
endif()

set(CROSS_COMPILE_TRIPLET "" CACHE STRING "Host triplet used to enable cross compiling.")

add_executable(nDPId nDPId.c utils.c)
add_executable(nDPIsrvd nDPIsrvd.c utils.c)
add_executable(nDPId-test nDPId-test.c)

add_custom_target(dist)
add_custom_command(
    TARGET dist
    COMMAND "${CMAKE_SOURCE_DIR}/scripts/make-dist.sh"
)

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

if(BUILD_NDPI AND NDPI_WITH_GCRYPT)
    enable_testing()
    add_test(NAME run_tests
             COMMAND "${CMAKE_SOURCE_DIR}/test/run_tests.sh"
                     "${CMAKE_SOURCE_DIR}/libnDPI"
                     "$<TARGET_FILE:nDPId-test>")
    if(NDPI_WITH_PCRE OR NDPI_WITH_MAXMINDDB)
        message(WARNING "NDPI_WITH_PCRE or NDPI_WITH_MAXMINDDB enabled.\n"
                        "${CMAKE_CURRENT_SOURCE_DIR}/test/run_tests.sh or ctest will fail!")
    endif()
endif()

if(ENABLE_COVERAGE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
    set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} --coverage")
    add_custom_target(coverage)
    add_custom_command(
        TARGET  coverage
        COMMAND "${CMAKE_SOURCE_DIR}/scripts/code-coverage.sh"
        DEPENDS nDPId nDPIsrvd nDPId-test
    )
endif()
if(ENABLE_SANITIZER)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize=undefined -fno-sanitize=alignment -fsanitize=enum -fsanitize=leak")
endif()
if(ENABLE_SANITIZER_THREAD)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=undefined -fno-sanitize=alignment -fsanitize=enum -fsanitize=thread")
endif()
if(ENABLE_ZLIB)
    set(ZLIB_DEFS "-DENABLE_ZLIB=1")
    pkg_check_modules(ZLIB REQUIRED zlib)
endif()
if(NDPI_WITH_GCRYPT)
    message(STATUS "Enable GCRYPT")
else()
    set(NDPI_ADDITIONAL_ARGS "${NDPI_ADDITIONAL_ARGS} --disable-gcrypt")
endif()
if(NDPI_WITH_PCRE)
    message(STATUS "Enable PCRE")
    set(NDPI_ADDITIONAL_ARGS "${NDPI_ADDITIONAL_ARGS} --with-pcre")
endif()
if(NDPI_WITH_MAXMINDDB)
    message(STATUS "Enable MAXMINDDB")
    set(NDPI_ADDITIONAL_ARGS "${NDPI_ADDITIONAL_ARGS} --with-maxminddb")
endif()

execute_process(
    COMMAND git describe --tags
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    OUTPUT_VARIABLE GIT_VERSION ERROR_QUIET)
string(STRIP "${GIT_VERSION}" GIT_VERSION)
if(GIT_VERSION STREQUAL "" OR NOT IS_DIRECTORY "${CMAKE_SOURCE_DIR}/.git")
    if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "")
        set(GIT_VERSION "${CPACK_PACKAGE_VERSION}-pre")
    else()
        set(GIT_VERSION "${CPACK_PACKAGE_VERSION}-release")
    endif()
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(NDPID_DEFS -DJSMN_STATIC=1 -DJSMN_STRICT=1 -DJSMN_PARENT_LINKS=1)
if(ENABLE_MEMORY_PROFILING)
    message(WARNING "ENABLE_MEMORY_PROFILING should not be used in production environments.")
    add_definitions("-DENABLE_MEMORY_PROFILING=1"
                    "-Duthash_malloc=nDPIsrvd_uthash_malloc"
                    "-Duthash_free=nDPIsrvd_uthash_free")
else()
    set(NDPID_TEST_MPROF_DEFS "-DENABLE_MEMORY_PROFILING=1")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g3 -fno-omit-frame-pointer -fno-inline")
endif()

if(ENABLE_SANITIZER AND ENABLE_SANITIZER_THREAD)
    message(FATAL_ERROR "ENABLE_SANITIZER and ENABLE_SANITIZER_THREAD can not be used together!")
endif()

if(BUILD_NDPI)
    include(ExternalProject)
    ExternalProject_Add(
        libnDPI
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libnDPI
        DOWNLOAD_COMMAND ""
        CONFIGURE_COMMAND env
            CFLAGS=${CMAKE_C_FLAGS}
            LDFLAGS=${CMAKE_MODULE_LINKER_FLAGS}
            CROSS_COMPILE_TRIPLET=${CROSS_COMPILE_TRIPLET}
            ADDITIONAL_ARGS=${NDPI_ADDITIONAL_ARGS}
            MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM}
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

if(STATIC_LIBNDPI_INSTALLDIR OR BUILD_NDPI OR NDPI_NO_PKGCONFIG)
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

if(STATIC_LIBNDPI_INSTALLDIR OR BUILD_NDPI)
    add_definitions("-DLIBNDPI_STATIC=1")
    set(STATIC_LIBNDPI_INC "${STATIC_LIBNDPI_INSTALLDIR}/include/ndpi")
    set(STATIC_LIBNDPI_LIB "${STATIC_LIBNDPI_INSTALLDIR}/lib/libndpi.a")

    if(STATIC_LIBNDPI_INSTALLDIR AND NOT BUILD_NDPI)
        if(NOT EXISTS "${STATIC_LIBNDPI_INC}" OR NOT EXISTS "${STATIC_LIBNDPI_LIB}")
            message(FATAL_ERROR "Include directory \"${STATIC_LIBNDPI_INC}\" or\n"
                                "static library \"${STATIC_LIBNDPI_LIB}\" does not exist!")
        endif()
    endif()
else()
    if(NOT NDPI_NO_PKGCONFIG)
        pkg_check_modules(NDPI REQUIRED libndpi>=3.5.0)

        unset(STATIC_LIBNDPI_INC CACHE)
        unset(STATIC_LIBNDPI_LIB CACHE)
    endif()
endif()

find_package(PCAP "1.8.1" REQUIRED)

target_compile_options(nDPId PRIVATE "-pthread")
target_compile_definitions(nDPId PRIVATE -D_GNU_SOURCE=1 -DGIT_VERSION=\"${GIT_VERSION}\" ${NDPID_DEFS} ${ZLIB_DEFS})
target_include_directories(nDPId PRIVATE
                           "${STATIC_LIBNDPI_INC}" "${NDPI_INCLUDEDIR}" "${NDPI_INCLUDEDIR}/ndpi")
target_link_libraries(nDPId "${STATIC_LIBNDPI_LIB}" "${pkgcfg_lib_NDPI_ndpi}"
                            "${pkgcfg_lib_PCRE_pcre}" "${pkgcfg_lib_MAXMINDDB_maxminddb}" "${pkgcfg_lib_ZLIB_z}"
                            "${GCRYPT_LIBRARY}" "${GCRYPT_ERROR_LIBRARY}" "${PCAP_LIBRARY}" "${LIBM_LIB}"
                            "-pthread")

target_compile_definitions(nDPIsrvd PRIVATE -D_GNU_SOURCE=1 -DGIT_VERSION=\"${GIT_VERSION}\" ${NDPID_DEFS})
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
target_compile_definitions(nDPId-test PRIVATE -D_GNU_SOURCE=1 -DNO_MAIN=1 -DGIT_VERSION=\"${GIT_VERSION}\"
                                              ${NDPID_DEFS} ${ZLIB_DEFS} ${NDPID_TEST_MPROF_DEFS})
target_include_directories(nDPId-test PRIVATE
                           "${STATIC_LIBNDPI_INC}" "${NDPI_INCLUDEDIR}" "${NDPI_INCLUDEDIR}/ndpi"
                           "${CMAKE_SOURCE_DIR}/dependencies/uthash/src")
target_link_libraries(nDPId-test "${STATIC_LIBNDPI_LIB}" "${pkgcfg_lib_NDPI_ndpi}"
                                 "${pkgcfg_lib_PCRE_pcre}" "${pkgcfg_lib_MAXMINDDB_maxminddb}" "${pkgcfg_lib_ZLIB_z}"
                                 "${GCRYPT_LIBRARY}" "${GCRYPT_ERROR_LIBRARY}" "${PCAP_LIBRARY}" "${LIBM_LIB}"
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
    if(BUILD_NDPI)
        add_dependencies(nDPIsrvd-captured libnDPI)
    endif()
    target_compile_definitions(nDPIsrvd-captured PRIVATE ${NDPID_DEFS})
    target_include_directories(nDPIsrvd-captured PRIVATE
                               "${STATIC_LIBNDPI_INC}" "${NDPI_INCLUDEDIR}" "${NDPI_INCLUDEDIR}/ndpi"
                               "${CMAKE_SOURCE_DIR}"
                               "${CMAKE_SOURCE_DIR}/dependencies"
                               "${CMAKE_SOURCE_DIR}/dependencies/jsmn"
                               "${CMAKE_SOURCE_DIR}/dependencies/uthash/src")
    target_link_libraries(nDPIsrvd-captured "${pkgcfg_lib_NDPI_ndpi}"
                                            "${pkgcfg_lib_PCRE_pcre}" "${pkgcfg_lib_MAXMINDDB_maxminddb}"
                                            "${GCRYPT_LIBRARY}" "${GCRYPT_ERROR_LIBRARY}" "${PCAP_LIBRARY}")

    add_executable(nDPIsrvd-json-dump examples/c-json-stdout/c-json-stdout.c)
    target_compile_definitions(nDPIsrvd-json-dump PRIVATE ${NDPID_DEFS})
    target_include_directories(nDPIsrvd-json-dump PRIVATE
                               "${CMAKE_SOURCE_DIR}"
                               "${CMAKE_SOURCE_DIR}/dependencies/jsmn")

    add_executable(nDPIsrvd-simple examples/c-simple/c-simple.c)
    target_compile_definitions(nDPIsrvd-simple PRIVATE ${NDPID_DEFS})
    target_include_directories(nDPIsrvd-simple PRIVATE
                               "${CMAKE_SOURCE_DIR}"
                               "${CMAKE_SOURCE_DIR}/dependencies"
                               "${CMAKE_SOURCE_DIR}/dependencies/jsmn"
                               "${CMAKE_SOURCE_DIR}/dependencies/uthash/src")
    target_link_libraries(nDPIsrvd-simple "${pkgcfg_lib_NDPI_ndpi}"
                                          "${pkgcfg_lib_PCRE_pcre}" "${pkgcfg_lib_MAXMINDDB_maxminddb}"
                                          "${GCRYPT_LIBRARY}" "${GCRYPT_ERROR_LIBRARY}" "${PCAP_LIBRARY}")

    if(ENABLE_COVERAGE)
        add_dependencies(coverage nDPIsrvd-collectd nDPIsrvd-captured nDPIsrvd-json-dump nDPIsrvd-simple)
    endif()

    install(TARGETS nDPIsrvd-collectd nDPIsrvd-captured nDPIsrvd-json-dump nDPIsrvd-simple DESTINATION bin)
endif()

install(TARGETS nDPId DESTINATION sbin)
install(TARGETS nDPIsrvd nDPId-test DESTINATION bin)
install(FILES dependencies/nDPIsrvd.py examples/py-flow-dashboard/plotly_dash.py
        DESTINATION share/nDPId)
install(FILES examples/py-flow-info/flow-info.py
        DESTINATION bin RENAME nDPIsrvd-flow-info.py
        PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
install(FILES examples/py-flow-dashboard/flow-dash.py
        DESTINATION bin RENAME nDPIsrvd-flow-dash.py
        PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
install(FILES examples/py-ja3-checker/py-ja3-checker.py
        DESTINATION bin RENAME nDPIsrvd-ja3-checker.py
        PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
install(FILES examples/py-json-stdout/json-stdout.py
        DESTINATION bin RENAME nDPIsrvd-json-stdout.py
        PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
install(FILES examples/py-schema-validation/py-schema-validation.py
        DESTINATION bin RENAME nDPIsrvd-schema-validation.py
        PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
install(FILES examples/py-semantic-validation/py-semantic-validation.py
        DESTINATION bin RENAME nDPIsrvd-semantic-validation.py
        PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
install(FILES schema/error_event_schema.json schema/daemon_event_schema.json
              schema/flow_event_schema.json schema/packet_event_schema.json DESTINATION share/nDPId)

message(STATUS "--------------------------")
message(STATUS "nDPId GIT_VERSION........: ${GIT_VERSION}")
message(STATUS "CROSS_COMPILE_TRIPLET....: ${CROSS_COMPILE_TRIPLET}")
message(STATUS "CMAKE_BUILD_TYPE.........: ${CMAKE_BUILD_TYPE}")
message(STATUS "CMAKE_C_FLAGS............: ${CMAKE_C_FLAGS}")
message(STATUS "NDPID_DEFS...............: ${NDPID_DEFS}")
message(STATUS "ENABLE_COVERAGE..........: ${ENABLE_COVERAGE}")
message(STATUS "ENABLE_SANITIZER.........: ${ENABLE_SANITIZER}")
message(STATUS "ENABLE_SANITIZER_THREAD..: ${ENABLE_SANITIZER_THREAD}")
message(STATUS "ENABLE_MEMORY_PROFILING..: ${ENABLE_MEMORY_PROFILING}")
message(STATUS "ENABLE_ZLIB..............: ${ENABLE_ZLIB}")
if(STATIC_LIBNDPI_INSTALLDIR)
message(STATUS "STATIC_LIBNDPI_INSTALLDIR: ${STATIC_LIBNDPI_INSTALLDIR}")
endif()
message(STATUS "BUILD_NDPI...............: ${BUILD_NDPI}")
if(BUILD_NDPI)
message(STATUS "NDPI_ADDITIONAL_ARGS.....: ${NDPI_ADDITIONAL_ARGS}")
endif()
message(STATUS "NDPI_NO_PKGCONFIG........: ${NDPI_NO_PKGCONFIG}")
if(STATIC_LIBNDPI_INSTALLDIR OR BUILD_NDPI OR NDPI_NO_PKGCONFIG)
message(STATUS "--------------------------")
message(STATUS "- STATIC_LIBNDPI_INC....: ${STATIC_LIBNDPI_INC}")
message(STATUS "- STATIC_LIBNDPI_LIB....: ${STATIC_LIBNDPI_LIB}")
message(STATUS "- NDPI_WITH_GCRYPT......: ${NDPI_WITH_GCRYPT}")
message(STATUS "- NDPI_WITH_PCRE........: ${NDPI_WITH_PCRE}")
message(STATUS "- NDPI_WITH_MAXMINDDB...: ${NDPI_WITH_MAXMINDDB}")
endif()
message(STATUS "--------------------------")
