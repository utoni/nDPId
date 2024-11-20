cmake_minimum_required(VERSION 3.12.4)
project(nDPId C)
if(CMAKE_COMPILER_IS_GNUCXX)
    execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpversion OUTPUT_VARIABLE GCC_VERSION)
    if (GCC_VERSION VERSION_GREATER 4.7 OR GCC_VERSION VERSION_EQUAL 4.7)
        message(STATUS "${CMAKE_C_COMPILER} supports C11 standard.")
   else ()
        message(FATAL_ERROR "C Compiler with C11 standard needed. Therefore a gcc compiler with a version equal or higher than 4.7 is needed.")
   endif()
endif(CMAKE_COMPILER_IS_GNUCXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -D_DEFAULT_SOURCE=1 -D_GNU_SOURCE=1")
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
set(CPACK_DEBIAN_PACKAGE_SECTION "network")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "nDPId is a set of daemons and tools to capture, process and classify network traffic.")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Toni Uhlig <toni@impl.cc>")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_SOURCE_DIR}/packages/debian/preinst;${CMAKE_SOURCE_DIR}/packages/debian/prerm;${CMAKE_SOURCE_DIR}/packages/debian/postrm")
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION TRUE)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_DEBUGINFO_PACKAGE ON)
set(CPACK_RPM_PACKAGE_LICENSE "GPL-3")
set(CPACK_RPM_PACKAGE_VENDOR "Toni Uhlig")
set(CPACK_RPM_PACKAGE_URL "https://www.github.com/utoni/nDPId.git")
set(CPACK_RPM_PACKAGE_DESCRIPTION "nDPId is a set of daemons and tools to capture, process and classify network traffic.")
set(CPACK_RPM_PRE_INSTALL_SCRIPT_FILE "${CMAKE_SOURCE_DIR}/packages/redhat/pre_install")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${CMAKE_SOURCE_DIR}/packages/redhat/pre_uninstall")
set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE "${CMAKE_SOURCE_DIR}/packages/redhat/post_uninstall")
set(CPACK_STRIP_FILES ON)
set(CPACK_PACKAGE_VERSION_MAJOR 1)
set(CPACK_PACKAGE_VERSION_MINOR 7)
set(CPACK_PACKAGE_VERSION_PATCH 0)
# Note: CPACK_PACKAGING_INSTALL_PREFIX and CMAKE_INSTALL_PREFIX are *not* the same.
# It is used only to ease environment file loading via systemd.
set(CPACK_PACKAGING_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")
set(CMAKE_MACOSX_RPATH 1)

include(CPack)
include(CheckFunctionExists)
include(CheckLibraryExists)
include(CheckEpoll)

check_epoll(HAS_EPOLL)
if(HAS_EPOLL)
    option(FORCE_POLL "Force the use of poll() instead of epoll()." OFF)
    if(NOT FORCE_POLL)
        set(EPOLL_DEFS "-DENABLE_EPOLL=1")
    endif()
else()
    if(BUILD_EXAMPLES)
        message(FATAL_ERROR "Examples are using epoll event I/O. Without epoll available, you can not build/run those.")
    endif()
endif()

if(NOT MATH_FUNCTION_EXISTS AND NOT NEED_LINKING_AGAINST_LIBM)
    CHECK_FUNCTION_EXISTS(log2f MATH_FUNCTION_EXISTS)
    if(NOT MATH_FUNCTION_EXISTS)
        unset(MATH_FUNCTION_EXISTS CACHE)
        list(APPEND CMAKE_REQUIRED_LIBRARIES m)
        CHECK_FUNCTION_EXISTS(log2f MATH_FUNCTION_EXISTS)
        if(MATH_FUNCTION_EXISTS)
            set(NEED_LINKING_AGAINST_LIBM TRUE CACHE BOOL "" FORCE)
        else()
            check_library_exists(m sqrt "" NEED_LINKING_AGAINST_LIBM)
            if(NOT NEED_LINKING_AGAINST_LIBM)
                # Was not able to figure out if explicit linkage against libm is required.
                # Forcing libm linkage. Good idea?
                set(NEED_LINKING_AGAINST_LIBM TRUE CACHE BOOL "" FORCE)
            endif()
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
option(ENABLE_SYSTEMD "Install systemd components." OFF)
option(BUILD_EXAMPLES "Build C examples." ON)
if(BUILD_EXAMPLES)
option(ENABLE_DBUS "Build DBus notification example." OFF)
option(ENABLE_CURL "Build influxdb data write example." OFF)
endif()
option(ENABLE_PFRING "Enable PF_RING support for nDPId (experimental)" OFF)
option(BUILD_NDPI "Clone and build nDPI from github." OFF)

if(ENABLE_PFRING)
    option(PFRING_LINK_STATIC "Link against a static version of pfring." ON)
    set(PFRING_KERNEL_INC "" CACHE STRING "Path to PFRING kernel module include directory.")
    set(PFRING_DEFS "-DENABLE_PFRING=1")

    if(PFRING_KERNEL_INC STREQUAL "")
        message(FATAL_ERROR "PFRING_KERNEL_INC needs to be set to the PFRING kernel module include directory.")
    endif()
    if(NOT EXISTS "${PFRING_KERNEL_INC}/linux/pf_ring.h")
        message(FATAL_ERROR "Expected to find <linux/pf_ring.h> below ${PFRING_KERNEL_INC}, but none found.")
    endif()

    set(PFRING_INSTALLDIR "/opt/PF_RING/usr" CACHE STRING "")
    set(PFRING_INC "${PFRING_INSTALLDIR}/include")

    if(NOT EXISTS "${PFRING_INC}")
        message(FATAL_ERROR "Include directory \"${PFRING_INC}\" does not exist!")
    endif()
    if(PFRING_LINK_STATIC)
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            if(EXISTS "${PFRING_INSTALLDIR}/lib64")
                set(STATIC_PFRING_LIB "${PFRING_INSTALLDIR}/lib64/libpfring.a")
            else()
                set(STATIC_PFRING_LIB "${PFRING_INSTALLDIR}/lib/libpfring.a")
            endif()
        else()
            if(EXISTS "${PFRING_INSTALLDIR}/lib32")
                set(STATIC_PFRING_LIB "${PFRING_INSTALLDIR}/lib32/libpfring.a")
            else()
                set(STATIC_PFRING_LIB "${PFRING_INSTALLDIR}/lib/libpfring.a")
            endif()
        endif()

        if(NOT EXISTS "${STATIC_PFRING_LIB}")
            message(FATAL_ERROR "Static library \"${STATIC_PFRING_LIB}\" does not exist!")
        endif()
    else()
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            if(EXISTS "${PFRING_INSTALLDIR}/lib64")
                find_library(PF_RING_LIB pfring PATHS "${PFRING_INSTALLDIR}/lib64")
            else()
                find_library(PF_RING_LIB pfring PATHS "${PFRING_INSTALLDIR}/lib")
            endif()
        else()
            if(EXISTS "${PFRING_INSTALLDIR}/lib32")
                find_library(PF_RING_LIB pfring PATHS "${PFRING_INSTALLDIR}/lib32")
            else()
                find_library(PF_RING_LIB pfring PATHS "${PFRING_INSTALLDIR}/lib")
            endif()
        endif()

        if(NOT PF_RING_LIB)
            message(FATAL_ERROR "libpfring.so not found below ${PFRING_INSTALLDIR}/{lib,lib32,lib64}")
        endif()
    endif()

    if(NOT EXISTS "${PFRING_INSTALLDIR}/include/pfring.h")
        message(FATAL_ERROR "Expected to find <include/pfring.h> inside ${PFRING_INSTALLDIR}, but none found.")
    endif()
else()
    unset(PFRING_INSTALLDIR CACHE)
    unset(PFRING_INC CACHE)
    unset(STATIC_PFRING_LIB CACHE)
    unset(PFRING_LINK_STATIC CACHE)
endif()

if(BUILD_NDPI)
    option(BUILD_NDPI_FORCE_GIT_UPDATE "Forcefully instruments nDPI build script to update the git submodule." OFF)
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
    option(NDPI_WITH_GCRYPT "Link static libndpi library against libgcrypt." OFF)
    option(NDPI_WITH_PCRE "Link static libndpi library against libpcre." OFF)
    option(NDPI_WITH_MAXMINDDB "Link static libndpi library against libmaxminddb." OFF)
else()
    unset(NDPI_WITH_GCRYPT CACHE)
    unset(NDPI_WITH_PCRE CACHE)
    unset(NDPI_WITH_MAXMINDDB CACHE)
endif()

if(ENABLE_PFRING)
    set(NDPID_PFRING_SRCS npfring.c)
endif()
add_executable(nDPId nDPId.c ${NDPID_PFRING_SRCS} nio.c utils.c)
add_executable(nDPIsrvd nDPIsrvd.c nio.c utils.c)
add_executable(nDPId-test nDPId-test.c ${NDPID_PFRING_SRCS})

add_custom_target(umask_check)
add_custom_command(
    TARGET umask_check
    PRE_BUILD
    COMMAND ${CMAKE_SOURCE_DIR}/scripts/umask-check.sh
)
add_dependencies(nDPId umask_check)

add_custom_target(dist)
add_custom_command(
    TARGET dist
    COMMAND "${CMAKE_SOURCE_DIR}/scripts/make-dist.sh"
)

add_custom_target(daemon)
add_custom_command(
    TARGET  daemon
    COMMAND env nDPIsrvd_ARGS='-C 1024' "${CMAKE_SOURCE_DIR}/scripts/daemon.sh" "$<TARGET_FILE:nDPId>" "$<TARGET_FILE:nDPIsrvd>"
    DEPENDS nDPId nDPIsrvd
)

if(CMAKE_CROSSCOMPILING)
    set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
    set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
    set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
    set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
endif()

if(BUILD_NDPI)
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
    add_custom_target(coverage DEPENDS "${CMAKE_BINARY_DIR}/coverage_report/nDPId/index.html")
    add_custom_command(
        OUTPUT "${CMAKE_BINARY_DIR}/coverage_report/nDPId/index.html"
        COMMAND lcov --directory "${CMAKE_BINARY_DIR}" --directory "${CMAKE_SOURCE_DIR}/libnDPI" --capture --output-file "${CMAKE_BINARY_DIR}/lcov.info"
        COMMAND genhtml -o "${CMAKE_BINARY_DIR}/coverage_report" "${CMAKE_BINARY_DIR}/lcov.info"
        DEPENDS nDPId nDPId-test nDPIsrvd
    )
    add_custom_target(coverage-clean)
    add_custom_command(
        TARGET coverage-clean
        COMMAND find "${CMAKE_BINARY_DIR}" "${CMAKE_SOURCE_DIR}/libnDPI" -name "*.gcda" -delete
    )
    add_custom_target(coverage-view)
    add_custom_command(
        TARGET  coverage-view
        COMMAND cd "${CMAKE_BINARY_DIR}/coverage_report" && python3 -m http.server
        DEPENDS "${CMAKE_BINARY_DIR}/coverage_report/nDPId/index.html"
    )
endif()
if(ENABLE_SANITIZER)
    # TODO: Check for `-fsanitize-memory-track-origins` and add if available?
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize=undefined -fno-sanitize=alignment -fsanitize=enum -fsanitize=leak")
endif()
if(ENABLE_SANITIZER_THREAD)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=undefined -fno-sanitize=alignment -fsanitize=enum -fsanitize=thread")
endif()
if(ENABLE_ZLIB)
    set(ZLIB_DEFS "-DENABLE_ZLIB=1")
    pkg_check_modules(ZLIB REQUIRED zlib)
endif()
if(BUILD_EXAMPLES)
    if(ENABLE_DBUS)
        pkg_check_modules(DBUS REQUIRED dbus-1)
    endif()
    if(ENABLE_CURL)
        pkg_check_modules(CURL REQUIRED libcurl)
    endif()
endif()
if(BUILD_NDPI)
    if(NDPI_WITH_GCRYPT)
        message(STATUS "nDPI: Enable GCRYPT")
        set(NDPI_ADDITIONAL_ARGS "${NDPI_ADDITIONAL_ARGS} --with-local-libgcrypt")
    endif()
    if(NDPI_WITH_PCRE)
        message(STATUS "nDPI: Enable PCRE")
        set(NDPI_ADDITIONAL_ARGS "${NDPI_ADDITIONAL_ARGS} --with-pcre2")
    endif()
    if(NDPI_WITH_MAXMINDDB)
        message(STATUS "nDPI: Enable MAXMINDDB")
        set(NDPI_ADDITIONAL_ARGS "${NDPI_ADDITIONAL_ARGS} --with-maxminddb")
    endif()
    if(ENABLE_COVERAGE)
        message(STATUS "nDPI: Enable Coverage")
        set(NDPI_ADDITIONAL_ARGS "${NDPI_ADDITIONAL_ARGS} --enable-code-coverage")
    endif()
    if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "")
        message(STATUS "nDPI: Enable Debug Build")
        set(NDPI_ADDITIONAL_ARGS "${NDPI_ADDITIONAL_ARGS} --enable-debug-build --enable-debug-messages")
    endif()
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
set(PKG_VERSION "${CPACK_PACKAGE_VERSION}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(NDPID_DEFS -DJSMN_STATIC=1 -DJSMN_STRICT=1 -DJSMN_PARENT_LINKS=1)
set(NDPID_DEPS_INC "${CMAKE_SOURCE_DIR}"
                   "${CMAKE_SOURCE_DIR}/dependencies"
                   "${CMAKE_SOURCE_DIR}/dependencies/jsmn"
                   "${CMAKE_SOURCE_DIR}/dependencies/uthash/src")
if(CMAKE_CROSSCOMPILING)
    add_definitions("-DCROSS_COMPILATION=1")
endif()
if(ENABLE_MEMORY_PROFILING)
    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT CMAKE_BUILD_TYPE STREQUAL "")
        message(WARNING "ENABLE_MEMORY_PROFILING should not be used in production environments.")
    endif()
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
            CC=${CMAKE_C_COMPILER}
            CXX=false
            AR=${CMAKE_AR}
            RANLIB=${CMAKE_RANLIB}
            PKG_CONFIG=${PKG_CONFIG_EXECUTABLE}
            CFLAGS=${CMAKE_C_FLAGS}
            LDFLAGS=${CMAKE_MODULE_LINKER_FLAGS}
            ADDITIONAL_ARGS=${NDPI_ADDITIONAL_ARGS}
            MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM}
            DEST_INSTALL=${CMAKE_BINARY_DIR}/libnDPI
            FORCE_GIT_UPDATE=${BUILD_NDPI_FORCE_GIT_UPDATE}
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/get-and-build-libndpi.sh
        BUILD_BYPRODUCTS ${CMAKE_BINARY_DIR}/libnDPI/lib/libndpi.a
        BUILD_COMMAND ""
        INSTALL_COMMAND ""
        BUILD_IN_SOURCE 1)

    add_custom_target(clean-libnDPI
        COMMAND ${CMAKE_BUILD_TOOL} clean
        COMMAND rm -rf ${CMAKE_BINARY_DIR}/libnDPI
        COMMAND rm -f ${CMAKE_BINARY_DIR}/libnDPI-prefix/src/libnDPI-stamp/libnDPI-configure
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
        pkg_check_modules(PCRE REQUIRED libpcre2-8)
    endif()

    if(NDPI_WITH_MAXMINDDB)
        pkg_check_modules(MAXMINDDB REQUIRED libmaxminddb)
    endif()
endif()

if(STATIC_LIBNDPI_INSTALLDIR OR BUILD_NDPI)
    add_definitions("-DLIBNDPI_STATIC=1")
    set(STATIC_LIBNDPI_INC "${STATIC_LIBNDPI_INSTALLDIR}/include/ndpi")
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        if(EXISTS "${STATIC_LIBNDPI_INSTALLDIR}/lib64/libndpi.a")
            set(STATIC_LIBNDPI_LIB "${STATIC_LIBNDPI_INSTALLDIR}/lib64/libndpi.a")
        else()
            set(STATIC_LIBNDPI_LIB "${STATIC_LIBNDPI_INSTALLDIR}/lib/libndpi.a")
        endif()
    else()
        if(EXISTS "${STATIC_LIBNDPI_INSTALLDIR}/lib32/libndpi.a")
            set(STATIC_LIBNDPI_LIB "${STATIC_LIBNDPI_INSTALLDIR}/lib32/libndpi.a")
        else()
            set(STATIC_LIBNDPI_LIB "${STATIC_LIBNDPI_INSTALLDIR}/lib/libndpi.a")
        endif()
    endif()

    if(STATIC_LIBNDPI_INSTALLDIR AND NOT BUILD_NDPI)
        if(NOT EXISTS "${STATIC_LIBNDPI_INC}" OR NOT EXISTS "${STATIC_LIBNDPI_LIB}")
            message(FATAL_ERROR "Include directory \"${STATIC_LIBNDPI_INC}\" or\n"
                                "static library \"${STATIC_LIBNDPI_LIB}\" does not exist!")
        endif()
    endif()

    unset(DEFAULT_NDPI_INCLUDE CACHE)
    unset(pkgcfg_lib_NDPI_ndpi CACHE)
else()
    if(NOT NDPI_NO_PKGCONFIG)
        pkg_check_modules(NDPI REQUIRED libndpi>=4.11.0)
        if(NOT pkgcfg_lib_NDPI_ndpi)
            find_package(NDPI "4.11.0" REQUIRED)
        endif()

        unset(STATIC_LIBNDPI_INC CACHE)
        unset(STATIC_LIBNDPI_LIB CACHE)
    endif()

    set(DEFAULT_NDPI_INCLUDE ${NDPI_INCLUDE_DIRS})
endif()

pkg_check_modules(PCAP libpcap>=1.9.0) # no *.pc file before 1.9.0
if(NOT pkgcfg_lib_PCAP_pcap)
    pkg_check_modules(PCAP libpcap>=1.8.1) # seems like some distributions provide their own *.pc file for 1.8.1 (e.g. Ubuntu-18.04)
endif()
if(NOT pkgcfg_lib_PCAP_pcap)
    find_package(PCAP "1.9.0" REQUIRED)
endif()

target_compile_options(nDPId PRIVATE "-pthread")
target_compile_definitions(nDPId PRIVATE -D_GNU_SOURCE=1 -DPKG_VERSION=\"${PKG_VERSION}\" -DGIT_VERSION=\"${GIT_VERSION}\" ${NDPID_DEFS} ${EPOLL_DEFS} ${ZLIB_DEFS} ${PFRING_DEFS})
target_include_directories(nDPId PRIVATE "${STATIC_LIBNDPI_INC}" "${DEFAULT_NDPI_INCLUDE}" ${NDPID_DEPS_INC} ${PFRING_KERNEL_INC} ${PFRING_INC})
target_link_libraries(nDPId "${STATIC_LIBNDPI_LIB}" "${STATIC_PFRING_LIB}" "${pkgcfg_lib_PCAP_pcap}" "${pkgcfg_lib_NDPI_ndpi}"
                            "${pkgcfg_lib_PCRE_pcre2-8}" "${pkgcfg_lib_MAXMINDDB_maxminddb}" "${pkgcfg_lib_ZLIB_z}"
                            "${GCRYPT_LIBRARY}" "${GCRYPT_ERROR_LIBRARY}" "${PCAP_LIBRARY}" "${LIBM_LIB}" "${PF_RING_LIB}"
                            "-pthread")

target_compile_definitions(nDPIsrvd PRIVATE -D_GNU_SOURCE=1 -DPKG_VERSION=\"${PKG_VERSION}\" -DGIT_VERSION=\"${GIT_VERSION}\" ${NDPID_DEFS} ${EPOLL_DEFS})
target_include_directories(nDPIsrvd PRIVATE ${NDPID_DEPS_INC})

target_compile_options(nDPId-test PRIVATE "-Wno-unused-function" "-pthread")
target_compile_definitions(nDPId-test PRIVATE -D_GNU_SOURCE=1 -DNO_MAIN=1 -DPKG_VERSION=\"${PKG_VERSION}\" -DGIT_VERSION=\"${GIT_VERSION}\"
                                              ${NDPID_DEFS} ${EPOLL_DEFS} ${ZLIB_DEFS} ${PFRING_DEFS} ${NDPID_TEST_MPROF_DEFS})
target_include_directories(nDPId-test PRIVATE
                           "${STATIC_LIBNDPI_INC}" "${DEFAULT_NDPI_INCLUDE}" ${NDPID_DEPS_INC} ${PFRING_KERNEL_INC} ${PFRING_INC})
target_link_libraries(nDPId-test "${STATIC_LIBNDPI_LIB}" "${STATIC_PFRING_LIB}" "${pkgcfg_lib_PCAP_pcap}" "${pkgcfg_lib_NDPI_ndpi}"
                                 "${pkgcfg_lib_PCRE_pcre2-8}" "${pkgcfg_lib_MAXMINDDB_maxminddb}" "${pkgcfg_lib_ZLIB_z}"
                                 "${GCRYPT_LIBRARY}" "${GCRYPT_ERROR_LIBRARY}" "${PCAP_LIBRARY}" "${LIBM_LIB}" "${PF_RING_LIB}"
                                 "-pthread")

if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    add_executable(fuzz_ndpi_process_packet test/fuzz_ndpi_process_packet.c)
    if(BUILD_NDPI)
        add_dependencies(fuzz_ndpi_process_packet libnDPI)
    endif()
    target_compile_options(fuzz_ndpi_process_packet PRIVATE "-Wno-unused-function" "-fsanitize=fuzzer" "-pthread")
    target_compile_definitions(fuzz_ndpi_process_packet PRIVATE -D_GNU_SOURCE=1
                                                                -DPKG_VERSION=\"${PKG_VERSION}\" -DGIT_VERSION=\"${GIT_VERSION}\"
                                                                ${NDPID_DEFS} ${EPOLL_DEFS} ${ZLIB_DEFS} ${PFRING_DEFS})
    target_include_directories(fuzz_ndpi_process_packet PRIVATE "${STATIC_LIBNDPI_INC}" "${DEFAULT_NDPI_INCLUDE}"
                                                                ${NDPID_DEPS_INC} ${PFRING_KERNEL_INC} ${PFRING_INC})
    target_link_libraries(fuzz_ndpi_process_packet "${STATIC_LIBNDPI_LIB}" "${STATIC_PFRING_LIB}" "${pkgcfg_lib_PCAP_pcap}" "${pkgcfg_lib_NDPI_ndpi}"
                                "${pkgcfg_lib_PCRE_pcre2-8}" "${pkgcfg_lib_MAXMINDDB_maxminddb}" "${pkgcfg_lib_ZLIB_z}"
                                "${GCRYPT_LIBRARY}" "${GCRYPT_ERROR_LIBRARY}" "${PCAP_LIBRARY}" "${LIBM_LIB}" "${PF_RING_LIB}"
                                "-pthread")
    target_link_options(fuzz_ndpi_process_packet PRIVATE "-fsanitize=fuzzer")
endif()

if(BUILD_EXAMPLES)
    add_executable(nDPIsrvd-collectd examples/c-collectd/c-collectd.c utils.c)
    if(BUILD_NDPI)
        add_dependencies(nDPIsrvd-collectd libnDPI)
    endif()
    target_compile_definitions(nDPIsrvd-collectd PRIVATE ${NDPID_DEFS})
    target_include_directories(nDPIsrvd-collectd PRIVATE
                               "${STATIC_LIBNDPI_INC}" "${DEFAULT_NDPI_INCLUDE}" "${CMAKE_SOURCE_DIR}" ${NDPID_DEPS_INC})

    add_executable(nDPIsrvd-captured examples/c-captured/c-captured.c utils.c)
    if(BUILD_NDPI)
        add_dependencies(nDPIsrvd-captured libnDPI)
    endif()
    target_compile_definitions(nDPIsrvd-captured PRIVATE ${NDPID_DEFS})
    target_include_directories(nDPIsrvd-captured PRIVATE
                               "${STATIC_LIBNDPI_INC}" "${DEFAULT_NDPI_INCLUDE}" "${CMAKE_SOURCE_DIR}" ${NDPID_DEPS_INC})
    target_link_libraries(nDPIsrvd-captured "${pkgcfg_lib_PCAP_pcap}" "${pkgcfg_lib_NDPI_ndpi}"
                                            "${pkgcfg_lib_PCRE_pcre2-8}" "${pkgcfg_lib_MAXMINDDB_maxminddb}"
                                            "${GCRYPT_LIBRARY}" "${GCRYPT_ERROR_LIBRARY}" "${PCAP_LIBRARY}")

    add_executable(nDPIsrvd-analysed examples/c-analysed/c-analysed.c utils.c)
    if(BUILD_NDPI)
        add_dependencies(nDPIsrvd-analysed libnDPI)
    endif()
    target_compile_definitions(nDPIsrvd-analysed PRIVATE ${NDPID_DEFS})
    target_include_directories(nDPIsrvd-analysed PRIVATE
                               "${STATIC_LIBNDPI_INC}" "${DEFAULT_NDPI_INCLUDE}" "${CMAKE_SOURCE_DIR}" ${NDPID_DEPS_INC})

    add_executable(nDPIsrvd-simple examples/c-simple/c-simple.c)
    target_compile_definitions(nDPIsrvd-simple PRIVATE ${NDPID_DEFS})
    target_include_directories(nDPIsrvd-simple PRIVATE ${NDPID_DEPS_INC})

    if(ENABLE_COVERAGE)
        add_dependencies(coverage nDPIsrvd-analysed nDPIsrvd-collectd nDPIsrvd-captured nDPIsrvd-simple)
        if(BUILD_NDPI)
            add_dependencies(coverage libnDPI)
        endif()
    endif()

    if(ENABLE_DBUS)
        add_executable(nDPIsrvd-notifyd examples/c-notifyd/c-notifyd.c utils.c)
        if(BUILD_NDPI)
            add_dependencies(nDPIsrvd-notifyd libnDPI)
        endif()
        target_compile_definitions(nDPIsrvd-notifyd PRIVATE ${NDPID_DEFS})
        target_include_directories(nDPIsrvd-notifyd PRIVATE
                                   "${STATIC_LIBNDPI_INC}" "${DEFAULT_NDPI_INCLUDE}" "${CMAKE_SOURCE_DIR}" "${NDPID_DEPS_INC}"
                                   "${DBUS_INCLUDE_DIRS}")
        target_link_libraries(nDPIsrvd-notifyd "${DBUS_LIBRARIES}")
        install(TARGETS nDPIsrvd-notifyd DESTINATION bin)
    endif()

    if(ENABLE_CURL)
        add_executable(nDPIsrvd-influxd examples/c-influxd/c-influxd.c utils.c)
        if(BUILD_NDPI)
            add_dependencies(nDPIsrvd-influxd libnDPI)
        endif()
        target_compile_definitions(nDPIsrvd-influxd PRIVATE ${NDPID_DEFS})
        target_include_directories(nDPIsrvd-influxd PRIVATE
                                   "${STATIC_LIBNDPI_INC}" "${DEFAULT_NDPI_INCLUDE}" "${CMAKE_SOURCE_DIR}" "${NDPID_DEPS_INC}"
                                   "${CURL_INCLUDE_DIRS}")
        target_link_libraries(nDPIsrvd-influxd "${CURL_LIBRARIES}")
        install(TARGETS nDPIsrvd-influxd DESTINATION bin)
    endif()

    install(TARGETS nDPIsrvd-analysed nDPIsrvd-collectd nDPIsrvd-captured nDPIsrvd-simple DESTINATION bin)
    install(FILES examples/c-collectd/plugin_nDPIsrvd.conf examples/c-collectd/rrdgraph.sh DESTINATION share/nDPId/nDPIsrvd-collectd)
    install(DIRECTORY examples/c-collectd/www DESTINATION share/nDPId/nDPIsrvd-collectd)
endif()

if(ENABLE_SYSTEMD)
    configure_file(packages/systemd/ndpisrvd.service.in ndpisrvd.service @ONLY)
    configure_file(packages/systemd/ndpid@.service.in ndpid@.service @ONLY)

    install(DIRECTORY DESTINATION etc/nDPId)
    install(FILES "ndpid.conf.example" DESTINATION share/nDPId)
    install(FILES "ndpisrvd.conf.example" DESTINATION share/nDPId)
    install(FILES "${CMAKE_BINARY_DIR}/ndpisrvd.service" DESTINATION lib/systemd/system)
    install(FILES "${CMAKE_BINARY_DIR}/ndpid@.service" DESTINATION lib/systemd/system)
endif()

install(FILES config.h
              dependencies/nDPIsrvd.h
              dependencies/jsmn/jsmn.h
              dependencies/uthash/src/utarray.h
              dependencies/uthash/src/uthash.h
              dependencies/uthash/src/utlist.h
              dependencies/uthash/src/utringbuffer.h
              dependencies/uthash/src/utstack.h
              dependencies/uthash/src/utstring.h
        DESTINATION include/nDPId)
install(TARGETS nDPId DESTINATION sbin)
install(TARGETS nDPIsrvd nDPId-test DESTINATION bin)
if(BUILD_EXAMPLES)
    install(FILES dependencies/nDPIsrvd.py examples/py-flow-dashboard/plotly_dash.py
            DESTINATION share/nDPId)
    install(FILES examples/py-flow-info/flow-info.py
            DESTINATION bin RENAME nDPIsrvd-flow-info.py
            PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
    install(FILES examples/py-flow-dashboard/flow-dash.py
            DESTINATION bin RENAME nDPIsrvd-flow-dash.py
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
    install(FILES examples/py-machine-learning/sklearn-random-forest.py
            DESTINATION bin RENAME nDPIsrvd-sklearn.py
            PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
endif()
install(FILES schema/error_event_schema.json schema/daemon_event_schema.json
              schema/flow_event_schema.json schema/packet_event_schema.json DESTINATION share/nDPId/json-schema)

message(STATUS "--------------------------")
message(STATUS "nDPId GIT_VERSION........: ${GIT_VERSION}")
message(STATUS "Cross Compilation........: ${CMAKE_CROSSCOMPILING}")
message(STATUS "CMAKE_BUILD_TYPE.........: ${CMAKE_BUILD_TYPE}")
message(STATUS "CMAKE_C_FLAGS............: ${CMAKE_C_FLAGS}")
message(STATUS "NDPID_DEFS...............: ${NDPID_DEFS}")
message(STATUS "FORCE_POLL...............: ${FORCE_POLL}")
message(STATUS "ENABLE_PFRING............: ${ENABLE_PFRING}")
if(ENABLE_PFRING)
message(STATUS "PFRING_LINK_STATIC.......: ${PFRING_LINK_STATIC}")
endif()
message(STATUS "ENABLE_COVERAGE..........: ${ENABLE_COVERAGE}")
message(STATUS "ENABLE_SANITIZER.........: ${ENABLE_SANITIZER}")
message(STATUS "ENABLE_SANITIZER_THREAD..: ${ENABLE_SANITIZER_THREAD}")
message(STATUS "ENABLE_MEMORY_PROFILING..: ${ENABLE_MEMORY_PROFILING}")
message(STATUS "ENABLE_ZLIB..............: ${ENABLE_ZLIB}")
message(STATUS "BUILD_NDPI...............: ${BUILD_NDPI}")
message(STATUS "BUILD_EXAMPLES...........: ${BUILD_EXAMPLES}")
if(BUILD_EXAMPLES)
message(STATUS "ENABLE_DBUS..............: ${ENABLE_DBUS}")
message(STATUS "ENABLE_CURL..............: ${ENABLE_CURL}")
endif()
if(BUILD_NDPI)
message(STATUS "NDPI_ADDITIONAL_ARGS.....: ${NDPI_ADDITIONAL_ARGS}")
endif()
message(STATUS "NDPI_NO_PKGCONFIG........: ${NDPI_NO_PKGCONFIG}")
message(STATUS "--------------------------")
if(PFRING_INSTALLDIR)
message(STATUS "PFRING_INSTALLDIR........: ${PFRING_INSTALLDIR}")
message(STATUS "- PFRING_INC.............: ${PFRING_INC}")
message(STATUS "- PFRING_KERNEL_INC......: ${PFRING_KERNEL_INC}")
message(STATUS "- STATIC_PFRING_LIB......: ${STATIC_PFRING_LIB}")
message(STATUS "- SHARED_PFRING_LIB......: ${PF_RING_LIB}")
message(STATUS "--------------------------")
endif()
if(STATIC_LIBNDPI_INSTALLDIR)
message(STATUS "STATIC_LIBNDPI_INSTALLDIR: ${STATIC_LIBNDPI_INSTALLDIR}")
endif()
if(STATIC_LIBNDPI_INSTALLDIR OR BUILD_NDPI OR NDPI_NO_PKGCONFIG)
message(STATUS "- STATIC_LIBNDPI_INC.....: ${STATIC_LIBNDPI_INC}")
message(STATUS "- STATIC_LIBNDPI_LIB.....: ${STATIC_LIBNDPI_LIB}")
message(STATUS "- NDPI_WITH_GCRYPT.......: ${NDPI_WITH_GCRYPT}")
message(STATUS "- NDPI_WITH_PCRE.........: ${NDPI_WITH_PCRE}")
message(STATUS "- NDPI_WITH_MAXMINDDB....: ${NDPI_WITH_MAXMINDDB}")
endif()
if(NOT STATIC_LIBNDPI_INSTALLDIR AND NOT BUILD_NDPI)
message(STATUS "- DEFAULT_NDPI_INCLUDE...: ${DEFAULT_NDPI_INCLUDE}")
endif()
if(NOT NDPI_NO_PKGCONFIG)
message(STATUS "- pkgcfg_lib_NDPI_ndpi...: ${pkgcfg_lib_NDPI_ndpi}")
endif()
message(STATUS "--------------------------")
if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
message(STATUS "Fuzzing enabled")
endif()
