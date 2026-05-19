#!/usr/bin/env bash

set -e

GIT_EXEC="$(command -v git || printf '%s' "")"
WGET_EXEC="$(command -v wget || printf '%s' "")"
UNZIP_EXEC="$(command -v unzip || printf '%s' "")"
CMAKE_EXEC="$(command -v cmake || printf '%s' "")"
FLOCK_EXEC="$(command -v flock || printf '%s' "")"

WIRESHARK_BRANCH="wireshark-4.2"
GITHUB_FALLBACK_URL="https://github.com/wireshark/wireshark/archive/refs/heads/${WIRESHARK_BRANCH}.zip"

if [[ -z "${GIT_EXEC}" || -z "${WGET_EXEC}" || -z "${UNZIP_EXEC}" || -z "${CMAKE_EXEC}" || -z "${FLOCK_EXEC}" ]]; then
    printf '%s\n' "Required Executables missing: git, wget, unzip, cmake, flock" >&2
    exit 1
fi

LOCKFILE="$(realpath "${0}").lock"
touch "${LOCKFILE}"
exec 42< "${LOCKFILE}"
${FLOCK_EXEC} -x -n 42 || {
    printf '%s\n' "Could not aquire file lock for ${0}. Already running instance?" >&2;
    exit 1;
}

if [[ -n "${CC}" ]]; then
    HOST_TRIPLET="$(${CC} ${CFLAGS} -dumpmachine)"
fi

cat <<EOF
------ environment variables ------
HOST_TRIPLET=${HOST_TRIPLET:-}
CC=${CC:-}
AR=${AR:-}
RANLIB=${RANLIB:-}
PKG_CONFIG=${PKG_CONFIG:-}
CFLAGS=${CFLAGS:-}
MAKE_PROGRAM=${MAKE_PROGRAM:-}
DEST_INSTALL=${DEST_INSTALL:-}
FORCE_GIT_UPDATE=${FORCE_GIT_UPDATE:-}
-----------------------------------
EOF

set -x

cd "$(dirname "${0}")/.."

GIT_SUCCESS=0
if [[ -d ./.git || -f ./.git ]]; then
    GIT_SUCCESS=1

    if [[ -n "${FORCE_GIT_UPDATE}" && "${FORCE_GIT_UPDATE}" != "OFF" ]]; then
        git submodule deinit --force -- ./libWireshark || { GIT_SUCCESS=0; true; }
        LINES_CHANGED=0
    else
        LINES_CHANGED="$(git --no-pager diff ./libWireshark 2>/dev/null | wc -l || printf '0')"
    fi

    if [[ ${LINES_CHANGED} -eq 0 ]]; then
        git submodule update --progress --init ./libWireshark || { GIT_SUCCESS=0; true; }
    else
        set +x
        printf '%s\n' '-----------------------------------'
        printf 'WARNING: %s changes in source tree %s, no GIT update will be done!\n' "${LINES_CHANGED}" "$(realpath $(dirname "${0}")/../libWireshark)"
        printf '%s\n' '-----------------------------------'
        set -x
    fi
fi

if [[ ${GIT_SUCCESS} -eq 0 ]]; then
    set +x
    printf '%s\n' '-----------------------------------'
    printf 'WARNING: %s is supposed to be a GIT repository. But it is not.\n' "$(realpath $(dirname "${0}")/..)"
    printf '%s\n' 'Can not clone libWireshark as GIT submodule.'
    printf '%s\n' 'Falling back to Github direct download.'
    printf 'URL: %s\n' "${GITHUB_FALLBACK_URL}"
    printf '%s\n' '-----------------------------------'
    set -x
    ${WGET_EXEC} "${GITHUB_FALLBACK_URL}" -O ./wireshark-github.zip
    ${UNZIP_EXEC} ./wireshark-github.zip
    rm -rf ./libWireshark
    # GitHub archives branch zips as wireshark-${BRANCH}/
    mv "./wireshark-${WIRESHARK_BRANCH}" ./libWireshark
fi

DEST_INSTALL="${DEST_INSTALL:-$(realpath ./libWireshark-install)}"
MAKE_PROGRAM="${MAKE_PROGRAM:-cmake --build}"

# Use an out-of-source build directory
BUILD_DIR="$(realpath ./libWireshark-build)"
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

CMAKE_ARGS=(
    -DCMAKE_BUILD_TYPE=Release
    "-DCMAKE_INSTALL_PREFIX=${DEST_INSTALL}"
    # Disable all executables; only the core libraries are needed
    -DBUILD_wireshark=OFF
    -DBUILD_tshark=OFF
    -DBUILD_rawshark=OFF
    -DBUILD_sharkd=OFF
    -DBUILD_dumpcap=OFF
    -DBUILD_androiddump=OFF
    -DBUILD_sshdump=OFF
    -DBUILD_ciscodump=OFF
    -DBUILD_randpktdump=OFF
    -DBUILD_udpdump=OFF
    -DBUILD_wifidump=OFF
    -DBUILD_fuzz_targets=OFF
    -DBUILD_logray=OFF
    # Disable optional features that pull in heavy dependencies
    -DENABLE_PLUGINS=OFF
    -DENABLE_LUA=OFF
    -DENABLE_PCAP=OFF
    -DENABLE_KERBEROS=OFF
    -DENABLE_SBC=OFF
    -DENABLE_SPANDSP=OFF
    -DENABLE_BCG729=OFF
    -DENABLE_AMRNB=OFF
    -DENABLE_ILBC=OFF
    -DENABLE_OPUS=OFF
    # No Qt GUI
    -DUSE_qt6=OFF
    -DUSE_qt5=OFF
)

if [[ -n "${CC}" ]]; then
    CMAKE_ARGS+=("-DCMAKE_C_COMPILER=${CC}")
fi
if [[ -n "${AR}" ]]; then
    CMAKE_ARGS+=("-DCMAKE_AR=${AR}")
fi
if [[ -n "${RANLIB}" ]]; then
    CMAKE_ARGS+=("-DCMAKE_RANLIB=${RANLIB}")
fi
if [[ -n "${PKG_CONFIG}" ]]; then
    CMAKE_ARGS+=("-DCMAKE_PKG_CONFIG_EXECUTABLE=${PKG_CONFIG}")
fi
if [[ -n "${CFLAGS}" ]]; then
    CMAKE_ARGS+=("-DCMAKE_C_FLAGS=${CFLAGS}")
fi

${CMAKE_EXEC} "${CMAKE_ARGS[@]}" -S ./libWireshark -B "${BUILD_DIR}"
${CMAKE_EXEC} --build "${BUILD_DIR}" --parallel
${CMAKE_EXEC} --install "${BUILD_DIR}"

rm -f "${LOCKFILE}"
