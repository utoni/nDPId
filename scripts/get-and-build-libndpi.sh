#!/usr/bin/env bash

set -e
set -x

LOCKFILE="$(realpath "${0}").lock"
touch "${LOCKFILE}"
exec 42< "${LOCKFILE}"
flock -x -n 42 || {
    printf '%s\n' "Could not aquire file lock for ${0}. Already running instance?" >&2;
    exit 1;
}

cd "$(dirname "${0}")/.."
git submodule update --init ./libnDPI

cd ./libnDPI
DEST_INSTALL="${DEST_INSTALL:-$(realpath ./install)}"
MAKE_PROGRAM="${MAKE_PROGRAM:-make -j4}"
./autogen.sh --prefix="${DEST_INSTALL}" --with-only-libndpi
${MAKE_PROGRAM} install

rm -f "${LOCKFILE}"
