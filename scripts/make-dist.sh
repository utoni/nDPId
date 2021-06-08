#!/usr/bin/env bash

set -e

LOCKFILE="$(realpath "${0}").lock"
touch "${LOCKFILE}"
exec 42< "${LOCKFILE}"
flock -x -n 42 || {
    printf '%s\n' "Could not aquire file lock for ${0}. Already running instance?" >&2;
    exit 1;
}

cd "$(dirname "${0}")/.."
if [ ! -d ./.git ]; then
    printf '%s\n' "This script can only by run from a nDPId git repository." >&2
fi

git submodule update --init ./libnDPI
NDPID_GIT_VERSION="$(git describe --tags)"
cd ./libnDPI && \
    LIBNDPI_GIT_VERSION="$(git describe --tags)"
    git archive --prefix="nDPId-${NDPID_GIT_VERSION}/libnDPI/" -o "../libnDPI-${LIBNDPI_GIT_VERSION}.tar" HEAD && \
    cd ..
git archive --prefix="nDPId-${NDPID_GIT_VERSION}/" -o "./nDPId-${NDPID_GIT_VERSION}.tar" HEAD
tar --concatenate --file="./nDPId-${NDPID_GIT_VERSION}.tar" "./libnDPI-${LIBNDPI_GIT_VERSION}.tar"
bzip2 -9 "./nDPId-${NDPID_GIT_VERSION}.tar"

rm -f "${LOCKFILE}"
