#!/usr/bin/env sh
#
# Simple nDPId/nDPIsrvd start/stop script for testing purposes.
#

NROOT="${NROOT:-/tmp}"
NUSER="${NUSER:-$(id -u -n)}"
NSUFFIX="${NSUFFIX:-daemon-test}"
nDPId_THREADS="${nDPId_THREADS:-4}"
nDPId_ARGS="${nDPId_ARGS:-}"
nDPIsrvd_ARGS="${nDPIsrvd_ARGS:-}"

if [ x"${1}" = x -o x"${2}" = x ]; then
    printf '%s\n' "usage: ${0} [nDPId-path] [nDPIsrvd-path]" >&2
    printf '\n\t%s=%s\n' 'env NUSER'         "${NUSER}" >&2
    printf   '\t%s=%s\n' 'env NSUFFIX'       "${NSUFFIX}" >&2
    printf   '\t%s=%s\n' 'env nDPId_ARGS'    "${nDPId_ARGS}" >&2
    printf   '\t%s=%s\n' 'env nDPIsrvd_ARGS' "${nDPIsrvd_ARGS}" >&2
    exit 1
fi

RETVAL=0

if [ -r "${NROOT}/nDPId-${NSUFFIX}.pid" -o -r "${NROOT}/nDPIsrvd-${NSUFFIX}.pid" ]; then
    nDPId_PID="$(cat "${NROOT}/nDPId-${NSUFFIX}.pid" 2>/dev/null)"
    nDPIsrvd_PID="$(cat "${NROOT}/nDPIsrvd-${NSUFFIX}.pid" 2>/dev/null)"

    if [ x"${nDPId_PID}" != x ]; then
        sudo kill "${nDPId_PID}" 2>/dev/null || true
        while ps -p "${nDPId_PID}" > /dev/null; do sleep 1; done
        rm -f "${NROOT}/nDPId-${NSUFFIX}.pid"
    else
        printf '%s\n' "${1} not started .." >&2
        RETVAL=1
    fi

    if [ x"${nDPIsrvd_PID}" != x ]; then
        kill "${nDPIsrvd_PID}" 2>/dev/null || true
        while ps -p "${nDPIsrvd_PID}" > /dev/null; do sleep 1; done
        rm -f "${NROOT}/nDPIsrvd-${NSUFFIX}.pid" "${NROOT}/nDPIsrvd-${NSUFFIX}-collector.sock" "${NROOT}/nDPIsrvd-${NSUFFIX}-distributor.sock"
    else
        printf '%s\n' "${2} not started .." >&2
        RETVAL=1
    fi

    printf '%s\n' "daemons stopped" >&2
else
    set -x
    sudo ${2} -p "${NROOT}/nDPIsrvd-${NSUFFIX}.pid" -c "${NROOT}/nDPIsrvd-${NSUFFIX}-collector.sock" -s "${NROOT}/nDPIsrvd-${NSUFFIX}-distributor.sock" -d -u "${NUSER}" -L "${NROOT}/nDPIsrvd.log" ${nDPIsrvd_ARGS}
    test $? -eq 0 || RETVAL=1

    MAX_TRIES=10
    while [ ! -S "${NROOT}/nDPIsrvd-${NSUFFIX}-collector.sock" -a ${MAX_TRIES} -gt 0 ]; do
        sleep 0.5
        MAX_TRIES=$((MAX_TRIES - 1))
    done
    test ${MAX_TRIES} -eq 0 && RETVAL=1

    MAX_TRIES=10
    while [ ! -S "${NROOT}/nDPIsrvd-${NSUFFIX}-distributor.sock" -a ${MAX_TRIES} -gt 0 ]; do
        sleep 0.5
        MAX_TRIES=$((MAX_TRIES - 1))
    done
    test ${MAX_TRIES} -eq 0 && RETVAL=1

    sudo chgrp "$(id -n -g "${NUSER}")" "${NROOT}/nDPIsrvd-${NSUFFIX}-collector.sock"
    test $? -eq 0 || RETVAL=1
    sudo chmod g+w "${NROOT}/nDPIsrvd-${NSUFFIX}-collector.sock"
    test $? -eq 0 || RETVAL=1
    sudo ${1} -p "${NROOT}/nDPId-${NSUFFIX}.pid" -c "${NROOT}/nDPIsrvd-${NSUFFIX}-collector.sock" -d -u "${NUSER}" -L "${NROOT}/nDPId.log" -o max-reader-threads=${nDPId_THREADS} ${nDPId_ARGS}
    test $? -eq 0 || RETVAL=1
    set +x
    printf '%s\n' "daemons started" >&2
    test ${RETVAL} -eq 0 && printf '%s\n' "You may now run examples e.g.: $(realpath --relative-to="$(pwd)" $(dirname "${0}")/../examples/py-flow-info/flow-info.py) --unix ${NROOT}/nDPIsrvd-${NSUFFIX}-distributor.sock"
fi

if [ ${RETVAL} -ne 0 ]; then
    test -r "${NROOT}/nDPIsrvd.log" && cat "${NROOT}/nDPIsrvd.log"
    test -r "${NROOT}/nDPId.log" && cat "${NROOT}/nDPId.log"
fi

exit ${RETVAL}
