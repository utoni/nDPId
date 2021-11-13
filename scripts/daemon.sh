#!/usr/bin/env sh
#
# Simple nDPId/nDPIsrvd start/stop script for testing purposes.
#

NUSER="nobody"
NSUFFIX="${NSUFFIX:-daemon-test}"
nDPId_THREADS="${nDPId_THREADS:-4}"

if [ x"${1}" = x -o x"${2}" = x ]; then
    printf '%s\n' "usage: ${0} [nDPId-path] [nDPIsrvd-path]" >&2
    printf '\n\t%s=%s\n' 'env NUSER'   "${NUSER}" >&2
    printf   '\t%s=%s\n' 'env NSUFFIX' "${NSUFFIX}" >&2
    exit 1
fi

if [ -r "/tmp/nDPId-${NSUFFIX}.pid" -o -r "/tmp/nDPIsrvd-${NSUFFIX}.pid" ]; then
    nDPId_PID="$(cat "/tmp/nDPId-${NSUFFIX}.pid" 2>/dev/null)"
    nDPIsrvd_PID="$(cat "/tmp/nDPIsrvd-${NSUFFIX}.pid" 2>/dev/null)"

    if [ x"${nDPId_PID}" != x ]; then
        sudo kill "${nDPId_PID}" 2>/dev/null || true
        while ps -p "${nDPId_PID}" > /dev/null; do sleep 1; done
        rm -f "/tmp/nDPId-${NSUFFIX}.pid"
    else
        printf '%s\n' "${1} not started .." >&2
    fi

    if [ x"${nDPIsrvd_PID}" != x ]; then
        kill "${nDPIsrvd_PID}" 2>/dev/null || true
        while ps -p "${nDPIsrvd_PID}" > /dev/null; do sleep 1; done
        rm -f "/tmp/nDPIsrvd-${NSUFFIX}.pid" "/tmp/nDPIsrvd-${NSUFFIX}-collector.sock" "/tmp/nDPIsrvd-${NSUFFIX}-distributor.sock"
    else
        printf '%s\n' "${2} not started .." >&2
    fi

    printf '%s\n' "daemons stopped" >&2
else
    set -x
    ${2} -p "/tmp/nDPIsrvd-${NSUFFIX}.pid" -c "/tmp/nDPIsrvd-${NSUFFIX}-collector.sock" -s "/tmp/nDPIsrvd-${NSUFFIX}-distributor.sock" -d
    sudo chgrp "$(id -n -g "${NUSER}")" "/tmp/nDPIsrvd-${NSUFFIX}-collector.sock"
    sudo chmod g+w "/tmp/nDPIsrvd-${NSUFFIX}-collector.sock"
    sudo ${1} -p "/tmp/nDPId-${NSUFFIX}.pid" -c "/tmp/nDPIsrvd-${NSUFFIX}-collector.sock" -d -u "${NUSER}" -o max-reader-threads=${nDPId_THREADS}
    set +x
    printf '%s\n' "daemons started" >&2
    printf '%s\n' "You may now run examples e.g.: $(realpath --relative-to="$(pwd)" $(dirname "${0}")/../examples/py-flow-info/flow-info.py) --unix /tmp/nDPIsrvd-${NSUFFIX}-distributor.sock"
fi
