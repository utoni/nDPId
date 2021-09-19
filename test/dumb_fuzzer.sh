#!/usr/bin/env bash

set -e

MYDIR="$(realpath "$(dirname ${0})")"
nDPId_test_EXEC="$(realpath "${1:-"${MYDIR}/../nDPId-test"}")"
PROTOCOL="${2:-tcp}"
MAX_RUNS="${3:-100}"
MAX_COUNT="${4:-10000}"

function usage()
{
cat <<EOF
usage: ${0} [path-to-nDPId-test-exec] [protocol] [max-runs] [max-count]

    path-to-nDPId-test-exec defaults to ${nDPId_test_EXEC}
    protocol defaults to ${PROTOCOL}
    max-runs defaults to ${MAX_RUNS}
    max-count defaults to ${MAX_COUNT}
EOF
return 0
}

if [ $# -eq 0 ]; then
    usage
    exit 1
elif [ ! -x "${nDPId_test_EXEC}" ]; then
    printf '%s\n' "Required nDPId-test executable does not exist; ${nDPId_test_EXEC}"
    exit 1
fi

function sighandler()
{
    printf '%s\n' ' Received shutdown SIGNAL, bye' >&2
    rm -f "/tmp/randpkt_$$.pcap"
    $(which pkill) -P $$
    wait
    exit 2
}
trap sighandler SIGINT SIGTERM

test -z "$(which pkill)" && { printf '%s\n' 'pkill not found'; exit 1; }
test -z "$(which randpkt)" && { printf '%s\n' 'randpkt not found'; exit 1; }

while (( ${MAX_RUNS} > 0 )); do
    printf '.'
    test $((${MAX_RUNS} % 10)) -ne 0 || printf '%s' "${MAX_RUNS}"
    $(which randpkt) -c "${MAX_COUNT}" -t "${PROTOCOL}" "/tmp/randpkt_$$.pcap"
    ${nDPId_test_EXEC} "/tmp/randpkt_$$.pcap" >/dev/null
    MAX_RUNS=$((${MAX_RUNS} - 1))
done

rm -f "/tmp/randpkt_$$.pcap"
printf '\n'
