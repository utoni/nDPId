#!/usr/bin/env sh

set -e

NDPI_REPO_PATH="${1}"
MYDIR="$(dirname ${0})"
NCBIN="/bin/nc"

cd "${MYDIR}/.."

if [ -z "${NDPI_REPO_PATH}" ]; then
    printf '%s: %s\n' "${0}" 'NDPI_REPO_PATH (argument 1) missing!'
    exit 1
fi

if [ ! -x "${NCBIN}" ]; then
    printf '%s: %s\n' "${0}" "${NCBIN} not found or not executable. Please make sure to install 'netcat-openbsd'."
    exit 1
fi

test -d "${NDPI_REPO_PATH}"

EXIT_VALUE=0

# Create new results.
trap 'eval "set +e && kill $(cat /tmp/nDPId.pid) $(cat /tmp/nc.pid) && rm -f /tmp/nDPId.pid /tmp/nDPIsrvd.pid && exit 1"' INT QUIT TERM

for pcap_file in `ls ${NDPI_REPO_PATH}/tests/pcap/*.pcap ${NDPI_REPO_PATH}/tests/pcap/*.pcapng`; do
    printf '%s ' "${pcap_file}"
    rm -f /tmp/ndpid-collector.sock
    ${NCBIN} -k -l -U /tmp/ndpid-collector.sock >"./tests/result/nDPId_$(basename ${pcap_file}).txt.tmp" & printf "$!" >/tmp/nc.pid
    ./nDPId -p /tmp/nDPId.pid -o max-reader-threads=1 -l -i "${pcap_file}" >"./tests/out/nDPId_$(basename ${pcap_file}).txt.tmp" 2>/tmp/nDPId.stderr || { cat /tmp/nDPId.stderr; exit 1; }
    cat "./tests/out/nDPId_$(basename ${pcap_file}).txt.tmp" | grep 'Total' >"./tests/out/nDPId_$(basename ${pcap_file}).txt.tmp2"

    if [ $(diff "./tests/out/nDPId_$(basename ${pcap_file}).txt.tmp2" "./tests/out/nDPId_$(basename ${pcap_file}).txt" | wc -l) -eq 0 ]; then
        printf '%s ' '[OUT OK]'
    else
        printf '%s ' '[OUT DIFF EXISTS]'
        EXIT_VALUE=1
    fi

    if [ $(diff "./tests/result/nDPId_$(basename ${pcap_file}).txt.tmp" "./tests/result/nDPId_$(basename ${pcap_file}).txt" | wc -l) -eq 0 ]; then
        printf '%s\n' '[RESULT OK]'
    else
        printf '%s\n' '[RESULT DIFF EXISTS]'
        EXIT_VALUE=1
    fi

    diff "./tests/out/nDPId_$(basename ${pcap_file}).txt.tmp2" "./tests/out/nDPId_$(basename ${pcap_file}).txt" || true
    mv "./tests/out/nDPId_$(basename ${pcap_file}).txt.tmp2" "./tests/out/nDPId_$(basename ${pcap_file}).txt"
    rm -f "./tests/out/nDPId_$(basename ${pcap_file}).txt.tmp"

    diff "./tests/result/nDPId_$(basename ${pcap_file}).txt.tmp" "./tests/result/nDPId_$(basename ${pcap_file}).txt" || true
    mv "./tests/result/nDPId_$(basename ${pcap_file}).txt.tmp" "./tests/result/nDPId_$(basename ${pcap_file}).txt"
    rm -f "./tests/result/nDPId_$(basename ${pcap_file}).txt.tmp"

    kill `cat /tmp/nc.pid`
done

exit ${EXIT_VALUE}
