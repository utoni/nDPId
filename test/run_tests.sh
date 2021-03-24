#!/usr/bin/env sh

set -e

LINE_SPACES=${LINE_SPACES:-48}
MYDIR="$(realpath "$(dirname ${0})")"
nDPId_test_EXEC="${2:-"$(realpath "${MYDIR}/../nDPId-test")"}"
nDPI_SOURCE_ROOT="${1}"

if [ $# -ne 1 -a $# -ne 2 ]; then
cat <<EOF
usage: ${0} [path-to-nDPI-source-root] [path-to-nDPId-test-exec]

	path-to-nDPId-test-exec defaults to ${nDPId_test_EXEC}
EOF
exit 1
fi

if [ ! -x "${nDPId_test_EXEC}" ]; then
cat <<EOF
Required nDPId-test executable does not exist; ${nDPId_test_EXEC}
EOF
exit 1
fi

nDPI_TEST_DIR="${nDPI_SOURCE_ROOT}/tests/pcap"

cat <<EOF
nDPId-test......: ${nDPId_test_EXEC}
nDPI source root: ${nDPI_TEST_DIR}

EOF

cd "${nDPI_TEST_DIR}"
mkdir -p /tmp/nDPId-test-stderr
set +e
RETVAL=0
for pcap_file in $(ls *.pcap*); do
    ${nDPId_test_EXEC} "${pcap_file}" \
        >"${MYDIR}/results/${pcap_file}.out.new" \
        2>"/tmp/nDPId-test-stderr/${pcap_file}.out"

    if [ $? -eq 0 ]; then
        if diff -u0 "${MYDIR}/results/${pcap_file}.out" \
                    "${MYDIR}/results/${pcap_file}.out.new" >/dev/null; then
            printf "%-${LINE_SPACES}s\t%s\n" "${pcap_file}" '[OK]'
        else
            printf "%-${LINE_SPACES}s\t%s\n" "${pcap_file}" '[DIFF]'
            diff -u0 "${MYDIR}/results/${pcap_file}.out" \
                     "${MYDIR}/results/${pcap_file}.out.new"
            mv -v "${MYDIR}/results/${pcap_file}.out.new" \
                  "${MYDIR}/results/${pcap_file}.out"
            RETVAL=1
        fi
    else
        printf "%-${LINE_SPACES}s\t%s\n" "${pcap_file}" '[FAIL]'
        printf '%s\n' '----------------------------------------'
        printf '%s\n' "-- STDERR of ${pcap_file}"
        cat "/tmp/nDPId-test-stderr/${pcap_file}.out"
        RETVAL=1
    fi

    rm -f "${MYDIR}/results/${pcap_file}.out.new"
done

exit ${RETVAL}
