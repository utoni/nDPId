#!/usr/bin/env bash

set -e

LINE_SPACES=${LINE_SPACES:-48}
MYDIR="$(realpath "$(dirname ${0})")"
nDPId_test_EXEC="$(realpath "${2:-"${MYDIR}/../nDPId-test"}")"
IS_GIT=$(test -d "${MYDIR}/../.git" -o -f "${MYDIR}/../.git" && printf '1' || printf '0')

function usage()
{
cat <<EOF
usage: ${0} [path-to-nDPI-source-root] \\
    [path-to-nDPId-test-exec]

    path-to-nDPId-test-exec defaults to         ${nDPId_test_EXEC}
EOF
return 0
}

test -z "$(which flock)" && { printf '%s\n' 'flock not found'; exit 1; }
test -z "$(which pkill)" && { printf '%s\n' 'pkill not found'; exit 1; }

if [ $# -eq 0 -a -x "${MYDIR}/../libnDPI/tests/cfgs" ]; then
    nDPI_SOURCE_ROOT="${MYDIR}/../libnDPI"
elif [ $# -ne 1 -a $# -ne 2 -a $# -ne 3 -a $# -ne 4 ]; then
    usage
    exit 2
else
    nDPI_SOURCE_ROOT="$(realpath "${1}")"
fi

if [ ! -x "${nDPI_SOURCE_ROOT}/tests/cfgs" ]; then
    printf 'Test config directory %s does not exist or you do not have the permission to access it.\n' "${nDPI_SOURCE_ROOT}/tests/cfgs" >&2
    printf '%s\n' 'Please make also sure that your nDPI library is not too old.'
    exit 2
fi

LOCKFILE="$(realpath "${0}").lock"

touch "${LOCKFILE}"
exec 42< "${LOCKFILE}"
$(which flock) -x -n 42 || {
    printf '%s\n' "Could not aquire file lock for ${0}. Already running instance?" >&2;
    exit 3;
}
function sighandler()
{
    printf '%s\n' ' Received shutdown SIGNAL, bye' >&2
    $(which pkill) -P $$
    wait
    rm -f "${LOCKFILE}"
    exit 4
}
trap sighandler SIGINT SIGTERM

if [ ! -x "${nDPId_test_EXEC}" ]; then
    usage
    printf '\n%s\n' "Required nDPId-test executable does not exist; ${nDPId_test_EXEC}"
    exit 5
fi

nDPI_TEST_DIR="$(realpath "${nDPI_SOURCE_ROOT}/tests")"
cd "${nDPI_TEST_DIR}"

cat <<EOF
nDPId-test: ${nDPId_test_EXEC}
nDPI pcaps: ${nDPI_TEST_DIR} ($(ls -l cfgs/*/pcap/*.pcap cfgs/*/pcap/*.pcapng cfgs/*/pcap/*.cap 2>/dev/null | wc -l) total)

-----------------------------
-- nDPId PCAP config tests --
-----------------------------

EOF

if ! `ls -l cfgs/*/pcap/*.pcap cfgs/*/pcap/*.pcapng cfgs/*/pcap/*.cap >/dev/null 2>/dev/null`; then
    printf '\n%s\n' "Could not find any PCAP files."
    exit 7
fi

mkdir -p /tmp/nDPId-cfgtest-stderr
mkdir -p /tmp/nDPId-cfgtest-stdout

set +e
TESTS_FAILED=0

${nDPId_test_EXEC} -h 2>/dev/null
if [ $? -ne 1 ]; then
    printf '%s\n' "nDPId-test: ${nDPId_test_EXEC} seems to be an invalid executable"
    exit 7
fi

for cfg_file in ${MYDIR}/configs/*.conf; do
    cfg_name="$(basename ${cfg_file})"
    printf 'Config: %s\n' "${cfg_name}"
    for pcap_file in cfgs/*/pcap/*.pcap cfgs/*/pcap/*.pcapng cfgs/*/pcap/*.cap; do
        if [ ! -r "${pcap_file}" ]; then
            printf '%s: %s\n' "${0}" "${pcap_file} does not exist!"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            continue
        fi
        pcap_cfg="$(basename $(dirname $(dirname ${pcap_file})))"
        pcap_name="$(basename ${pcap_file})"
        stdout_file="/tmp/nDPId-cfgtest-stdout/${pcap_cfg}_${pcap_name}.out.new"
        stderr_file="/tmp/nDPId-cfgtest-stderr/${pcap_name}.out"
        printf '%s\n' "-- CMD: ${nDPId_test_EXEC} ${pcap_path}" \
            >${stderr_file}

        timeout --foreground -k 3 -s SIGINT 60 ${nDPId_test_EXEC} "${pcap_file}" "${cfg_file}" \
            >${stdout_file} \
            2>>${stderr_file}
        nDPId_test_RETVAL=$?

        if [ ${nDPId_test_RETVAL} -eq 0 ]; then
            printf '%s' '.'
        else
            printf '%s\n' '[FAIL]'
            printf '%s\n' '----------------------------------------'
            printf '%s\n' "-- STDERR of ${pcap_file}: ${stderr_file}"
            cat "${stderr_file}"
            test -r "/tmp/nDPId-test-stderr/${pcap_name}.strace.out" && cat "/tmp/nDPId-test-stderr/${pcap_name}.strace.out"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    done

    printf '%s\n' 'OK'
done
