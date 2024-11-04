#!/usr/bin/env bash

set -e

LINE_SPACES=${LINE_SPACES:-48}
STRACE_EXEC="${STRACE_EXEC}"
MYDIR="$(realpath "$(dirname ${0})")"
nDPId_test_EXEC="$(realpath "${2:-"${MYDIR}/../nDPId-test"}")"
NETCAT_SOCK="/tmp/ndpid-run-tests.sock"
NETCAT_EXEC="$(which nc) -q 0 -Ul ${NETCAT_SOCK}"
JSON_VALIDATOR="$(realpath "${3:-"${MYDIR}/../examples/py-schema-validation/py-schema-validation.py"}")"
SEMN_VALIDATOR="$(realpath "${4:-"${MYDIR}/../examples/py-semantic-validation/py-semantic-validation.py"}")"
FLOW_INFO="$(realpath "${5:-"${MYDIR}/../examples/py-flow-info/flow-info.py"}")"
NDPISRVD_ANALYSED="$(realpath "${6:-"$(dirname ${nDPId_test_EXEC})/nDPIsrvd-analysed"}")"
NDPISRVD_CAPTURED="$(realpath "${6:-"$(dirname ${nDPId_test_EXEC})/nDPIsrvd-captured"}")"
NDPISRVD_COLLECTD="$(realpath "${6:-"$(dirname ${nDPId_test_EXEC})/nDPIsrvd-collectd"}")"
NDPISRVD_INFLUXD="$(realpath "${6:-"$(dirname ${nDPId_test_EXEC})/nDPIsrvd-influxd"}")"
IS_GIT=$(test -d "${MYDIR}/../.git" -o -f "${MYDIR}/../.git" && printf '1' || printf '0')

function usage()
{
cat <<EOF
usage: ${0} [path-to-nDPI-source-root] \\
    [path-to-nDPId-test-exec] [path-to-nDPId-JSON-validator] [path-to-nDPId-SEMANTIC-validator]

    path-to-nDPId-test-exec defaults to         ${nDPId_test_EXEC}
    path-to-nDPId-JSON-validator defaults to    ${JSON_VALIDATOR}
    path-to-nDPId-SEMANTIC-validator default to ${SEMN_VALIDATOR}
    path-to-nDPId-flow-info defaults to         ${FLOW_INFO}
    path-to-nDPIsrvd-analysed defaults to       ${NDPISRVD_ANALYSED}
    path-to-nDPIsrvd-captured defaults to       ${NDPISRVD_CAPTURED}
    path-to-nDPIsrvd-collectd defaults to       ${NDPISRVD_COLLECTD}
    path-to-nDPIsrvd-influxd defaults to        ${NDPISRVD_INFLUXD}
EOF
return 0
}

test -z "$(which flock)" && { printf '%s\n' 'flock not found'; exit 1; }
test -z "$(which pkill)" && { printf '%s\n' 'pkill not found'; exit 1; }
test -z "$(which nc)" && { printf '%s\n' 'nc not found'; exit 1; }
test -z "$(which ss)" && { printf '%s\n' 'ss not found'; exit 1; }
test -z "$(which cat)" && { printf '%s\n' 'cat not found'; exit 1; }
test -z "$(which grep)" && { printf '%s\n' 'grep not found'; exit 1; }

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

$(which nc) -h |& head -n1 | grep -qoE '^OpenBSD netcat' || {
    printf '%s\n' "$(which nc): OpenBSD netcat (nc) version required!" >&2;
    printf '%s\n' "$(which nc): Your version: $(nc -h |& head -n1)" >&2;
    exit 6;
}

nDPI_TEST_DIR="$(realpath "${nDPI_SOURCE_ROOT}/tests")"
cd "${nDPI_TEST_DIR}"

cat <<EOF
nDPId-test: ${nDPId_test_EXEC}
nDPI pcaps: ${nDPI_TEST_DIR} ($(ls -l cfgs/*/pcap/*.pcap cfgs/*/pcap/*.pcapng cfgs/*/pcap/*.cap 2>/dev/null | wc -l) total)

--------------------------
-- nDPId PCAP diff tests --
--------------------------

EOF

if ! `ls -l cfgs/*/pcap/*.pcap cfgs/*/pcap/*.pcapng cfgs/*/pcap/*.cap >/dev/null 2>/dev/null`; then
    printf '\n%s\n' "Could not find any PCAP files."
    exit 7
fi

mkdir -p /tmp/nDPId-test-stderr
mkdir -p /tmp/nDPId-test-stdout

set +e
TESTS_FAILED=0

${nDPId_test_EXEC} -h 2>/dev/null
if [ $? -ne 1 ]; then
    printf '%s\n' "nDPId-test: ${nDPId_test_EXEC} seems to be an invalid executable"
    exit 7
fi

for pcap_file in cfgs/*/pcap/*.pcap cfgs/*/pcap/*.pcapng cfgs/*/pcap/*.cap; do
    if [ ! -r "${pcap_file}" ]; then
        printf '%s: %s\n' "${0}" "${pcap_file} does not exist!"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        continue
    fi
    pcap_cfg="$(basename $(dirname $(dirname ${pcap_file})))"
    pcap_name="$(basename ${pcap_file})"
    pcap_path="$(realpath ${pcap_file})"
    stdout_file="/tmp/nDPId-test-stdout/${pcap_cfg}_${pcap_name}.out.new"
    stderr_file="/tmp/nDPId-test-stderr/${pcap_cfg}_${pcap_name}.out"
    result_file="${MYDIR}/results/${pcap_cfg}/${pcap_name}.out"
    mkdir -p "$(dirname ${result_file})"

    printf "%-${LINE_SPACES}s\t" "${pcap_name}"

    if [ -r "${MYDIR}/configs/${pcap_cfg}.ndpiconf" ]; then
        nDPId_test_cfg="${MYDIR}/configs/${pcap_cfg}.ndpiconf"
    else
        nDPId_test_cfg=""
    fi

    printf '%s\n' "-- CMD: ${nDPId_test_EXEC} ${pcap_path} ${nDPId_test_cfg}" \
        >${stderr_file}
    printf '%s\n' "-- OUT: ${result_file}" \
        >>${stderr_file}

    if [ ! -z "${STRACE_EXEC}" ]; then
        STRACE_CMD="${STRACE_EXEC} -f -e decode-fds=path,socket,dev,pidfd -s 1024 -o /tmp/nDPId-test-stderr/${pcap_name}.strace.out"
    else
        STRACE_CMD=""
    fi
    if [ "x${nDPId_test_cfg}" != "x" ]; then
        timeout --foreground -k 3 -s SIGINT 60 ${STRACE_CMD} ${nDPId_test_EXEC} "${pcap_file}" "${nDPId_test_cfg}" \
            >${stdout_file} \
            2>>${stderr_file}
    else
        timeout --foreground -k 3 -s SIGINT 60 ${STRACE_CMD} ${nDPId_test_EXEC} "${pcap_file}" \
            >${stdout_file} \
            2>>${stderr_file}
    fi
    nDPId_test_RETVAL=$?

    if [ ${nDPId_test_RETVAL} -eq 0 ]; then
        if [ ! -r "${result_file}" ]; then
            printf '%s\n' '[NEW]'
            test ${IS_GIT} -eq 1 && \
                mv "${stdout_file}" "${result_file}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        elif diff -u0 "${result_file}" "${stdout_file}" >/dev/null; then
            printf '%s\n' '[OK]'
            rm -f "${stdout_file}"
        else
            printf '%s\n' '[DIFF]'
            diff -u0 "${result_file}" "${stdout_file}"
            test ${IS_GIT} -eq 1 && \
                mv "${stdout_file}" "${result_file}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    else
        printf '%s\n' '[FAIL]'
        printf '%s\n' '----------------------------------------'
        printf '%s\n' "-- STDERR of ${pcap_file}: ${stderr_file}"
        cat "${stderr_file}"
        test -r "/tmp/nDPId-test-stderr/${pcap_name}.strace.out" && cat "/tmp/nDPId-test-stderr/${pcap_name}.strace.out"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
done

for out_file in ${MYDIR}/results/*/*.out; do
    pcap_file="$(basename ${out_file%.out})"
    pcap_cfg="$(basename $(dirname ${out_file%.out}))"
    if [ ! -r "cfgs/${pcap_cfg}/pcap/${pcap_file}" ]; then
        printf "%-${LINE_SPACES}s\t%s\n" "${pcap_file}" "[MISSING][config: ${pcap_cfg}]"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
done

function validate_results()
{
    prefix_str="${1}"
    pcap_cfg="${2}"
    pcap_name="$(basename ${3})"
    result_file="${4}"
    validator_exec="${5}"

    stderr_file="/tmp/nDPId-test-stderr/${pcap_cfg}_${pcap_name}.out"
    printf "%s %-$((${LINE_SPACES} - ${#prefix_str}))s\t" "${prefix_str}" "${pcap_name}"
    printf '%s\n' "-- ${prefix_str}" >>"${stderr_file}"

    if [ ! -r "${result_file}" ]; then
        printf ' %s\n' "[MISSING][config: ${pcap_cfg}]"
        return 1
    fi

    # Note that the grep command is required as we generate a summary in the results file.
    cat "${result_file}" | grep -vE '^~~.*$' | ${NETCAT_EXEC} &
    nc_pid=$!
    printf '%s\n' "-- ${validator_exec}" >>"${stderr_file}"
    ${validator_exec} 2>>"${stderr_file}"
    if [ $? -eq 0 ]; then
        printf ' %s\n' '[OK]'
        rc=0
    else
        printf ' %s\n' '[FAIL]'
        printf '%s\n' '----------------------------------------'
        printf '%s\n' "-- STDERR of ${pcap_file}: ${stderr_file}"
        cat "${stderr_file}"
        rc=1
    fi
    kill -SIGTERM ${nc_pid} 2>/dev/null
    wait ${nc_pid} 2>/dev/null

    return ${rc}
}

cat <<EOF

--------------------
-- Flow Info DIFF --
--------------------

EOF

cd "${MYDIR}"
mkdir -p "${MYDIR}/results/flow-info"
for out_file in results/*/*.out; do
    if [ ! -r "${out_file}" ]; then
        printf '%s: %s\n' "${0}" "${out_file} does not exist!"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        continue
    fi
    out_name="$(basename ${out_file})"
    pcap_cfg="$(basename $(dirname ${out_file%.out}))"
    stdout_file="/tmp/nDPId-test-stdout/${pcap_cfg}_${out_name}.flow-info.new"
    stderr_file="/tmp/nDPId-test-stderr/${pcap_cfg}_${out_name}"
    result_file="${MYDIR}/results/flow-info/${pcap_cfg}/${out_name}"
    mkdir -p "$(dirname ${result_file})"
    printf "%-${LINE_SPACES}s\t" "${out_name}"
    cat "${out_file}" | grep -vE '^~~.*$' | ${NETCAT_EXEC} &
    nc_pid=$!
    ${FLOW_INFO} --unix "${NETCAT_SOCK}" \
        --no-color --no-statusbar --hide-instance-info \
        --print-analyse-results --print-hostname >"${stdout_file}" 2>>"${stderr_file}"
    kill -SIGTERM ${nc_pid} 2>/dev/null
    wait ${nc_pid} 2>/dev/null
    if [ ! -r "${result_file}" ]; then
        printf '%s\n' '[NEW]'
        test ${IS_GIT} -eq 1 && \
            mv "${stdout_file}" "${result_file}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    elif diff -u0 "${result_file}" "${stdout_file}" >/dev/null; then
        printf '%s\n' '[OK]'
        rm -f "${stdout_file}"
    else
        printf '%s\n' '[DIFF]'
        diff -u0 "${result_file}" "${stdout_file}"
        test ${IS_GIT} -eq 1 && \
            mv "${stdout_file}" "${result_file}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
done

for out_file in ${MYDIR}/results/flow-info/*/*.out; do
    if [ ! -r "${out_file}" ]; then
        printf '%s: %s\n' "${0}" "${out_file} does not exist!"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        continue
    fi
    result_file="$(basename ${out_file})"
    pcap_cfg="$(basename $(dirname ${out_file%.out}))"
    if [ ! -r "${MYDIR}/results/${pcap_cfg}/${result_file}" ]; then
        printf "%-${LINE_SPACES}s\t%s\n" "${result_file}" "[MISSING][config: ${pcap_cfg}]"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
done

cat <<EOF

-----------------------
-- Flow Analyse DIFF --
-----------------------

EOF

mkdir -p "${MYDIR}/results/flow-analyse"
if [ -x "${NDPISRVD_ANALYSED}" ]; then
    cd "${MYDIR}"
    for out_file in results/*/*.out; do
        if [ ! -r "${out_file}" ]; then
            printf '%s: %s\n' "${0}" "${out_file} does not exist!"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            continue
        fi
        out_name="$(basename ${out_file})"
        pcap_cfg="$(basename $(dirname ${out_file%.out}))"
        stdout_file="/tmp/nDPId-test-stdout/${pcap_cfg}_${out_name}.flow-analyse.csv.new"
        stderr_file="/tmp/nDPId-test-stderr/${pcap_cfg}_${out_name}"
        result_file="${MYDIR}/results/flow-analyse/${pcap_cfg}/${out_name}"
        mkdir -p "$(dirname ${result_file})"
        printf "%-${LINE_SPACES}s\t" "${out_name}"
        cat "${out_file}" | grep -vE '^~~.*$' | ${NETCAT_EXEC} &
        nc_pid=$!
        while ! ss -x -t -n -l | grep -q "${NETCAT_SOCK}"; do sleep 0.1; printf '%s\n' "Waiting until socket ${NETCAT_SOCK} is available.." >>"${stderr_file}"; done
        ${NDPISRVD_ANALYSED} -l -s "${NETCAT_SOCK}" -o "${stdout_file}" 2>>"${stderr_file}" 1>&2
        kill -SIGTERM ${nc_pid} 2>/dev/null
        wait ${nc_pid} 2>/dev/null
        while ss -x -t -n -l | grep -q "${NETCAT_SOCK}"; do sleep 0.1; printf '%s\n' "Waiting until socket ${NETCAT_SOCK} is not available anymore.." >>"${stderr_file}"; done
        if [ ! -r "${result_file}" ]; then
            printf '%s\n' '[NEW]'
            test ${IS_GIT} -eq 1 && \
                mv "${stdout_file}" "${result_file}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        elif diff -u0 "${result_file}" "${stdout_file}" >/dev/null; then
            printf '%s\n' '[OK]'
            rm -f "${stdout_file}"
        else
            printf '%s\n' '[DIFF]'
            diff -u0 "${result_file}" "${stdout_file}"
            test ${IS_GIT} -eq 1 && \
                mv "${stdout_file}" "${result_file}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    done

    for out_file in ${MYDIR}/results/flow-analyse/*/*.out; do
        if [ ! -r "${out_file}" ]; then
            printf '%s: %s\n' "${0}" "${out_file} does not exist!"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            continue
        fi
        result_file="$(basename ${out_file})"
        pcap_cfg="$(basename $(dirname ${out_file%.out}))"
        if [ ! -r "${MYDIR}/results/${pcap_cfg}/${result_file}" ]; then
            printf "%-${LINE_SPACES}s\t%s\n" "${result_file}" "[MISSING][config: ${pcap_cfg}]"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    done
else
    printf '%s\n' "Not found or not executable: ${NDPISRVD_ANALYSED}"
fi

cat <<EOF

------------------------
-- Flow Captured DIFF --
------------------------

EOF

mkdir -p "${MYDIR}/results/flow-captured"
if [ -x "${NDPISRVD_CAPTURED}" ]; then
    cd "${MYDIR}"
    for out_file in results/*/*.out; do
        if [ ! -r "${out_file}" ]; then
            printf '%s: %s\n' "${0}" "${out_file} does not exist!"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            continue
        fi
        out_name="$(basename ${out_file})"
        pcap_cfg="$(basename $(dirname ${out_file%.out}))"
        stdout_file="/tmp/nDPId-test-stdout/${pcap_cfg}_${out_name}.flow-captured.csv.new"
        stderr_file="/tmp/nDPId-test-stderr/${pcap_cfg}_${out_name}"
        result_file="${MYDIR}/results/flow-captured/${pcap_cfg}/${out_name}"
        mkdir -p "$(dirname ${result_file})"
        printf "%-${LINE_SPACES}s\t" "${out_name}"
        cat "${out_file}" | grep -vE '^~~.*$' | ${NETCAT_EXEC} &
        nc_pid=$!
        while ! ss -x -t -n -l | grep -q "${NETCAT_SOCK}"; do sleep 0.1; printf '%s\n' "Waiting until socket ${NETCAT_SOCK} is available.." >>"${stderr_file}"; done
        ${NDPISRVD_CAPTURED} -s "${NETCAT_SOCK}" -c -l -G -U -R0 -M -E 2>>"${stderr_file}" 1>"${stdout_file}"
        kill -SIGTERM ${nc_pid} 2>/dev/null
        wait ${nc_pid} 2>/dev/null
        while ss -x -t -n -l | grep -q "${NETCAT_SOCK}"; do sleep 0.1; printf '%s\n' "Waiting until socket ${NETCAT_SOCK} is not available anymore.." >>"${stderr_file}"; done
        if [ ! -r "${result_file}" ]; then
            printf '%s\n' '[NEW]'
            test ${IS_GIT} -eq 1 && \
                mv "${stdout_file}" "${result_file}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        elif diff -u0 "${result_file}" "${stdout_file}" >/dev/null; then
            printf '%s\n' '[OK]'
            rm -f "${stdout_file}"
        else
            printf '%s\n' '[DIFF]'
            diff -u0 "${result_file}" "${stdout_file}"
            test ${IS_GIT} -eq 1 && \
                mv "${stdout_file}" "${result_file}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    done

    for out_file in ${MYDIR}/results/flow-captured/*/*.out; do
        if [ ! -r "${out_file}" ]; then
            printf '%s: %s\n' "${0}" "${out_file} does not exist!"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            continue
        fi
        result_file="$(basename ${out_file})"
        pcap_cfg="$(basename $(dirname ${out_file%.out}))"
        if [ ! -r "${MYDIR}/results/${pcap_cfg}/${result_file}" ]; then
            printf "%-${LINE_SPACES}s\t%s\n" "${result_file}" "[MISSING][config: ${pcap_cfg}]"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    done
else
    printf '%s\n' "Not found or not executable: ${NDPISRVD_CAPTURED}"
fi

cat <<EOF

------------------------------
-- Collectd Statistics DIFF --
------------------------------

EOF

if [ -x "${NDPISRVD_COLLECTD}" ]; then
    cd "${MYDIR}"
    for out_file in results/*/*.out; do
        if [ ! -r "${out_file}" ]; then
            printf '%s: %s\n' "${0}" "${out_file} does not exist!"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            continue
        fi
        out_name="$(basename ${out_file})"
        pcap_cfg="$(basename $(dirname ${out_file%.out}))"
        stdout_file="/tmp/nDPId-test-stdout/${pcap_cfg}_${out_name}.stats.new"
        stderr_file="/tmp/nDPId-test-stderr/${pcap_cfg}_${out_name}"
        result_file="${MYDIR}/results/stats/${pcap_cfg}/${out_name}"
        mkdir -p "$(dirname ${result_file})"
        printf "%-${LINE_SPACES}s\t" "${out_name}"
        cat "${out_file}" | grep -vE '^~~.*$' | ${NETCAT_EXEC} &
        nc_pid=$!
        while ! ss -x -t -n -l | grep -q "${NETCAT_SOCK}"; do sleep 0.1; printf '%s\n' "Waiting until socket ${NETCAT_SOCK} is available.." >>"${stderr_file}"; done
        ${NDPISRVD_COLLECTD} -l -s "${NETCAT_SOCK}" 2>>"${stderr_file}" 1>"${stdout_file}"
        kill -SIGTERM ${nc_pid} 2>/dev/null
        wait ${nc_pid} 2>/dev/null
        while ss -x -t -n -l | grep -q "${NETCAT_SOCK}"; do sleep 0.1; printf '%s\n' "Waiting until socket ${NETCAT_SOCK} is not available anymore.." >>"${stderr_file}"; done

        unknown_count="$(cat "${stdout_file}" | grep -E 'flow_.*_unknown' | wc -l || printf '%s' '0')"
        if [ "${unknown_count}" -ne 5 ]; then
            printf '%s: Unknown count: %s\n' '[INTERNAL]' "${unknown_count}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        elif cat "${stdout_file}" | grep -E 'flow_.*_unknown' | grep -qvE 'N:0'; then
            printf '%s\n' '[INTERNAL]'
            cat "${stdout_file}" | grep -E 'flow_.*_unknown' | grep -vE 'N:0' || true
            TESTS_FAILED=$((TESTS_FAILED + 1))
        elif [ ! -r "${result_file}" ]; then
            printf '%s\n' '[NEW]'
            test ${IS_GIT} -eq 1 && \
                mv "${stdout_file}" "${result_file}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        elif diff -u0 "${result_file}" "${stdout_file}" >/dev/null; then
            printf '%s\n' '[OK]'
            rm -f "${stdout_file}"
        else
            printf '%s\n' '[DIFF]'
            diff -u0 "${result_file}" "${stdout_file}"
            test ${IS_GIT} -eq 1 && \
                mv "${stdout_file}" "${result_file}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    done

    for out_file in ${MYDIR}/results/stats/*/*.out; do
        if [ ! -r "${out_file}" ]; then
            printf '%s: %s\n' "${0}" "${out_file} does not exist!"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            continue
        fi
        result_file="$(basename ${out_file})"
        pcap_cfg="$(basename $(dirname ${out_file%.out}))"
        if [ ! -r "${MYDIR}/results/${pcap_cfg}/${result_file}" ]; then
            printf "%-${LINE_SPACES}s\t%s\n" "${result_file}" "[MISSING][config: ${pcap_cfg}]"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    done
else
    printf '%s\n' "Not found or not executable: ${NDPISRVD_COLLECTD}"
fi

cat <<EOF

-----------------------------
-- Influxd Statistics DIFF --
-----------------------------

EOF

if [ -x "${NDPISRVD_INFLUXD}" ]; then
    cd "${MYDIR}"
    for out_file in results/*/*.out; do
        if [ ! -r "${out_file}" ]; then
            printf '%s: %s\n' "${0}" "${out_file} does not exist!"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            continue
        fi
        out_name="$(basename ${out_file})"
        pcap_cfg="$(basename $(dirname ${out_file%.out}))"
        stdout_file="/tmp/nDPId-test-stdout/${pcap_cfg}_${out_name}.influxd.new"
        stderr_file="/tmp/nDPId-test-stderr/${pcap_cfg}_${out_name}"
        result_file="${MYDIR}/results/influxd/${pcap_cfg}/${out_name}"
        mkdir -p "$(dirname ${result_file})"
        printf "%-${LINE_SPACES}s\t" "${out_name}"
        cat "${out_file}" | grep -vE '^~~.*$' | ${NETCAT_EXEC} &
        nc_pid=$!
        while ! ss -x -t -n -l | grep -q "${NETCAT_SOCK}"; do sleep 0.1; printf '%s\n' "Waiting until socket ${NETCAT_SOCK} is available.." >>"${stderr_file}"; done
        ${NDPISRVD_INFLUXD} -t -i 10 -c -s "${NETCAT_SOCK}" 2>>"${stderr_file}" 1>"${stdout_file}"
        kill -SIGTERM ${nc_pid} 2>/dev/null
        wait ${nc_pid} 2>/dev/null
        while ss -x -t -n -l | grep -q "${NETCAT_SOCK}"; do sleep 0.1; printf '%s\n' "Waiting until socket ${NETCAT_SOCK} is not available anymore.." >>"${stderr_file}"; done

        unknown_count="$(cat "${stdout_file}" | tr ' ' '\n' | tr ',' '\n' | grep -E '^flow.*_unknown' | wc -l || printf '%s' '0')"
        if [ "${unknown_count}" -ne 5 ]; then
            printf '%s: Unknown count: %s\n' '[INTERNAL]' "${unknown_count}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        elif cat "${stdout_file}" | tr ' ' '\n' | tr ',' '\n' | grep -E '^flow.*_unknown' | grep -qvE '=0'; then
            printf '%s\n' '[INTERNAL]'
            cat "${stdout_file}" | tr ' ' '\n' | tr ',' '\n' | grep -E '^flow.*_unknown' | grep -vE '=0' || true
            TESTS_FAILED=$((TESTS_FAILED + 1))
        elif [ ! -r "${result_file}" ]; then
            printf '%s\n' '[NEW]'
            test ${IS_GIT} -eq 1 && \
                mv "${stdout_file}" "${result_file}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        elif diff -u0 "${result_file}" "${stdout_file}" >/dev/null; then
            printf '%s\n' '[OK]'
            rm -f "${stdout_file}"
        else
            printf '%s\n' '[DIFF]'
            diff -u0 "${result_file}" "${stdout_file}"
            test ${IS_GIT} -eq 1 && \
                mv "${stdout_file}" "${result_file}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    done

    for out_file in ${MYDIR}/results/influxd/*/*.out; do
        if [ ! -r "${out_file}" ]; then
            printf '%s: %s\n' "${0}" "${out_file} does not exist!"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            continue
        fi
        result_file="$(basename ${out_file})"
        pcap_cfg="$(basename $(dirname ${out_file%.out}))"
        if [ ! -r "${MYDIR}/results/${pcap_cfg}/${result_file}" ]; then
            printf "%-${LINE_SPACES}s\t%s\n" "${result_file}" "[MISSING][config: ${pcap_cfg}]"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    done
else
    printf '%s\n' "Not found or not executable: ${NDPISRVD_INFLUXD}"
fi

cat <<EOF

--------------------------------
-- SCHEMA/SEMANTIC Validation --
--------------------------------

netcat (OpenBSD) exec + args: ${NETCAT_EXEC}

EOF

cd "${MYDIR}"
for out_file in results/*/*.out; do
    if [ ! -r "${out_file}" ]; then
        printf '%s: %s\n' "${0}" "${out_file} does not exist!"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        continue
    fi
    out_name="$(basename ${out_file})"
    pcap_cfg="$(basename $(dirname ${out_file%.out}))"
    result_file="${MYDIR}/results/${pcap_cfg}/${out_name}"
    if [ ! -r "${result_file}" ]; then
        printf "%-${LINE_SPACES}s\t%s\n" "${out_name}" "[MISSING][config: ${pcap_cfg}]"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    else
        validate_results "SCHEMA  " "${pcap_cfg}" "${out_name%.out}" "${out_file}" \
            "${JSON_VALIDATOR} --unix ${NETCAT_SOCK}"
        if [ $? -ne 0 ]; then
            TESTS_FAILED=$((TESTS_FAILED + 1))
            continue
        fi

        validate_results "SEMANTIC" "${pcap_cfg}" "${out_name%.out}" "${out_file}" \
            "${SEMN_VALIDATOR} --unix ${NETCAT_SOCK} --strict"
        if [ $? -ne 0 ]; then
            TESTS_FAILED=$((TESTS_FAILED + 1))
            continue
        fi
    fi
done

cat <<EOF

Done. For more information see text files in:
    /tmp/nDPId-test-stdout/
    /tmp/nDPId-test-stderr/

EOF

if [ ${TESTS_FAILED} -eq 0 ]; then
cat <<EOF

--------------------------
-- All tests succeeded. --
--------------------------
EOF
    exit 0
else
cat <<EOF

*** ${TESTS_FAILED} tests failed. ***
EOF
    exit 1
fi
