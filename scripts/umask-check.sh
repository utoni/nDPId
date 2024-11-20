#!/usr/bin/env bash

UMASK=$(umask)

if [ "${UMASK}" != "0002" -a "${UMASK}" != "0022" ]; then
    cat <<EOF
********************************************
* WARNING: 'cpack -G DEB' / 'cpack -G RPM' *
* might not work correctly due to umask,   *
* which is set to ${UMASK}                     *
* but expected is either 0002 or 0022      *
********************************************
EOF
fi
