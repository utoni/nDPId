#!/usr/bin/env sh

if [ $# -ne 4 ]; then
    printf 'usage: %s [host:port] [path-to-ca-file] [path-to-cert-file] [path-to-key-file]\n' "${0}"
    exit 1
fi

HOST="${1}"
CAFILE="${2}"
CERTFILE="${3}"
KEYFILE="${4}"

socat tcp-listen:7000,bind=127.0.0.1,fork,reuseaddr openssl-connect:${HOST},cert=${CERTFILE},key=${KEYFILE},cafile=${CAFILE},verify=1,no-sni=1,commonname=nDPIsrvd
