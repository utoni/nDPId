#!/usr/bin/env bash

printf 'usage: %s [out-dir] [client-cname] [server-cname]\n' "${0}"

if [ -z "${1}" ]; then
    OUT_DIR="$(dirname ${0})/pki"
else
    OUT_DIR="${1}"
fi

if [ -z "${2}" ]; then
    CLIENT_CN="unknown"
else
    CLIENT_CN="${2}"
fi

if [ -z "${3}" ]; then
    SERVER_CN="unknown"
else
    SERVER_CN="${3}"
fi

printf 'PKI Directory: %s\n' "${OUT_DIR}"
printf 'Client CName.: %s\n' "${CLIENT_CN}"
printf 'Server CName.: %s\n' "${SERVER_CN}"

set -e
set -x

OLDPWD="$(pwd)"
mkdir -p "${OUT_DIR}"
cd "${OUT_DIR}"

if [ ! -r ./ca.key -o ! -r ./ca.crt ]; then
    printf '%s\n' '[*] Create CA...'
    openssl genrsa -out ./ca.key 4096
    openssl req -x509 -new -nodes -key ./ca.key -sha256 -days 3650 -out ./ca.crt -subj "/CN=nDPId Root CA"
fi

if [ ! -r ./server_${SERVER_CN}.key -o ! -r ./server_${SERVER_CN}.crt ]; then
    printf '[*] Create Server Cert: %s\n' "${SERVER_CN}"
    openssl genrsa -out ./server_${SERVER_CN}.key 2048
    openssl req -new -key ./server_${SERVER_CN}.key -out ./server_${SERVER_CN}.csr -subj "/CN=${SERVER_CN}"
    openssl x509 -req -in ./server_${SERVER_CN}.csr -CA ./ca.crt -CAkey ./ca.key -CAcreateserial \
        -out ./server_${SERVER_CN}.crt -days 825 -sha256
fi

if [ ! -r ./client_${CLIENT_CN}.key -o ! -r ./client_${CLIENT_CN}.crt ]; then
    printf '[*] Create Client Cert: %s\n' "${CLIENT_CN}"
    openssl genrsa -out ./client_${CLIENT_CN}.key 2048
    openssl req -new -key ./client_${CLIENT_CN}.key -out ./client_${CLIENT_CN}.csr -subj "/CN=${CLIENT_CN}"
    openssl x509 -req -in ./client_${CLIENT_CN}.csr -CA ./ca.crt -CAkey ./ca.key -CAcreateserial \
        -out ./client_${CLIENT_CN}.crt -days 825 -sha256
fi

printf '%s\n' '[*] Done'

cd "${OLDPWD}"

set +x

printf '%s\n' 'To test the certs you may use OpenSSL and start a client/server with:'
printf 'openssl s_server -accept %s -cert %s -key %s -CAfile %s -Verify 1 -verify_return_error -tls1_3\n' \
    "7777" \
    "${OUT_DIR}/server_${SERVER_CN}.crt" "${OUT_DIR}/server_${SERVER_CN}.key" \
    "${OUT_DIR}/ca.crt"
printf 'openssl s_client -connect 127.0.0.1:%s -cert %s -key %s -CAfile %s -verify_return_error -tls1_3\n' \
    "7777" \
    "${OUT_DIR}/client_${CLIENT_CN}.crt" "${OUT_DIR}/client_${CLIENT_CN}.key" \
    "${OUT_DIR}/ca.crt"
