#!/usr/bin/env bash

printf 'usage: %s [out-dir] [client-cert]' "${0}"

if [[ -z "${1}" ]]; then
    OUT_DIR="$(dirname ${0})/pki"
else
    OUT_DIR="${1}"
fi

if [[ -z "${2}" ]]; then
    CLIENT_CERT="./client_distributor_unknown.crt"
else
    CLIENT_CERT="${2}"
fi

printf 'PKI Directory: %s\n' "${OUT_DIR}"
printf 'Client Cert..: %s\n' "${CLIENT_CERT}"

set -e
set -x

OLDPWD="$(pwd)"
mkdir -p "${OUT_DIR}"
cd "${OUT_DIR}"

openssl ca -config ./openssl.conf -revoke "${CLIENT_CERT}" -crl_reason keyCompromise
openssl ca -gencrl -config ./openssl.conf -out ./crl.crt

printf '%s\n' '[*] Done'

cd "${OLDPWD}"
