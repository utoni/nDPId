#!/bin/sh

printf 'usage: %s [out-pem-private-key-file] [out-pem-public-key-file]\n' "${0}"

if [ -z "${1}" ]; then
    PRIV_KEY="./nDPId-x25519-priv.pem"
else
    PRIV_KEY="${1}"
fi

if [ -z "${2}" ]; then
    PUB_KEY="./nDPId-x25519-pub.pem"
else
    PUB_KEY="${2}"
fi

printf 'Private Key: %s\n' "${PRIV_KEY}"
printf 'Public Key.: %s\n' "${PUB_KEY}"

openssl genpkey -algorithm x25519 -out "${PRIV_KEY}"
openssl pkey -in "${PRIV_KEY}" -outform PEM -pubout -out "${PUB_KEY}"
