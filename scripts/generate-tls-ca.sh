#!/usr/bin/env sh

set -e

OUTDIR="$(dirname ${0})"

printf 'Output directory: %s\n' "${OUTDIR}"

printf 'ca\ncert_signing_key' > template
certtool --generate-privkey > "${OUTDIR}/ca-key.pem"
certtool --generate-self-signed \
	--template template \
	--load-privkey "${OUTDIR}/ca-key.pem" \
	--outfile "${OUTDIR}/ca-cert.pem"
rm template

printf 'expiration_days = 365' > template
certtool --generate-crl --load-ca-privkey "${OUTDIR}/ca-key.pem" \
	--template template \
	--load-ca-certificate "${OUTDIR}/ca-cert.pem" \
	--outfile "${OUTDIR}/crl.pem"
rm template

printf 'encryption_key\nsigning_key' > template
certtool --generate-privkey > "${OUTDIR}/server-key.pem"
certtool --generate-certificate \
	--template template \
	--load-privkey "${OUTDIR}/server-key.pem" \
	--load-ca-certificate "${OUTDIR}/ca-cert.pem" \
	--load-ca-privkey "${OUTDIR}/ca-key.pem" \
	--outfile "${OUTDIR}/server-cert.pem"
rm template
