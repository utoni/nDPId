#!/usr/bin/env sh

set -e

OUTDIR="$(dirname ${0})"

printf 'Output directory: %s\n' "${OUTDIR}"

printf 'encryption_key\nsigning_key' > template
certtool --generate-privkey > "${OUTDIR}/client-key.pem"
certtool --generate-certificate \
	--template template \
	--load-privkey "${OUTDIR}/client-key.pem" \
	--load-ca-certificate "${OUTDIR}/ca-cert.pem" \
	--load-ca-privkey "${OUTDIR}/ca-key.pem" \
	--outfile "${OUTDIR}/client-cert.pem"
rm template
