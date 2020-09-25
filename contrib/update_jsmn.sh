#!/usr/bin/env sh

MYDIR="$(dirname ${0})"
cd "${MYDIR}/.."

git subtree pull --squash --prefix=contrib/jsmn https://github.com/zserge/jsmn.git master
