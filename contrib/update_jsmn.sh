#!/usr/bin/env sh

MYDIR="$(dirname ${0})"
cd "${MYDIR}/.."

git subtree pull --prefix=contrib/jsmn https://github.com/zserge/jsmn.git master
