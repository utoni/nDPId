#!/usr/bin/env sh

MYDIR="$(dirname ${0})"
cd "${MYDIR}/.."

git subtree pull --squash --prefix=dependencies/jsmn https://github.com/zserge/jsmn.git master
