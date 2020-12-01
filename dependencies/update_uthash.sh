#!/usr/bin/env sh

MYDIR="$(dirname ${0})"
cd "${MYDIR}/.."

git subtree pull --squash --prefix=dependencies/uthash https://github.com/troydhanson/uthash.git master
