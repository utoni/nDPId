#!/usr/bin/env bash

set -e

cd "$(dirname "${0}")/.."
mkdir -p coverage_report
lcov --directory . --capture --output-file lcov.info
genhtml -o coverage_report lcov.info
