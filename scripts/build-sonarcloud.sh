#!/usr/bin/env bash

set -e
set -x

cd "$(dirname "${0}")/.."

BUILD_DIR=./build-sonarcloud
NUMBER_OF_PROCESSORS=$(nproc --all)
mkdir "${BUILD_DIR}"
cmake -S . -B "${BUILD_DIR}" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DENABLE_COVERAGE=ON \
    -DBUILD_NDPI=ON \
    -DBUILD_EXAMPLES=ON \
    -DENABLE_CURL=ON \
    -DENABLE_ZLIB=ON \
    -DNDPI_WITH_GCRYPT=OFF
cmake --build "${BUILD_DIR}" -j ${NUMBER_OF_PROCESSORS} \
    --config Release
