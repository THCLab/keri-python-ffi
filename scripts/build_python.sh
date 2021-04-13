#!/bin/bash

BASE_DIR=$(realpath $(dirname "$0")/..)
LIB_NAME="keri_ecosystem"

cd $BASE_DIR
cargo build --release

mkdir -p "$BASE_DIR/ffi/python/libs/"

cp $BASE_DIR"/target/release/lib${LIB_NAME}.so" "$BASE_DIR/ffi/python/libs/lib${LIB_NAME}.so"