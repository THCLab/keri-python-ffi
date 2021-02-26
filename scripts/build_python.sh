#!/bin/bash

BASE_DIR=$(realpath $(dirname "$0")/..)
LIB_NAME="kel_utils"

cd $BASE_DIR
cargo build --release

cp $BASE_DIR"/target/release/lib${LIB_NAME}.so" "$BASE_DIR/ffi/python/libs/lib${LIB_NAME}.so"