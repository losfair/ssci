#!/bin/sh

set -e

cd "$(dirname $0)"
RUSTFLAGS="--remap-path-prefix $(pwd)=/build --remap-path-prefix $HOME/.cargo=/cargo" cargo build --release --locked
