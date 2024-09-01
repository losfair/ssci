#!/bin/sh

set -e

cargo build --release --locked
cp ./target/x86_64-unknown-linux-musl/release/enclave-rpc .
docker build -t enclave-rpc .
nitro-cli build-enclave --docker-uri enclave-rpc:latest --output-file enclave-rpc.eif 
