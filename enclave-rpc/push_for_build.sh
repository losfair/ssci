#!/bin/sh

set -e

cargo build --release

scp ./target/x86_64-unknown-linux-musl/release/enclave-rpc ./Dockerfile ./sshd_config \
    enclave-dev-1:/home/ec2-user/enclave-rpc-build/
