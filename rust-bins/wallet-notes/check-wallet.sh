#!/usr/bin/env bash

set -eaxo pipefail

cargo build --release --manifest-path ../../rust-src/Cargo.toml
gcc example.c -lwallet -L ../../rust-src/target/release/ -o example
export LD_LIBRARY_PATH=../../rust-src/target/release/
./example ./files/create_transfer-input.json | jq > ./files/create_transfer-output.json
./example ./files/create_encrypted_transfer-input.json | jq > ./files/create_encrypted_transfer-output.json
./example ./files/create_pub_to_sec_transfer-input.json | jq > ./files/create_pub_to_sec_transfer-output.json
./example ./files/create_sec_to_pub_transfer-input.json | jq > ./files/create_sec_to_pub_transfer-output.json
./example ./files/create_id_request_and_private_data-input.json | jq > ./files/create_id_request_and_private_data-output.json
./example ./files/create_credential-input.json | jq > ./files/create_credential-output.json
./example ./files/generate-accounts-input.json | jq > ./files/generate-accounts-output.json
