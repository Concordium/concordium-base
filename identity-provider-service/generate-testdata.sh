#!/usr/bin/env bash

# This script can be used to generate the test files for the identity provider service unit tests.
# It requires the `jq` tool to be installed, as well as a rust toolchain to build the concordium crypto libraries and tools.
#
# The script should be run from the directory it is in. It will create a
# directory `database` (which can be overriden by setting the TMP_WORK_DIR environment variable with intermediate data files.
# The final artifact is copied to the `data` directory where it is expected by the identity provider tests.

# This should only be needed in rare circumstances when the formats of the identity provider request changes.

set -ea

OUT_DIR=${TMP_WORK_DIR:-"database"}

cargo build --release --manifest-path ../rust-bins/Cargo.toml

CLIENT="../rust-bins/target/release/client"

# Make a directory where we'll store intermediate date.
mkdir $OUT_DIR

# generate global parameters
$CLIENT generate-global --out-file $OUT_DIR/global.json
# generate identity providers and anonymity revokers. We generate two identity providers
# so we can create a valid and an invalid request.
$CLIENT generate-ips --global $OUT_DIR/global.json --num 2 --num-ars 5 --out-dir $OUT_DIR
# Create the PRF key
$CLIENT create-chi --out $OUT_DIR/test-chi.json
# Create the payload of a valid request.
$CLIENT start-ip\
        --ars $OUT_DIR/anonymity_revokers.json\
        --ips $OUT_DIR/identity_providers.json\
        --global $OUT_DIR/global.json\
        --chi $OUT_DIR/test-chi.json\
        --private $OUT_DIR/valid-private.json\
        --public $OUT_DIR/valid_request.json\
        --ip 0\
        --ar-threshold 3\
        --selected-ars 1 3 5
jq '{idObjectRequest: ., redirectURI: "Example.com"}' $OUT_DIR/valid_request.json > data/valid_request.json

# Create the payload of an invalid request.
# The only difference from the previous one is the choice of the identity provider (1 vs. 0)
$CLIENT start-ip\
        --ars $OUT_DIR/anonymity_revokers.json\
        --ips $OUT_DIR/identity_providers.json\
        --global $OUT_DIR/global.json\
        --chi $OUT_DIR/test-chi.json\
        --private $OUT_DIR/invalid-private.json\
        --public $OUT_DIR/invalid_request.json\
        --ip 1\
        --ar-threshold 3\
        --selected-ars 1 3 5
jq '{idObjectRequest: ., redirectURI: "Example.com"}' $OUT_DIR/invalid_request.json > data/fail_validation_request.json

cp $OUT_DIR/{global.json,anonymity_revokers.json} data/
cp $OUT_DIR/identity_provider-0.json data/identity_provider.json
cp $OUT_DIR/identity_provider-0.pub.json data/identity_provider.pub.json
