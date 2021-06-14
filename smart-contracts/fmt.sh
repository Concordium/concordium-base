#!/usr/bin/env bash

find . -name Cargo.toml -exec cargo +nightly-2021-06-09 fmt --manifest-path {} \;
