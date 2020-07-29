#!/usr/bin/env bash

find . -name Cargo.toml -exec cargo +nightly-2019-11-13 fmt --manifest-path {} \;
