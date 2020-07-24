#!/usr/bin/env bash

find . -name Cargo.toml -exec cargo +nightly-2019-10-28 fmt --manifest-path {} \;
