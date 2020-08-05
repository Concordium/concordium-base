#!/usr/bin/env bash

find . -name Cargo.toml -exec cargo clippy --color=always --all --manifest-path {} -- -Dclippy::all \;
