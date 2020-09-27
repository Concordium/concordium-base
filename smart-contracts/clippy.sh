#!/usr/bin/env bash

find . -name Cargo.toml -exec cargo clippy --color=always --tests --manifest-path {} -- -Dclippy::all \;
