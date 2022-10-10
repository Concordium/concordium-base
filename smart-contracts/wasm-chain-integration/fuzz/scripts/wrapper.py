#!/usr/bin/env python3

# Ensures that the coverage instrumentation happens only for selected crates.
# Otherwise, we currently get linker errors.

import os
import sys

cargo_names = [
               "wasm-chain-integration",
               "wasm-transform",
               "interpreter"
              ]

def include_coverage():
    for i in range(1, len(sys.argv) - 1):
        if sys.argv[i] == "--crate-name" and sys.argv[i + 1] in cargo_names:
            return True
    return False

def adjust_rustc_command():
    args = sys.argv[1:] + ["-Zinstrument-coverage"] if include_coverage() else sys.argv[1:]
    return os.execvp(sys.argv[1], args)

adjust_rustc_command()
