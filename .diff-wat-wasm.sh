#!/usr/bin/env bash

# Check that committed .wasm files correspond to the given .wat files.
# The .wasm files are committed for convenience in testing, so that people
# who do not touch the scheduler or smart contracts do not need all the Wasm tooling installed.

# This script should be run from the directory that it resides in. The idea is
# to report all the files that failed, hence no early exit from the script.


pushd smart-contracts/testdata/contracts || exit

# Files which should only be converted, not validated/checked.
NO_CHECK_FILES=(
    # Our interpreter accepts this file, but wat2wasm does not due to a change in the wasm spec.
    # See https://github.com/Concordium/concordium-base/issues/331 for more info.
    './global-offset-test.wat',

    # This module is invalid because it tries to use a mutable global value as an offset in the data and elem section.
    './mut-global-offset-test.wat',

    # This module is invalid because it tries to initialize a global value with the reference of another global value.
    './init-global-with-ref-test.wat'
    )

RET=0

for wat in $(find . -name '*.wat'); do
   OUT=$(mktemp)

   # Convert to wasm.
   if [[ "${NO_CHECK_FILES[*]}" =~ "$wat" ]]; then
     echo "Comparing: '$wat' (with --no-check)"
     wat2wasm "$wat" -o "$OUT" --no-check;
     continue
   else
     echo "Comparing: $wat"
     wat2wasm "$wat" -o "$OUT";
   fi

   if ! diff "$OUT" "${wat%.wat}.wasm"
   then
     RET=1
     echo "The $wat contract's .wasm output does not match the expected one. Regenerate the .wasm file."
   fi
   rm "$OUT"
done

popd || exit

exit $RET
