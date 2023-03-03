#!/usr/bin/env bash

# Check that committed .wasm files correspond to the given .wat files.
# The .wasm files are committed for convenience in testing, so that people
# who do not touch the scheduler or smart contracts do not need all the Wasm tooling installed.

# This script should be run from the directory that it resides in. The idea is
# to report all the files that failed, hence no early exit from the script.
#
# The script will ignore wat files listed in `/smart-contracts/testdata/contracts/.diff-wat-wasm-ignore`.


pushd smart-contracts/testdata/contracts || exit

# Create an array with all the files to ignore.
declare FILES_TO_IGNORE
while read -r line
do
   # Ignore lines starting comments (lines starting with #) and empty lines.
   [[ "$line" =~ ^#.*$|^$ ]] && continue

   FILES_TO_IGNORE+=("$line")
done < "./.diff-wat-wasm-ignore"

RET=0

for wat in $(find . -name '*.wat'); do
   # Skip the file if it is in the ignore list.
   if [[ "${FILES_TO_IGNORE[*]}" =~ "$wat" ]]; then
     echo "Ignoring file: '$wat'"
     continue
   fi
   echo "Validating file: '$wat'"
   # Otherwise, continue with the check.
   OUT=$(mktemp)
   wat2wasm "$wat" -o "$OUT";
   if ! diff "$OUT" "${wat%.wat}.wasm"
   then
     RET=1
     echo "The $wat contract's .wasm output does not match the expected one. Regenerate the .wasm file."
   fi
   rm "$OUT"
done

popd || exit

exit $RET
