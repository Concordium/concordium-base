#!/usr/bin/env python3

# To do everything (create raw coverage files, merge them, and create HTML report):
# ./generate-coverage.py <corpus-dir>
#
# To only create merge raw files and generate HTML report:
# ./generate-coverage.py merge

import os
from os.path import isfile, join, normpath
import subprocess
import sys
from tqdm import tqdm

target = "interpreter"
coverage_dir = normpath("fuzz/coverage/" + target)
raw_dir = normpath(coverage_dir + "/raw")
profdata_file = join(coverage_dir, target + ".profdata")

if not sys.argv[1] == "merge":

    corpus_dir = sys.argv[1] if not sys.argv[1] == "clean" else sys.argv[2]

    # Create fuzz/coverage/raw/<target>/ directory
    os.makedirs(os.path.dirname(raw_dir), exist_ok=True)

    # Create cargo fuzz command that will output raw coverage information
    print("Generating", len(os.listdir(corpus_dir)), "raw coverage files...")
    env_with_wrapper = os.environ.copy()
    env_with_wrapper["RUSTC_WRAPPER"] = "./wrapper.py"
    for f in tqdm(os.listdir(corpus_dir)):
        corpus_file = join(corpus_dir, f)
        raw_name = join(raw_dir, f) + ".profraw"
        devnull = open(os.devnull, 'w')
        if isfile(corpus_file) and not os.path.exists(raw_name):
            env_with_wrapper["LLVM_PROFILE_FILE"] = raw_name
            subprocess.run(["cargo", "fuzz", "run", target, corpus_file, "--features", "fuzz-coverage", "--", "-max_len=1200000"], env=env_with_wrapper, stdout=devnull, stderr=subprocess.STDOUT)

# Merge raw coverage files
print("Merging generated raw files into", profdata_file + "...")
subprocess.run(["cargo", "profdata", "--", "merge", raw_dir, "-o", profdata_file])

# Create coverage report
html_file_name = join(coverage_dir, target + "-coverage.html")
html_file = open(html_file_name, "w")
print("Writing HTML report to", html_file_name, "...")
subprocess.run(["cargo", "cov", "--", "show",
                normpath("target/x86_64-unknown-linux-gnu/release/" + target),
                "-show-expansions=true", # Expand inclusions, such as preprocessor macros or textual inclusions, inline in the display of the source file
                "-show-line-counts-or-regions=true",
                "-show-instantiations=false",
                "--format=html",
                "-Xdemangler=rustfilt",
                "-ignore-filename-regex=(\.cargo/registry)|(fuzz\.rs)|(ffi\.rs)",
                "-instr-profile=" + profdata_file], stdout=html_file)