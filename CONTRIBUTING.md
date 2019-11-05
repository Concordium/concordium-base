# Languages and tools

This repository contains Haskell and Rust libraries, split into haskell-src and
rust-src.

Typically Haskell sources only contain foreign imports of functionality
implemented in rust libraries, and available to the rest of the project (e.g.,
consensus, globalstate).

## Haskell workflow

We typically use [stack](https://docs.haskellstack.org/en/stable/README/) to
build, run, and test the code. In order to build the haskell libraries the rust
dependencies must be pre-build, which is done automatically by the cabal setup
script. There might be issues with finding the libraries that were build, in
which case setting LD_LIBRARY_PATH might help (this is dependant on the
platform).

We do not use any code formatting or linting tool on the CI. Running hlint might
uncover common issues, and with regards to formatting, the general rule is that
lines should not be too long, and follow the naming scheme and code style that
already exists.

## Rust workflow

We use **stable version** of rustc to compile the code. This should be used
indirectly via the [cargo](https://github.com/rust-lang/cargo) tool that
resolves dependencies, and provides additional options.

The easies way to install is via [rustup](https://rustup.rs/).

The CI is configured to check two things
- the [clippy](https://github.com/rust-lang/rust-clippy) tool is run to check
  for common mistakes and issues. We try to have no clippy warnings. Sometimes
  what clippy things is reasonable is not, in which case you should explicitly
  disable the warning on that site (a funciton or module), such as
  `#[allow(clippy::too_many_arguments)]`, but that is a method of last resort.
  Try to resolve the issue in a different way first.

- the [rust fmt](https://github.com/rust-lang/rustfmt) tool is run to check the
  formatting. Unfortunately the stable version of the tool is quite outdated, so
  we use a nightly version, which is updated a few times a year. Thus in order
  for the CI to pass you will need to install the relevant nightly version (for
  which see the [.gitlab-ci.yml](.gitlab-ci.yml) file, the `"lint:fmt"`
  section).
  
# Workflow

The typical workflow should be the following.
- make changes, commit and push on a separate branch
- make a merge request to merge your branch into master. Assign somebody else
  with knowledge of the code to review the changes before they are merged.
  
The tasks related to this repository are managed mostly on the
[crypto-id](https://trello.com/b/6IbgiO8T/crypto-id) Trello board.
