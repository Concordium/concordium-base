# Changelog

## Unreleased changes
- Add support for V1 contract builds, testing, and execution.
- The output of `cargo concordium build` is now versioned.
- Support contracts written with Rust edition 2021.

## 1.1.1
- Clarify that energy units used by `cargo-concordium` are "interpreter energy"
  and not the same as NRG.
- Allow the user to only specify the necessary fields in the JSON context files
  - Also allow the `--context` parameter to be omitted, for when no context is needed
- Correct and improve error message for incorrect array length during contract
  simulation:
  show expected and actual length rather than mislabelled actual length.
