# Changelog

## Unreleased changes

- `validate_module` is now parameterized by `ValidationConfig` which determines
  which Wasm features should be allowed. The currently supported configurable features are
  - allow access to globals (defined in the current module) in data and element
    initialization sections.
  - allow instructions defined in the [sign extension operators](https://github.com/WebAssembly/sign-extension-ops/blob/master/proposals/sign-extension-ops/Overview.md)
    Wasm proposal.
- `instantiate` and `instantiate_with_metering`'s return type is changed from
  `Artifact` to `InstantiatedModule` which adds metadata on top of the artifact.

## concordium-wasm 2.0.0 (2023-06-16)

- Bump concordium-contracts-common to version 7.

## concordium-wasm 1.1.0 (2023-05-08)

- Bump concordium-contracts-common to version 6.

## concordium-wasm 1.0.0 (2023-02-03)

- Initial release.
