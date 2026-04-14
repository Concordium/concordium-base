# idiss-go - Concordium Identity Issuance library for Go

Here, a Go library `idiss` for identity issuance is provided. The library can
use either:

- native Go-specific exports from the Rust library `idiss`
- a Wasm module produced by the same Rust library

The Go package intentionally exposes only the
non-deprecated flows:

- `ValidateRequestV1`
- `CreateIdentityObjectV1`
- `ValidateRecoveryRequest`

Deprecated v0 issuance APIs are intentionally omitted.

To build make sure to have Go, Rust, and Cargo installed. If you want to use
the native backend you also need a C toolchain for `cgo`. The build process for
this library does not build the Rust artifacts automatically.

## Prerequisites

- Go 1.21+
- Rust toolchain with Cargo
- a C toolchain for `cgo` when using the native backend

`idiss-go` does not invoke Cargo automatically. You must build the Rust native
library or Wasm module explicitly before using the corresponding Go backend.

## API

The `idiss` package provides three wrappers around the imported C functions:

```go
func ValidateRequestV1(
    global Versioned[GlobalContext],
    ipInfo Versioned[IPInfo],
    arsInfos Versioned[map[string]ARInfo],
    request IDObjectRequestV1,
) error
```

Given a global context, identity provider info, anonymity revoker info, and a
v1 request, it either:

- returns `nil`, if the request is valid, or
- returns an error, if the request is invalid or the input is malformed.

```go
func CreateIdentityObjectV1(
    ipInfo Versioned[IPInfo],
    attributes AttributeList,
    request IDObjectRequestV1,
    ipPrivateKey string,
) (IdentityCreationV1, error)
```

that given identity provider info, an attribute list, a v1 request, and the
private key of the identity provider either:

- returns an `IdentityCreationV1` object containing the identity object that is returned to the user and the anonymity revocation record
- returns an error, if the input is malformed or identity creation fails.

```go
func ValidateRecoveryRequest(
    global Versioned[GlobalContext],
    ipInfo Versioned[IPInfo],
    request IDRecoveryWrapper,
    now time.Time,
) error
```

that given a global context, identity provider info, a recovery request, and the
current time of the identity provider either:

- returns `nil`, if the request is valid, or
- returns an error, if the request is invalid or the input is malformed.

Before calling into Rust, `ValidateRecoveryRequest` also applies the a local
timestamp-window check. If the request timestamp is outside
the accepted window, the function returns `ErrInvalidRecoveryTimestamp`.

## Types

The public Go API is typed rather than JSON-in/JSON-out. The package includes
typed representations of the JSON schema used by the Rust and C#
implementations, including:

- `Versioned[T]`
- `GlobalContext`
- `IPInfo`
- `ARInfo`
- `IDObjectRequestV1`
- `AttributeList`
- `IdentityCreationV1`
- `IDRecoveryWrapper`

Some values are represented as strings because that matches the existing schema
used by the Rust library:

- `YearMonth`
- `AccountAddress`
- hex-encoded cryptographic values and signatures

## Building

To build the native Rust library for the `idissnative` backend, step inside the
repository root and do

```sh
cargo build --manifest-path idiss/Cargo.toml --release --features go
```

This produces the native library in `idiss/target/release/`:

- macOS: `libidiss.dylib`
- Linux: `libidiss.so`
- Windows: `idiss.dll`

To build the Wasm module for the `idisswasm` backend, step inside the
repository root and do

```sh
cargo build --manifest-path idiss/Cargo.toml --target wasm32-wasip1 --release --features wasm
```

This produces `idiss/target/wasm32-wasip1/release/idiss.wasm`.

By default, `idiss-go` uses a stub backend so the module compiles even if no
Rust artifact has been built.

To enable the native backend, build or test with the `idissnative` tag:

```sh
go test -tags idissnative ./...
go run -tags idissnative ./examples/basic
```

To enable the Wasm backend, build or test with the `idisswasm` tag:

```sh
go test -tags idisswasm ./...
go run -tags idisswasm ./examples/basic
```

The native Go binding code lives behind both `cgo` and `idissnative`.

## Runtime Artifact Loading

The Go native build links against `idiss/target/release`.

At runtime, the operating system loader must also be able to find the shared
library:

- macOS: `libidiss.dylib`
- Linux: `libidiss.so`
- Windows: `idiss.dll`

The current Go linker setup adds an `rpath` for macOS and Linux pointing at the
repository-local `idiss/target/release` directory. On Windows, the DLL still
needs to be discoverable via the normal DLL search path.

The native backend currently uses that repository-local shared library path at
link time. Unlike the Wasm backend, it does not currently support overriding the
native library path with an environment variable.

The Go Wasm backend loads the repository-local Wasm artifact from
`idiss/target/wasm32-wasip1/release/idiss.wasm` by default. This path can be
overridden with the `IDISS_WASM_PATH` environment variable.

For example:

```sh
IDISS_WASM_PATH=/path/to/idiss.wasm go test -tags idisswasm ./...
IDISS_WASM_PATH=/path/to/idiss.wasm go run -tags idisswasm ./examples/basic
```

## Example

In `examples/basic`, there is an example that uses the fixture data from the
repository and exercises all three public functions.

To run the example, step inside the `idiss-go` directory and do

```sh
cargo build --manifest-path idiss/Cargo.toml --release --features go
go run -tags idissnative ./examples/basic
```

To run the same example through the Wasm backend, do instead

```sh
cargo build --manifest-path idiss/Cargo.toml --target wasm32-wasip1 --release --features wasm
go run -tags idisswasm ./examples/basic
```

If the example is successful, it prints a few values derived from the validated
request and the created identity object.

## Testing

In `idiss/integration_test.go`, there are tests for the functions
`ValidateRequestV1`, `CreateIdentityObjectV1`, and `ValidateRecoveryRequest`,
including failure cases.

To run the default Go build without the native library, step inside the
`idiss-go` directory and do

```sh
go test ./...
```

To run the native integration tests, step inside the `idiss-go` directory and
do

```sh
cargo build --manifest-path idiss/Cargo.toml --release --features go
go test -tags idissnative ./...
```

To run the Wasm integration tests, step inside the `idiss-go` directory and do

```sh
cargo build --manifest-path idiss/Cargo.toml --target wasm32-wasip1 --release --features wasm
go test -tags idisswasm ./...
```

## Notes

- `cgo` and `unsafe` are intentionally isolated to `internal/native`.
- Wasm runtime integration is intentionally isolated to `internal/wasm`.
- The Go package returns Go values and `error` values instead of exposing the
  Rust JSON ABI directly.
- The package layout is:
- `idiss/`: public typed API
- `internal/backend/`: build-tag based backend selection
- `internal/native/`: `cgo`, `unsafe`, and Rust buffer ownership handling
- `internal/wasm/`: Wasm module loading and memory handling via `wazero`
- `examples/basic/`: minimal runnable example using fixture data
