# idiss-go - Concordium Identity Issuance library for Go

Here, a Go library `idiss` for identity issuance is provided. The library uses
three Go-specific C functions `validate_request_v1_go`,
`create_identity_object_v1_go`, and `validate_recovery_request_go` that are
exported by the Rust library `idiss` in `concordium-base`.

The Go package intentionally exposes only the
non-deprecated flows:

- `ValidateRequestV1`
- `CreateIdentityObjectV1`
- `ValidateRecoveryRequest`

Deprecated v0 issuance APIs are intentionally omitted.

To build make sure to have Go, Rust, Cargo, and a C toolchain for `cgo`
installed. The build process for this library does not build the Rust library
automatically.

## Api

- Go 1.21+
- Rust toolchain with Cargo
- A C toolchain for `cgo`

`idiss-go` does not invoke Cargo automatically. You must build the Rust shared
library explicitly before using the native Go bindings.

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

To build the Rust library, step inside the repository root and do

```sh
cargo build --manifest-path idiss/Cargo.toml --release --features go
```

This produces the native library in `idiss/target/release/`:

- macOS: `libidiss.dylib`
- Linux: `libidiss.so`
- Windows: `idiss.dll`

By default, `idiss-go` uses a stub native layer so the module compiles even if
the Rust library has not been built.

To enable the real native bindings, build or test with the `idissnative` tag:

```sh
go test -tags idissnative ./...
go run -tags idissnative ./examples/basic
```

The native Go binding code lives behind both `cgo` and `idissnative`.

## Runtime Library Loading

The Go native build links against `idiss/target/release`.

At runtime, the operating system loader must also be able to find the shared
library:

- macOS: `libidiss.dylib`
- Linux: `libidiss.so`
- Windows: `idiss.dll`

The current Go linker setup adds an `rpath` for macOS and Linux pointing at the
repository-local `idiss/target/release` directory. On Windows, the DLL still
needs to be discoverable via the normal DLL search path.

## Example

In `examples/basic`, there is an example that uses the fixture data from the
repository and exercises all three public functions.

To run the example, step inside the `idiss-go` directory and do

```sh
cargo build --manifest-path idiss/Cargo.toml --release --features go
go run -tags idissnative ./examples/basic
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

## Notes

- `cgo` and `unsafe` are intentionally isolated to `internal/native`.
- The Go package returns Go values and `error` values instead of exposing the
  Rust JSON ABI directly.
- The package layout is:
- `idiss/`: public typed API
- `internal/native/`: `cgo`, `unsafe`, and Rust buffer ownership handling
- `examples/basic/`: minimal runnable example using fixture data
