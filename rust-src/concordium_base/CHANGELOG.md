## Unreleased changes

- Publish `get_canonical_address` on `AccountAddress` 

## 7.0.0 (2025-02-03)

- Add getter function `reward_period_epochs` to access the field in the struct `RewardPeriodLength`.
- Add constructor `TokenAddress::new` for CIS2 type `TokenAddress`.
- Introduce new chain parameters `ValidatorScoreParameters` that contain the
  threshold of maximal missed rounds before a validator gets suspended.
- Add `Default` instance for `UpdateSequenceNumber`.
- Add `FinalizationCommitteeHash` type.

## 6.0.0 (2024-08-26)

- Extend `id::types::ATTRIBUTE_NAMES` with new company attribute tags: "legalName", "legalCountry", "businessNumber" and "registationAuth".
- Add a new module `cis3_types` that defines the interface types for CIS3
  compatible contracts.
- Fix discrepancy in (de)serializing `Web3IdAttribute::Timestamp`s due to an unexpected breaking change introduced in version 0.4.32 of `chrono`.
- `concordium_base::ed25519` now also exports `SigningKey` to enable constructing `KeyPair` structs.
- Deprecated various functions related to encrypted transfers, as encrypted transfers are no longer supported in protocol version 7.

## 5.0.0 (2024-03-25)

- Set minimum supported Rust version to 1.73.
- Make fields of CIS4 events public.
- Remove the `From<SlotDuration>` and `From<DurationSeconds>` implementations
  for `chrono::Duration` and replace them with fallible `TryFrom`
  implementations that fail when durations overflow.
- `ContractAddress::new`
- `ContractName`, `ReceiveName`, `EntrypointName`, and `Parameter`
  `new_unchecked` constructors are made `const` so they can be used when
  defining constants. Similarly `Parameter::empty` is `const` now.

## 4.0.0 (2024-01-22)

- Add `MultiExp` trait that allows to have different `multiexp` algorithm implementations for different curves.
- Improve performance of the generic `multiexp` algorithm.
- Add an instance of `MultiExp` that is specific to `curve25519`.
- Add traits `Field` and `PrimeField` with implementations for the underlying field of the `BLS12-381` curve.
- Add integration with the `arkworks` library interfaces for fields and elliptic curves (wrapper types and blanket trait implementations).
- Add the `BLS12-381`implementation from the `arkworks` ecosystem.
- The public types `id::constants::ArCurve`, `id::constants::IpPairing` are defined in terms of the `arkworks` BLS12-381 implementation.
- Add a type alias `id::constants::BlsG2` for the `G2` group of `arkworks` BLS12-381.
- Upgrade `ed25519-dalek` to `v2.0`.
- Bump the `rand` version to `v0.8`
- Add implementations of `Field`, `PrimeField` and `Curve` for the Ristretto representation of `curve25519`.
- Remove `Curve::bytes_to_curve_unchecked()`.
- Rename `Cipher::from_bytes_unchecked()` to `Cipher::from_bytes()`; the method uses `deserial()` instead of `Curve::bytes_to_curve_unchecked()`.
- Support `P7` protocol version.
- The `Debug` implementation for `ContractEvent` displays the value in `hex`.
  The alternate formatter (using `#`) displays it as a list of bytes.
- Add `FromStr` and `Display` instances to `dodis_yampolskiy_prf::SecretKey`.
- Change `Debug` instance of `dodis_yampolskiy_prf::SecretKey` to hide the value.
- Remove `Timestamp` to instead reexport the similar type from `concordium_contracts_common`.
  This adds several new methods, but results in a breaking change in the `serde::Serialize` implementation, which is now using string containing RFC3393 representation instead the underlying milliseconds.
- Remove `smart_contracts::WasmVersion` to instead reexport a similar type from `concordium_contracts_common`.
  This adds a `FromStr` implementation and changes the associated type `TryFrom<u8>::Error` from `anyhow::Error` to `concordium_contracts_common::U8WasmVersionConvertError`.

## 3.2.0 (2023-11-22)

- Add `From` trait to convert `AccountKeys` into `AccountPublicKeys`.
- Add `singleton` and `new` function to `AccountAccessStructure`.
- Export `PublicKey`, `SecretKey`, and `Signature` type from `ed25519_dalek` crate.
- Add `sign_message` function to sign a message with all `AccountKeys`. The return type is `AccountSignatures`.
- Support using `validatorId` instead of `bakerId` when parsing
  `BakerCredentials` from JSON.

## 3.1.1 (2023-10-27)

- Add helpers `from_file` and `from_slice` to construct a `WasmModule`.

## 3.1.0 (2023-10-18)

- Fix `Display` implementation of `Web3IdAttribute::Timestamp` attribute.
- Add helper method `parse` to `ContractEvent` for deserializing into types that implement `concordium_contracts_common::Deserial`.

## 3.0.1 (2023-08-28)

- Add `Serialize` and `Deserialize` instances to `CredentialStatus` type.
- Fix the epoch when converting Web3ID attributes from Unix epoch to `-262144-01-01T00:00:00Z`.
  The representable timestamps are between `-262144-01-01T00:00:00Z` and
  `+262143-12-31T23:59:59.999Z`


## 3.0.0 (2023-08-21)

- Remove the constant `MAX_ALLOWED_INVOKE_ENERGY` since it was no longer
  relevant with the way the node currently handles the invoke API.
- Add `ED25519_SIGNATURE_LENGTH` constant for the size of an ed25519 signature.
- Add `concordium_contracts_common::{Serial,Deserial}` implementations to
  `CredentialPublicKeys` and `AccountAccessStructure`.
- Add `sign_data` and `generate` methods to `AccountKeys` to sign arbitrary
  data, and to generate a fresh set of keys.
- Add `From<&AccountKeys>` instance for AccountAccessStructure.
- Add `verify_data_signature` function to verify a signature with account keys
  on arbitrary data.
- Update notation of sigma protocols to better match the literature and the bluepaper.
- Move all sigma protocols to a common sigma-protocol crate.
- Move all range proof helper functions to `range_proofs`.
- Add a new module `web3id` that defines types related to Web3ID and implements
  proving and verification functions.
- Add a new module `cis4_types` that defines the interface types for CIS4
  compatible contracts.

## 2.0.0 (2023-06-16)

- Extend types `UpdatePayload` and `UpdateType` with variants introduced in protocol version 6.
- Implement `Serial` and `Deserial` for `num::rational::Ratio<u64>` and `Duration`.
- Introduce types for protocol version 6: `Ratio`, `ChainParameterVersion2`, `GASRewardsCPV1`, `TimeoutParameters` and `FinalizationCommitteeParameters`.

## 1.2.0 (2023-05-08)

- Add helpers to extract policy from credentials.
- Add helpers to `TransactionTime` to construct future timestamps relative to
  current time, and from a unix timestamp.
- Add `new_` helpers to `cis2::TokenId` to simplify the common case of token id
  construction from integral types.
- Add new sigma protocol `VecComEq` for linking a vector commitment with individual commitments.
- Add `VecCommitmentKey` for generating vector commitments.
- Fix a serialization bug for UpdatePayload. The serialization did not match
  that of the node for AddIdentityProvider and AddAnonymityRevoker payloads.

## 1.1.1 (2023-04-13)

- Add Serialize instances to `Proof` and `Statement` types, and its constituent
  parts (`AtomicProof` and `AtomicStatement`).
- `Deserial` for `BTreeMap` and `BTreeSet` no longer requires `Copy`.

## 1.1.0 (2023-04-12)

- Additions to `Energy` type:
  - Add helper methods to `Energy`: `checked_sub` and `tick_energy`.
  - Derive `Sub`.
- Add `InsufficientEnergy` type.
- Derive `PartialEq`/`Eq` to `ContractTraceElement`, `InstanceUpdatedEvent`, and `ContractEvent`.
- Add `size` (in bytes) methods to `InitContractPayload` and `UpdateContractPayload` types.

## 1.0.0

- Initial public release.
