## Unreleased

- Support decoding unsigned and negative CBOR bignums to fixed-size machine integers (`i8`, ..., `i64`, `u8`, ..., `u64`)

## 8.0.0 (2025-08-18)

Adds support for integrating with Concordium nodes running protocol version 9.

- Introduce protocol version 9 variant `ProtocolVersion::P9`.
- Introduce basic types related to protocol level tokens (PLT)
  - `RawCbor`: Represents CBOR encoded details for PLT module state, events, and operations
  - `CborMemo`: Represents CBOR encoded memos for PLT transactions
  - `TokenId`: A unique text identifier of a PLT
  - `TokenAmount`: A representation of a PLT amount
  - `TokenModuleRef`: The module reference of a PLT instance
  - `MetadataUrl`: An object containing the url for token metadata
  - `TokenModuleAccountState`: The state of an account with respect to a PLT token (e.g. balances or if account is on the allow/deny list)
  - `TokenModuleInitializationParameters`: The parameters that are parsed to the token module when creating a PLT token.
  - `TokenModuleState`: The state stored by the token module.
  - `TokenHolder`: A representation of the different token holder entities. Currently, only accounts are supported.
- Added new struct `CreatePlt` and corresponding `UpdatePayload` type representing the payload of a create PLT chain-update transaction creating a new token.
- Added new variant `TokenUpdate` to the `Payload` enum and corresponding `TransactionType` representing the payload of an account transaction updating a token.
- Added `TokenOperations` type to represent the different actions when updating a token (e.g. `mint/burn/transfer/pause/unpause/addAndRemoveFromToAllowDenyLists`). Operations can be created using functions in `concordium_base::protocol_level_tokens::operations`.
- Added `TokenEvent` type.
- Added `TokenEventDetails` enum with variants `Module(TokenModuleEvent)`, `Transfer(TokenTransferEvent)`, `Mint(TokenSupplyUpdateEvent)`, and `Burn(TokenSupplyUpdateEvent)`.
- Added `TokenModuleRejectReason` struct representing PLT transaction rejections.
- Added generic support for `cbor` encoding/decoding in the `cbor` module. The `cbor::cbor_decode/encode` function can encode/decode PLT types that are represented as `cbor`.
- Added `Level2KeysUpdateV2(AuthorizationsV1)` variant to the `RootUpdate` enum which must have a field `Some(create_plt)` for exposing and updating the access structure for PLT creation.
- Added new method `get_canonical_address` on the `AccountAddress` type.
- Added Clone derive for `AccountCredentialWithoutProofs`.
- Additional changes with respect to the last `alpha` release: 
  - Added PLT `TokenModuleInitializationParameters` CBOR type.
  - Support empty structs with `CborSerialize` derive macro.
  - Support CBOR decoding maps and arrays of indefinite length.
  - Fix bug where CBOR decoding would fail on empty text strings.

## 8.0.0-alpha.2 (2025-07-14)

- Adjusted cost of PLT mint/burn from 100 to 50
- Adds `pause` function to `concordium_base::protocol_level_tokens::operations`, to support pausing/unpausing
  execution of token operations.
- Adds support for decoding `paused` state as part of the state of a token module instance.
- Adds support for decoding token modules events related to pausing/unpausing tokens.

## 8.0.0-alpha.1 (2025-06-30)

- `TokenAmount` changed to require explicit number of decimals equal to the token when creating a value
- `MetadataUrl` and `TokenModuleState` now supports decoding "additional" data matching the CDDL rule `* text => any`.
- CBOR map encoding is now deterministic and follows the order described at <https://www.rfc-editor.org/rfc/rfc8949.html#name-core-deterministic-encoding>
- `TokenAmount` CBOR encoding now supports `value` in full `u64` range and not just overlap between `u64` and `i64`
- Added `TokenModuleAccountState` type.
- Removed `try_from_cbor` and `to_cbor` from a number of types implementing CBOR serialization in favour of just
  using `cbor::cbor_encode/decode`.
- The serialization of `AuthorizationsV1` is fixed to be compatible with the Haskell implementation.
- Replace concepts `TokenHolder` and `TokenGovernance` by `TokenUpdate`.
- Add `governance_account` to `TokenModuleState`.

## 8.0.0-alpha (2025-06-06)

- Protocol level token events and reject reasons are now defined in `concordium_base::protocol_level_tokens`.
  Event and reject reasons CBOR can be decoded with `TokenModuleEvent::decode_token_module_event_type` or
  `TokenModuleRejectReason::decode_reject_reason_type`.
- Transaction `Payload` now supports `TokenGovernance` payloads.
  Operations can be created using functions in `concordium_base::protocol_level_tokens::operations`
  and composed to transactions with `send::token_governance_operations` and `construct::token_governance_operations`.
- Transaction `Payload` now supports `TokenHolder` payloads.
  Operations can be created using functions in `concordium_base::protocol_level_tokens::operations`
  and composed to transactions with `send::token_holder_operations` and `construct::token_holder_operations`.
  The underlying model for protocol level tokens is defined in `concordium_base::protocol_level_tokens`.
- Publish `get_canonical_address` on `AccountAddress`
- Introduce protocol version 9 `ProtocolVersion::P9`
- Introduce basic types related to protocol level tokens (PLT)
  - `RawCbor`, `TokenId`, `TokenAmount`, `TokenModuleRef`.
  - Extend `UpdatePayload` with `CreatePlt` variant.

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
