## Unreleased changes

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
