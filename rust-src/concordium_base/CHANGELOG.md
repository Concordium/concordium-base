## Unreleased changes

- Implement Serial for `num::rational::Ratio<u64>` and `Duration`.
- Introduce types for protocol version 6: `ChainParameterVersion2`, `GASRewardsV1`, `TimeoutParameters` and `FinalizationCommitteeParameters`.

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
