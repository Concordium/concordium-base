## Unreleased changes

- Additions to `Energy` type:
  - Add helper methods to `Energy`: `checked_sub` and `tick_energy`.
  - Derive `Sub`.
- Add `InsufficientEnergy` type.
- Derive `PartialEq`/`Eq` to `ContractTraceElement`, `InstanceUpdatedEvent`, and `ContractEvent`.
- Add `size` (in bytes) methods to `InitContractPayload` and `UpdateContractPayload` types.

## 1.0.0

- Initial public release.
