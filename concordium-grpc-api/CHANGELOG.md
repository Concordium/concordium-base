# Changelog

## Unreleased changes

- Extend `ProtocolVersion` enum with a protocol version 9 variant `PROTOCOL_VERSION_9`.

## Node 8.0 API

- Extend `ProtocolVersion` enum with a protocol version 8 variant `PROTOCOL_VERSION_8`.
- Support for changes related to validator suspension in protocol version 8:
  - Added `BakerSuspended`, `BakerResumed` message types and corresponding
    events to `BakerEvent`.
  - Added `validator_suspended` and `validator_primed_for_suspension` cases
    for `BlockSpecialEvent`.
  - Extended `PoolCurrentPaydayInfo` and `PoolInfoResponse`.
- Add `GetConsensusDetailedStatus` endpoint for querying detailed consensus
  status information.
- Add `GetScheduledReleaseAccounts` endpoint for querying the list of accounts that
  have scheduled releases.
- Add `GetCooldownAccounts`, `GetPreCooldownAccounts` and `GetPrePreCooldownAccounts`
  endpoints for querying the lists of accounts that have pending cooldowns in protocol
  version 7 onwards.
- Add `parameter` field to `ContractInitializedEvent` containing the parameter passed
  to the contract initializer.
- Add chain parameters v3 with the new `ValidatorScoreParameters` parameters.
- Add `validator_score_parameters` to `NextUpdateSequenceNumbers`.

## Node 7.0 API

- Extend `ProtocolVersion` enum with a protocol version 7 variant `PROTOCOL_VERSION_7`.
- Support for changes to cooldown behavior in protocol version 7:
  - `AccountInfo` has a new repeated `cooldowns` field. Each `Cooldown` records
    the amount, (expected) release time and whether it's a regular cooldown,
    pre-cooldown or pre-pre-cooldown.
  - `AccountInfo` now includes `available_balance`. This is included since the
    method for calculating it has changed (it now must account for the
    cooldowns), so this is provided as a convenience.
  - `PoolInfoResponse` is revised to make the fields `equity_capital`,
    `delegated_capital`, `delegated_capital_cap` and `pool_info` optional. This
    is since in protocol 7 a validator can be unregistered, but still part of the
    current epoch validators.
  - `BakerEvent` now has an additional case `delegation_removed`, as configuring a baker can
    result in a delegator being removed (from protocol 7).
  - `DelegationEvent` now has an additional case `baker_removed`, as configuring a delegator
    can result in a baker being removed (from protocol 7).


## Node 6.2 API

- Add a new health service that conforms to the API expected
  by Google https://github.com/grpc/grpc-proto/blob/master/grpc/health/v1/health.proto
- Add `DryRun` endpoint.
- Remove `UpdateInstructionSignature`. It was not used in any endpoints.
- Remove V1 API.

## Node 6.1 API

- Add `GetBakersRewardPeriod` endpoint.
- Add `GetBlockCertificates` endpoint.
- Add `GetBakerEarliestWinTime` endpoint.
- Add `GetWinningBakersEpoch` endpoint.
- Add `GetFirstBlockEpoch` endpoint.
- Add a `CommissionRates` field for `PoolCurrentPaydayInfo`.

## Node 6.0 API

- Expand `BlockHashInput` to support querying by block height.
- Add `protocol_version` to the return of BlockInfo.
- Make `slot_duration` optional in `ConsensusInfo`.
- Add optional fields `current_timeout_duration`, `current_round`, `current_epoch`,
  and `trigger_block_time` to `ConsensusInfo`.
- Make `slot_number` optional in `BlockInfo`.
- Add optional fields `round` and `epoch` to `BlockInfo`.
- Make `election_difficulty` optional in `ElectionInfo`.
