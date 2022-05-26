{-# LANGUAGE GADTs #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Concordium.Types.Migration where

import Concordium.Genesis.Data
import qualified Concordium.Genesis.Data.P4 as P4
import Concordium.Types
import Concordium.Types.Accounts
import Concordium.Types.Parameters
import Concordium.Types.Updates

-- |Apply a state migration to an 'Authorizations' structure.
--
-- [P3 to P4]: access structures for cooldown and time parameters are added.
migrateAuthorizations ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    Authorizations (ChainParametersVersionFor oldpv) ->
    Authorizations (ChainParametersVersionFor pv)
migrateAuthorizations StateMigrationParametersTrivial auths = auths
migrateAuthorizations (StateMigrationParametersP3ToP4 migration) Authorizations{..} =
    Authorizations
        { asCooldownParameters = JustForCPV1 updateCooldownParametersAccessStructure,
          asTimeParameters = JustForCPV1 updateTimeParametersAccessStructure,
          ..
        }
  where
    P4.ProtocolUpdateData{..} = P4.migrationProtocolUpdateData migration
migrateAuthorizations (StateMigrationParametersP3ToP5 migration) Authorizations{..} =
    Authorizations
        { asCooldownParameters = JustForCPV1 updateCooldownParametersAccessStructure,
          asTimeParameters = JustForCPV1 updateTimeParametersAccessStructure,
          ..
        }
  where
    P4.ProtocolUpdateData{..} = P4.migrationProtocolUpdateData migration

-- |Apply a state migration to an 'UpdateKeysCollection' structure.
--
-- [P3 to P4]: access structures for cooldown and time parameters are added.
migrateUpdateKeysCollection ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    UpdateKeysCollection (ChainParametersVersionFor oldpv) ->
    UpdateKeysCollection (ChainParametersVersionFor pv)
migrateUpdateKeysCollection migration UpdateKeysCollection{..} =
    UpdateKeysCollection{level2Keys = migrateAuthorizations migration level2Keys, ..}

-- |Apply a state migration to a 'MintDistribution' structure.
--
-- [P3 to P4]: the mint-per-slot rate is removed.
-- [P3 to P5]: the mint-per-slot rate is removed.
migrateMintDistribution ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    MintDistribution (ChainParametersVersionFor oldpv) ->
    MintDistribution (ChainParametersVersionFor pv)
migrateMintDistribution StateMigrationParametersTrivial mint = mint
migrateMintDistribution StateMigrationParametersP3ToP4{} mint =
    migrateMintDistributionV0V1 mint
migrateMintDistribution StateMigrationParametersP3ToP5{} mint =
    migrateMintDistributionV0V1 mint

migrateMintDistributionV0V1 ::
    MintDistribution 'ChainParametersV0 ->
    MintDistribution 'ChainParametersV1
migrateMintDistributionV0V1 MintDistribution{..} =
    MintDistribution{_mdMintPerSlot = MintPerSlotForCPV0None, ..}

-- |Apply a state migration to a 'PoolParameters' structure.
--
-- [P3 to P4]: the new pool parameters are defined by the migration parameters.
-- [P3 to P5]: the new pool parameters are defined by the migration parameters.
migratePoolParameters ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    PoolParameters (ChainParametersVersionFor oldpv) ->
    PoolParameters (ChainParametersVersionFor pv)
migratePoolParameters StateMigrationParametersTrivial poolParams = poolParams
migratePoolParameters (StateMigrationParametersP3ToP4 migration) _ =
    migratePoolParametersV0V1 migration
migratePoolParameters (StateMigrationParametersP3ToP5 migration) _ =
    migratePoolParametersV0V1 migration

migratePoolParametersV0V1 ::
    P4.StateMigrationData ->
    PoolParameters 'ChainParametersV1
migratePoolParametersV0V1 migration =
    P4.updatePoolParameters (P4.migrationProtocolUpdateData migration)

-- |Apply a state migration to a 'ChainParameters' structure.
--
-- [P3 to P4]: the new cooldown, time and pool parameters are given by the migration parameters;
--   the mint-per-slot rate is removed from the reward parameters.
-- [P3 to P5]: the new cooldown, time and pool parameters are given by the migration parameters;
--   the mint-per-slot rate is removed from the reward parameters.
migrateChainParameters ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    ChainParameters oldpv ->
    ChainParameters pv
migrateChainParameters StateMigrationParametersTrivial cps = cps
migrateChainParameters (StateMigrationParametersP3ToP4 migration) cps =
    migrateChainParametersV0V1 migration cps
migrateChainParameters (StateMigrationParametersP3ToP5 migration) cps =
    migrateChainParametersV0V1 migration cps

migrateChainParametersV0V1 ::
    P4.StateMigrationData ->
    ChainParameters' 'ChainParametersV0 ->
    ChainParameters' 'ChainParametersV1
migrateChainParametersV0V1 migration ChainParameters{..} =
    ChainParameters
        { _cpCooldownParameters = updateCooldownParameters,
          _cpTimeParameters = updateTimeParameters,
          _cpRewardParameters =
            RewardParameters
                { _rpMintDistribution = migrateMintDistributionV0V1 _rpMintDistribution,
                  ..
                },
          _cpPoolParameters = migratePoolParametersV0V1 migration,
          ..
        }
  where
    RewardParameters{..} = _cpRewardParameters
    P4.ProtocolUpdateData{..} = P4.migrationProtocolUpdateData migration


-- |Apply a state migration to an 'AccountStake' structure.
--
-- [P3 to P4]: bakers have the default baker pool information applied to them, where the pool status
--   and commission rates are given by the migration parameters; pending changes are converted from
--   epoch times to absolute times.
-- [P3 to P5]: bakers have the default baker pool information applied to them, where the pool status
--   and commission rates are given by the migration parameters; pending changes are converted from
--   epoch times to absolute times.
migrateAccountStake ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    AccountStake (AccountVersionFor oldpv) ->
    AccountStake (AccountVersionFor pv)
migrateAccountStake StateMigrationParametersTrivial = id
migrateAccountStake (StateMigrationParametersP3ToP4 migration) =
    migrateAccountStakeV0V1 migration
migrateAccountStake (StateMigrationParametersP3ToP5 migration) =
    migrateAccountStakeV0V1 migration

-- |A helper function to migrate accounts from V0 to V1
migrateAccountStakeV0V1 ::
    P4.StateMigrationData
    -> AccountStake 'AccountV0
    -> AccountStake 'AccountV1
migrateAccountStakeV0V1 migration@P4.StateMigrationData{..} =
    \case
        AccountStakeNone -> AccountStakeNone
        AccountStakeBaker AccountBaker{_accountBakerInfo = BakerInfoExV0 bi, ..} ->
            AccountStakeBaker
                AccountBaker
                    { _accountBakerInfo = BakerInfoExV1 bi (P4.defaultBakerPoolInfo migration),
                      _bakerPendingChange = migratePCE <$> _bakerPendingChange,
                      ..
                    }
  where
    migratePCE (PendingChangeEffectiveV0 eff) =
        PendingChangeEffectiveV1 $
            addDuration
                migrationPreviousGenesisTime
                (migrationPreviousEpochDuration * fromIntegral eff)
