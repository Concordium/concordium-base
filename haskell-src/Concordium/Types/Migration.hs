{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
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
migrateAuthorizations StateMigrationParametersP1P2 auths = auths
migrateAuthorizations StateMigrationParametersP2P3 auths = auths
migrateAuthorizations (StateMigrationParametersP3ToP4 migration) Authorizations{..} =
    Authorizations
        { asCooldownParameters = JustForCPV1 updateCooldownParametersAccessStructure,
          asTimeParameters = JustForCPV1 updateTimeParametersAccessStructure,
          ..
        }
  where
    P4.ProtocolUpdateData{..} = P4.migrationProtocolUpdateData migration
migrateAuthorizations StateMigrationParametersP4ToP5 auths = auths

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
migrateMintDistribution ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    MintDistribution (ChainParametersVersionFor oldpv) ->
    MintDistribution (ChainParametersVersionFor pv)
migrateMintDistribution StateMigrationParametersTrivial mint = mint
migrateMintDistribution StateMigrationParametersP1P2 mint = mint
migrateMintDistribution StateMigrationParametersP2P3 mint = mint
migrateMintDistribution StateMigrationParametersP3ToP4{} MintDistribution{..} =
    MintDistribution{_mdMintPerSlot = MintPerSlotForCPV0None, ..}
migrateMintDistribution StateMigrationParametersP4ToP5 mint = mint

-- |Apply a state migration to a 'PoolParameters' structure.
--
-- [P3 to P4]: the new pool parameters are defined by the migration parameters.
migratePoolParameters ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    PoolParameters (ChainParametersVersionFor oldpv) ->
    PoolParameters (ChainParametersVersionFor pv)
migratePoolParameters StateMigrationParametersTrivial poolParams = poolParams
migratePoolParameters StateMigrationParametersP1P2 poolParams = poolParams
migratePoolParameters StateMigrationParametersP2P3 poolParams = poolParams
migratePoolParameters (StateMigrationParametersP3ToP4 migration) _ =
    P4.updatePoolParameters (P4.migrationProtocolUpdateData migration)
migratePoolParameters StateMigrationParametersP4ToP5 poolParams = poolParams

-- |Apply a state migration to a 'ChainParameters' structure.
--
-- [P3 to P4]: the new cooldown, time and pool parameters are given by the migration parameters;
--   the mint-per-slot rate is removed from the reward parameters.
migrateChainParameters ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    ChainParameters oldpv ->
    ChainParameters pv
migrateChainParameters StateMigrationParametersTrivial cps = cps
migrateChainParameters StateMigrationParametersP1P2 cps = cps
migrateChainParameters StateMigrationParametersP2P3 cps = cps
migrateChainParameters m@(StateMigrationParametersP3ToP4 migration) ChainParameters{..} =
    ChainParameters
        { _cpCooldownParameters = updateCooldownParameters,
          _cpTimeParameters = updateTimeParameters,
          _cpRewardParameters =
            RewardParameters
                { _rpMintDistribution = migrateMintDistribution m _rpMintDistribution,
                  ..
                },
          _cpPoolParameters = migratePoolParameters m _cpPoolParameters,
          ..
        }
  where
    RewardParameters{..} = _cpRewardParameters
    P4.ProtocolUpdateData{..} = P4.migrationProtocolUpdateData migration
migrateChainParameters StateMigrationParametersP4ToP5 cps = cps

-- |Apply a state migration to an 'AccountStake' structure.
--
-- [P3 to P4]: bakers have the default baker pool information applied to them, where the pool status
--   and commission rates are given by the migration parameters; pending changes are converted from
--   epoch times to absolute times.
migrateAccountStake ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    AccountStake (AccountVersionFor oldpv) ->
    AccountStake (AccountVersionFor pv)
migrateAccountStake StateMigrationParametersTrivial = id
migrateAccountStake StateMigrationParametersP1P2 = id
migrateAccountStake StateMigrationParametersP2P3 = id
migrateAccountStake (StateMigrationParametersP3ToP4 migration) =
    \case
        AccountStakeNone -> AccountStakeNone
        AccountStakeBaker AccountBaker{_accountBakerInfo = BakerInfoExV0 bi, ..} ->
            AccountStakeBaker
                AccountBaker
                    { _accountBakerInfo = BakerInfoExV1 bi (P4.defaultBakerPoolInfo migration),
                      _bakerPendingChange = migratePendingChangeEffective migration <$> _bakerPendingChange,
                      ..
                    }
migrateAccountStake StateMigrationParametersP4ToP5 =
    \case
        AccountStakeNone -> AccountStakeNone
        AccountStakeBaker AccountBaker{_accountBakerInfo = BakerInfoExV1{..}, ..} ->
            AccountStakeBaker
                AccountBaker
                    { _accountBakerInfo = BakerInfoExV1{..},
                      _bakerPendingChange = coercePendingChangeEffectiveV1 <$> _bakerPendingChange,
                      ..
                    }
        AccountStakeDelegate AccountDelegationV1{..} ->
            AccountStakeDelegate
                AccountDelegationV1
                    { _delegationPendingChange = coercePendingChangeEffectiveV1 <$> _delegationPendingChange,
                      ..
                    }

-- |Migrate time of the effective change from V0 to V1 accounts. Currently this
-- translates times relative to genesis to times relative to the unix epoch.
migratePendingChangeEffective :: P4.StateMigrationData -> PendingChangeEffective 'AccountV0 -> PendingChangeEffective 'AccountV1
migratePendingChangeEffective P4.StateMigrationData{..} (PendingChangeEffectiveV0 eff) =
    PendingChangeEffectiveV1 $
        addDuration
            migrationPreviousGenesisTime
            (migrationPreviousEpochDuration * fromIntegral eff)

-- |Migrate the stake pending change from the representation used by protocol
-- version @oldpv@ to the representation used by the protocol version @pv@. The
-- migration parameters supply auxiliary data needed for the migration.
migrateStakePendingChange ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    StakePendingChange (AccountVersionFor oldpv) ->
    StakePendingChange (AccountVersionFor pv)
migrateStakePendingChange StateMigrationParametersTrivial = id
migrateStakePendingChange StateMigrationParametersP1P2 = id
migrateStakePendingChange StateMigrationParametersP2P3 = id
migrateStakePendingChange (StateMigrationParametersP3ToP4 migration) = \case
    NoChange -> NoChange
    ReduceStake amnt eff -> ReduceStake amnt (migratePendingChangeEffective migration eff)
    RemoveStake eff -> RemoveStake (migratePendingChangeEffective migration eff)
migrateStakePendingChange StateMigrationParametersP4ToP5 = fmap coercePendingChangeEffectiveV1
