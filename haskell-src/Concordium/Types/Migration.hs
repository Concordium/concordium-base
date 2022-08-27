{-# LANGUAGE GADTs #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DataKinds #-}

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
migrateAuthorizations StateMigrationParametersTrivialP1P2 auths = auths
migrateAuthorizations StateMigrationParametersTrivialP2P3 auths = auths
migrateAuthorizations (StateMigrationParametersP3ToP4 migration) Authorizations{..} =
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
migrateMintDistribution ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    MintDistribution (ChainParametersVersionFor oldpv) ->
    MintDistribution (ChainParametersVersionFor pv)
migrateMintDistribution StateMigrationParametersTrivial mint = mint
migrateMintDistribution StateMigrationParametersTrivialP1P2 mint = mint
migrateMintDistribution StateMigrationParametersTrivialP2P3 mint = mint
migrateMintDistribution StateMigrationParametersP3ToP4{} MintDistribution{..} =
    MintDistribution{_mdMintPerSlot = MintPerSlotForCPV0None, ..}

-- |Apply a state migration to a 'PoolParameters' structure.
--
-- [P3 to P4]: the new pool parameters are defined by the migration parameters.
migratePoolParameters ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    PoolParameters (ChainParametersVersionFor oldpv) ->
    PoolParameters (ChainParametersVersionFor pv)
migratePoolParameters StateMigrationParametersTrivial poolParams = poolParams
migratePoolParameters StateMigrationParametersTrivialP1P2 poolParams = poolParams
migratePoolParameters StateMigrationParametersTrivialP2P3 poolParams = poolParams
migratePoolParameters (StateMigrationParametersP3ToP4 migration) _ =
    P4.updatePoolParameters (P4.migrationProtocolUpdateData migration)

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
migrateChainParameters StateMigrationParametersTrivialP1P2 cps = cps
migrateChainParameters StateMigrationParametersTrivialP2P3 cps = cps
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
migrateAccountStake StateMigrationParametersTrivialP1P2 = id
migrateAccountStake StateMigrationParametersTrivialP2P3 = id
migrateAccountStake (StateMigrationParametersP3ToP4 migration) =
    \case
        AccountStakeNone -> AccountStakeNone
        AccountStakeBaker AccountBaker{_accountBakerInfo = BakerInfoExV0 bi, ..} ->
            AccountStakeBaker
                AccountBaker
                    { _accountBakerInfo = BakerInfoExV1 bi (P4.defaultBakerPoolInfo migration),
                      _bakerPendingChange = migratePCE migration <$> _bakerPendingChange,
                      ..
                    }

migratePCE :: P4.StateMigrationData -> PendingChangeEffective 'AccountV0 -> PendingChangeEffective 'AccountV1
migratePCE P4.StateMigrationData{..} (PendingChangeEffectiveV0 eff) =
    PendingChangeEffectiveV1 $
         addDuration
             migrationPreviousGenesisTime
             (migrationPreviousEpochDuration * fromIntegral eff)

migrateStakePendingChange :: forall oldpv pv .
    StateMigrationParameters oldpv pv ->
    StakePendingChange (AccountVersionFor oldpv) ->
    StakePendingChange (AccountVersionFor pv)
migrateStakePendingChange StateMigrationParametersTrivial = id
migrateStakePendingChange StateMigrationParametersTrivialP1P2 = id
migrateStakePendingChange StateMigrationParametersTrivialP2P3 = id
migrateStakePendingChange (StateMigrationParametersP3ToP4 migration) = \case
  NoChange -> NoChange
  ReduceStake amnt eff -> ReduceStake amnt (migratePCE migration eff)
  RemoveStake eff -> RemoveStake (migratePCE migration eff)
  
