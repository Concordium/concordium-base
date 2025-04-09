{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Concordium.Types.Migration where

import Concordium.Genesis.Data
import qualified Concordium.Genesis.Data.P4 as P4
import qualified Concordium.Genesis.Data.P6 as P6
import qualified Concordium.Genesis.Data.P8 as P8
import Concordium.Types
import Concordium.Types.Accounts
import Concordium.Types.Parameters
import Concordium.Types.Updates

-- | Apply a state migration to an 'Authorizations' structure.
--
--  [P3 to P4]: access structures for cooldown and time parameters are added.
migrateAuthorizations ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    Authorizations (AuthorizationsVersionForPV oldpv) ->
    Authorizations (AuthorizationsVersionForPV pv)
migrateAuthorizations StateMigrationParametersTrivial auths = auths
migrateAuthorizations StateMigrationParametersP1P2 auths = auths
migrateAuthorizations StateMigrationParametersP2P3 auths = auths
migrateAuthorizations (StateMigrationParametersP3ToP4 migration) Authorizations{..} =
    Authorizations
        { asCooldownParameters = CTrue updateCooldownParametersAccessStructure,
          asTimeParameters = CTrue updateTimeParametersAccessStructure,
          ..
        }
  where
    P4.ProtocolUpdateData{..} = P4.migrationProtocolUpdateData migration
migrateAuthorizations StateMigrationParametersP4ToP5 auths = auths
-- Note that the authorization for the consensus parameters v0
-- are carried over to consensus parameters v1.
migrateAuthorizations StateMigrationParametersP5ToP6{} auths = auths
migrateAuthorizations StateMigrationParametersP6ToP7{} auths = auths
migrateAuthorizations StateMigrationParametersP7ToP8{} auths = auths
migrateAuthorizations StateMigrationParametersP8ToP9{} auths = auths

-- | Apply a state migration to an 'UpdateKeysCollection' structure.
--
--  [P3 to P4]: access structures for cooldown and time parameters are added.
migrateUpdateKeysCollection ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    UpdateKeysCollection (AuthorizationsVersionForPV oldpv) ->
    UpdateKeysCollection (AuthorizationsVersionForPV pv)
migrateUpdateKeysCollection migration UpdateKeysCollection{..} =
    UpdateKeysCollection{level2Keys = migrateAuthorizations migration level2Keys, ..}

-- | Apply a state migration to a 'MintDistribution' structure.
--
--  [P3 to P4]: the mint-per-slot rate is removed.
migrateMintDistribution ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    MintDistribution (MintDistributionVersionFor (ChainParametersVersionFor oldpv)) ->
    MintDistribution (MintDistributionVersionFor (ChainParametersVersionFor pv))
migrateMintDistribution StateMigrationParametersTrivial mint = mint
migrateMintDistribution StateMigrationParametersP1P2 mint = mint
migrateMintDistribution StateMigrationParametersP2P3 mint = mint
migrateMintDistribution StateMigrationParametersP3ToP4{} MintDistribution{..} =
    MintDistribution{_mdMintPerSlot = CFalse, ..}
migrateMintDistribution StateMigrationParametersP4ToP5 mint = mint
migrateMintDistribution StateMigrationParametersP5ToP6{} mint = mint
migrateMintDistribution StateMigrationParametersP6ToP7{} mint = mint
migrateMintDistribution StateMigrationParametersP7ToP8{} mint = mint
migrateMintDistribution StateMigrationParametersP8ToP9{} mint = mint

-- | Apply a state migration to a 'PoolParameters' structure.
--
--  [P3 to P4]: the new pool parameters are defined by the migration parameters.
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
migratePoolParameters StateMigrationParametersP5ToP6{} poolParams = poolParams
migratePoolParameters StateMigrationParametersP6ToP7{} poolParams = poolParams
migratePoolParameters StateMigrationParametersP7ToP8{} poolParams = poolParams
migratePoolParameters StateMigrationParametersP8ToP9{} poolParams = poolParams

-- | Apply a state migration to a 'GASRewards' structure.
--
--  This does nothing except for the P5->P6 protocol update,
--  which removes the finalization proof reward.
migrateGASRewards ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    GASRewards (GasRewardsVersionFor (ChainParametersVersionFor oldpv)) ->
    GASRewards (GasRewardsVersionFor (ChainParametersVersionFor pv))
migrateGASRewards StateMigrationParametersTrivial gr = gr
migrateGASRewards StateMigrationParametersP1P2 gr = gr
migrateGASRewards StateMigrationParametersP2P3 gr = gr
migrateGASRewards StateMigrationParametersP3ToP4{} gr = gr
migrateGASRewards StateMigrationParametersP4ToP5 gr = gr
migrateGASRewards StateMigrationParametersP5ToP6{} GASRewards{..} = GASRewards{_gasFinalizationProof = CFalse, ..}
migrateGASRewards StateMigrationParametersP6ToP7{} gr = gr
migrateGASRewards StateMigrationParametersP7ToP8{} gr = gr
migrateGASRewards StateMigrationParametersP8ToP9{} gr = gr

-- | Apply a state migration to a 'ChainParameters' structure.
--
--  [P3 to P4]: the new cooldown, time and pool parameters are given by the migration parameters;
--    the mint-per-slot rate is removed from the reward parameters.
--
--  [P5 to P6]: the new consensus, finalization committee parameters are given by the migration parameters;
--    the GAS finalization proof reward is removed.
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
          _cpTimeParameters = SomeParam updateTimeParameters,
          _cpRewardParameters =
            RewardParameters
                { _rpMintDistribution = migrateMintDistribution m _rpMintDistribution,
                  _rpGASRewards = migrateGASRewards m _rpGASRewards,
                  ..
                },
          _cpPoolParameters = migratePoolParameters m _cpPoolParameters,
          _cpFinalizationCommitteeParameters = NoParam,
          _cpValidatorScoreParameters = NoParam,
          ..
        }
  where
    RewardParameters{..} = _cpRewardParameters
    P4.ProtocolUpdateData{..} = P4.migrationProtocolUpdateData migration
migrateChainParameters StateMigrationParametersP4ToP5 cps = cps
migrateChainParameters m@(StateMigrationParametersP5ToP6 migration) ChainParameters{..} =
    ChainParameters
        { _cpConsensusParameters = P6.updateConsensusParameters $ P6.migrationProtocolUpdateData migration,
          _cpRewardParameters =
            RewardParameters
                { _rpMintDistribution = migrateMintDistribution m _rpMintDistribution,
                  _rpGASRewards = migrateGASRewards m _rpGASRewards,
                  ..
                },
          _cpPoolParameters = migratePoolParameters m _cpPoolParameters,
          _cpFinalizationCommitteeParameters = SomeParam finalizationCommitteeParameters,
          -- We unwrap and wrap here in order to associate the correct cpv
          -- with the time parameters.
          _cpTimeParameters = SomeParam $ unOParam _cpTimeParameters,
          _cpValidatorScoreParameters = NoParam,
          ..
        }
  where
    RewardParameters{..} = _cpRewardParameters
    finalizationCommitteeParameters = P6.updateFinalizationCommitteeParameters $ P6.migrationProtocolUpdateData migration
migrateChainParameters StateMigrationParametersP6ToP7{} cps = cps
migrateChainParameters m@(StateMigrationParametersP7ToP8 migration) ChainParameters{..} =
    ChainParameters
        { _cpValidatorScoreParameters = SomeParam $ P8.updateValidatorScoreParameters $ P8.migrationProtocolUpdateData migration,
          _cpTimeParameters = SomeParam $ unOParam _cpTimeParameters,
          _cpFinalizationCommitteeParameters = SomeParam $ unOParam _cpFinalizationCommitteeParameters,
          _cpPoolParameters = migratePoolParameters m _cpPoolParameters,
          _cpRewardParameters =
            RewardParameters
                { _rpMintDistribution = migrateMintDistribution m _rpMintDistribution,
                  _rpGASRewards = migrateGASRewards m _rpGASRewards,
                  ..
                },
          ..
        }
  where
    RewardParameters{..} = _cpRewardParameters
migrateChainParameters StateMigrationParametersP8ToP9{} ChainParameters{..} = ChainParameters
        { _cpValidatorScoreParameters = SomeParam $ unOParam _cpValidatorScoreParameters,
          _cpTimeParameters = SomeParam $ unOParam _cpTimeParameters,
          _cpFinalizationCommitteeParameters = SomeParam $ unOParam _cpFinalizationCommitteeParameters,
          _cpRewardParameters = RewardParameters { .. },
          ..
        }
  where
    RewardParameters{..} = _cpRewardParameters

-- | Migrate time of the effective change from V0 to V1 accounts. Currently this
--  translates times relative to genesis to times relative to the unix epoch.
migratePendingChangeEffective :: P4.StateMigrationData -> PendingChangeEffective 'AccountV0 -> PendingChangeEffective 'AccountV1
migratePendingChangeEffective P4.StateMigrationData{..} (PendingChangeEffectiveV0 eff) =
    PendingChangeEffectiveV1 $
        addDuration
            migrationPreviousGenesisTime
            (migrationPreviousEpochDuration * fromIntegral eff)

-- | Migrate the stake pending change from the representation used by protocol
--  version @oldpv@ to the representation used by the protocol version @pv@. The
--  migration parameters supply auxiliary data needed for the migration.
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
migrateStakePendingChange StateMigrationParametersP5ToP6{} = id
migrateStakePendingChange StateMigrationParametersP6ToP7{} = const NoChange
migrateStakePendingChange StateMigrationParametersP7ToP8{} = const NoChange
migrateStakePendingChange StateMigrationParametersP8ToP9{} = const NoChange
