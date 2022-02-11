{-# LANGUAGE GADTs #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Concordium.Types.Migration where

import Concordium.Genesis.Data
import qualified Concordium.Genesis.Data.P4 as P4
import Concordium.Types
import Concordium.Types.Parameters
import Concordium.Types.Updates

-- |Apply a state migration to an 'Authorizations' structure.
migrateAuthorizations ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    Authorizations (ChainParametersVersionFor oldpv) ->
    Authorizations (ChainParametersVersionFor pv)
migrateAuthorizations StateMigrationParametersTrivial auths = auths
migrateAuthorizations
    (StateMigrationParametersP3ToP4 P4.StateMigrationParametersP3toP4{..})
    Authorizations{..} =
        Authorizations
            { asCooldownParameters = JustForCPV1 migrationCooldownParametersAccessStructure,
              asTimeParameters = JustForCPV1 migrationTimeParametersAccessStructure,
              ..
            }

-- |Apply a state migration to an 'UpdateKeysCollection' structure.
migrateUpdateKeysCollection ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    UpdateKeysCollection (ChainParametersVersionFor oldpv) ->
    UpdateKeysCollection (ChainParametersVersionFor pv)
migrateUpdateKeysCollection migration UpdateKeysCollection{..} =
    UpdateKeysCollection{level2Keys = migrateAuthorizations migration level2Keys, ..}

migrateMintDistribution ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    MintDistribution (ChainParametersVersionFor oldpv) ->
    MintDistribution (ChainParametersVersionFor pv)
migrateMintDistribution StateMigrationParametersTrivial mint = mint
migrateMintDistribution StateMigrationParametersP3ToP4{} MintDistribution{..} =
    MintDistribution{_mdMintPerSlot = MintPerSlotForCPV0None, ..}

migratePoolParameters ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    PoolParameters (ChainParametersVersionFor oldpv) ->
    PoolParameters (ChainParametersVersionFor pv)
migratePoolParameters StateMigrationParametersTrivial poolParams = poolParams
migratePoolParameters (StateMigrationParametersP3ToP4 migration) _ =
    P4.migrationPoolParameters migration

migrateChainParameters ::
    forall oldpv pv.
    StateMigrationParameters oldpv pv ->
    ChainParameters oldpv ->
    ChainParameters pv
migrateChainParameters StateMigrationParametersTrivial cps = cps
migrateChainParameters m@(StateMigrationParametersP3ToP4 migration) ChainParameters{..} =
    ChainParameters
        { _cpCooldownParameters = P4.migrationCooldownParameters migration,
          _cpTimeParameters = P4.migrationTimeParameters migration,
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