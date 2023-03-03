{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE StandaloneKindSignatures #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

module Concordium.Types.SeedState where

import Data.Serialize
import Data.Singletons.TH
import Prelude.Singletons

import Concordium.Crypto.SHA256 (Hash)
import Concordium.Types

-- This splice generates 'SSeedStateVersion' (a singletonised version of 'SeedStateVersion'), as
-- well as the type families 'SeedStateVersionFor' and 'SupportsEpochLength', and the singletonised
-- 'sSeedStateVersionFor' and 'sSupportsEpochLength', from 'seedStateVersionFor' and
-- 'supportsEpochLength'.
$( singletons
    [d|
        data SeedStateVersion
            = SeedStateVersion0
            | SeedStateVersion1

        seedStateVersionFor :: ProtocolVersion -> SeedStateVersion
        seedStateVersionFor P1 = SeedStateVersion0
        seedStateVersionFor P2 = SeedStateVersion0
        seedStateVersionFor P3 = SeedStateVersion0
        seedStateVersionFor P4 = SeedStateVersion0
        seedStateVersionFor P5 = SeedStateVersion0
        seedStateVersionFor P6 = SeedStateVersion1

        supportsEpochLength :: SeedStateVersion -> Bool
        supportsEpochLength SeedStateVersion0 = True
        supportsEpochLength SeedStateVersion1 = False
        |]
 )

-- |Constraint on a type level 'SeedStateVersion' that can be used to get a
-- corresponding 'SSeedStateVersion'.
type IsSeedStateVersion (ssv :: SeedStateVersion) = SingI ssv

-- |Witness an 'IsSeedStateVersion' constraint using a 'SProtocolVersion'.
withIsSeedStateVersionFor :: SProtocolVersion pv -> (IsSeedStateVersion (SeedStateVersionFor pv) => a) -> a
withIsSeedStateVersionFor spv = withSingI (sSeedStateVersionFor spv)

-- |State for computing the leadership election nonce.
--
-- (Implementation note: the constructors have equational constraints so that they have the same
-- return type. This allows them to have common field names (e.g. 'epoch'), which is not
-- allowed if the return types differ (e.g. @SeedState 'SeedStateVersion0@ and
-- @SeedState 'SeedStateVersion1@).)
data SeedState (ssv :: SeedStateVersion) where
    SeedStateV0 ::
        (ssv ~ 'SeedStateVersion0) =>
        { -- |Number of slots in an epoch. This is derived from genesis
          -- data and must not change.
          epochLength :: !EpochLength,
          -- |Current epoch.
          epoch :: !Epoch,
          -- |Current leadership election nonce.
          currentLeadershipElectionNonce :: !LeadershipElectionNonce,
          -- |The leadership election nonce updated with the block nonces
          -- of blocks in the first 2/3 of the current epoch.
          updatedNonce :: !Hash
        } ->
        SeedState ssv
    SeedStateV1 ::
        (ssv ~ 'SeedStateVersion1) =>
        { -- |Current epoch.
          epoch :: !Epoch,
          -- |Current leadership election nonce.
          currentLeadershipElectionNonce :: !LeadershipElectionNonce,
          -- |The leadership election nonce updated with the block nonces
          -- of blocks up to and including the trigger block.
          updatedNonce :: !Hash,
          -- |The first block in the epoch with timestamp at least this is considered to be the
          -- trigger block for the epoch transition.
          triggerBlockTime :: !Timestamp,
          -- |Flag indicating that a trigger block has been produced in the current epoch (on this
          -- chain).
          epochTransitionTriggered :: !Bool
        } ->
        SeedState ssv

instance Eq (SeedState ssv) where
    (SeedStateV0 el1 e1 clen1 un1) == (SeedStateV0 el2 e2 clen2 un2) =
        el1 == el2 && e1 == e2 && clen1 == clen2 && un1 == un2
    (SeedStateV1 e1 clen1 un1 tbt1 ett1) == (SeedStateV1 e2 clen2 un2 tbt2 ett2) =
        e1 == e2 && clen1 == clen2 && un1 == un2 && tbt1 == tbt2 && ett1 == ett2

instance Show (SeedState ssv) where
    show SeedStateV0{..} =
        "SeedStateV0{epochLength = "
            ++ show epochLength
            ++ ", epoch = "
            ++ show epoch
            ++ ", currentLeadershipElectionNonce = "
            ++ show currentLeadershipElectionNonce
            ++ ", updatedNonce = "
            ++ show updatedNonce
            ++ "}"
    show SeedStateV1{..} =
        "SeedStateV1{epoch = "
            ++ show epoch
            ++ ", currentLeadershipElectionNonce = "
            ++ show currentLeadershipElectionNonce
            ++ ", updatedNonce = "
            ++ show updatedNonce
            ++ ", triggerBlockTime = "
            ++ show triggerBlockTime
            ++ ", epochTransitionTriggered = "
            ++ show epochTransitionTriggered
            ++ "}"

-- |Serialize a 'SeedState'.
serializeSeedState :: Putter (SeedState ssv)
serializeSeedState SeedStateV0{..} = do
    put epochLength
    put epoch
    put currentLeadershipElectionNonce
    put updatedNonce
serializeSeedState SeedStateV1{..} = do
    put epoch
    put currentLeadershipElectionNonce
    put updatedNonce
    put triggerBlockTime
    put epochTransitionTriggered

-- |Deserialize a 'SeedState' of a given version.
deserializeSeedState :: SSeedStateVersion ssv -> Get (SeedState ssv)
deserializeSeedState SSeedStateVersion0 = do
    epochLength <- get
    epoch <- get
    currentLeadershipElectionNonce <- get
    updatedNonce <- get
    return SeedStateV0{..}
deserializeSeedState SSeedStateVersion1 = do
    epoch <- get
    currentLeadershipElectionNonce <- get
    updatedNonce <- get
    triggerBlockTime <- get
    epochTransitionTriggered <- get
    return SeedStateV1{..}

instance IsSeedStateVersion ssv => Serialize (SeedState ssv) where
    put = serializeSeedState
    get = deserializeSeedState sing

-- |Instantiate a seed state: leadership election nonce should be random, epoch length should be long, but not too long...
initialSeedStateV0 :: LeadershipElectionNonce -> EpochLength -> SeedState 'SeedStateVersion0
initialSeedStateV0 nonce theEpochLength =
    SeedStateV0
        { epoch = 0,
          epochLength = theEpochLength,
          currentLeadershipElectionNonce = nonce,
          updatedNonce = nonce
        }

-- |Instantiate a seed state for consensus version 1, given the initial leadership election nonce
-- and the trigger time for the first epoch transition.
initialSeedStateV1 :: LeadershipElectionNonce -> Timestamp -> SeedState 'SeedStateVersion1
initialSeedStateV1 nonce triggerTime =
    SeedStateV1
        { epoch = 0,
          currentLeadershipElectionNonce = nonce,
          updatedNonce = nonce,
          triggerBlockTime = triggerTime,
          epochTransitionTriggered = False
        }
