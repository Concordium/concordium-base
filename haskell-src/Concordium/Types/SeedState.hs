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
{-# LANGUAGE NoFieldSelectors #-}

module Concordium.Types.SeedState where

import Data.Serialize
import Data.Singletons.TH
import Lens.Micro.Platform
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
        seedStateVersionFor P7 = SeedStateVersion1

        supportsEpochLength :: SeedStateVersion -> Bool
        supportsEpochLength SeedStateVersion0 = True
        supportsEpochLength SeedStateVersion1 = False
        |]
 )

-- | Constraint on a type level 'SeedStateVersion' that can be used to get a
--  corresponding 'SSeedStateVersion'.
type IsSeedStateVersion (ssv :: SeedStateVersion) = SingI ssv

-- | Witness an 'IsSeedStateVersion' constraint using a 'SProtocolVersion'.
withIsSeedStateVersionFor :: SProtocolVersion pv -> ((IsSeedStateVersion (SeedStateVersionFor pv)) => a) -> a
withIsSeedStateVersionFor spv = withSingI (sSeedStateVersionFor spv)

-- | State for computing the leadership election nonce.
data SeedState (ssv :: SeedStateVersion) where
    SeedStateV0 ::
        { -- | Number of slots in an epoch. This is derived from genesis
          --  data and must not change.
          ss0EpochLength :: !EpochLength,
          -- | Current epoch.
          ss0Epoch :: !Epoch,
          -- | Current leadership election nonce.
          ss0CurrentLeadershipElectionNonce :: !LeadershipElectionNonce,
          -- | The leadership election nonce updated with the block nonces
          --  of blocks in the first 2/3 of the current epoch.
          ss0UpdatedNonce :: !Hash
        } ->
        SeedState 'SeedStateVersion0
    SeedStateV1 ::
        { -- | Current epoch.
          ss1Epoch :: !Epoch,
          -- | Current leadership election nonce.
          ss1CurrentLeadershipElectionNonce :: !LeadershipElectionNonce,
          -- | The leadership election nonce updated with the block nonces
          --  of blocks up to and including the trigger block.
          ss1UpdatedNonce :: !Hash,
          -- | The first block in the epoch with timestamp at least this is considered to be the
          --  trigger block for the epoch transition.
          ss1TriggerBlockTime :: !Timestamp,
          -- | Flag indicating that a trigger block has been produced in the current epoch (on this
          --  chain).
          ss1EpochTransitionTriggered :: !Bool,
          -- | Flag indicating that a protocol update has become effective.
          --  Note that the protocol update will not actually take effect until at
          --  the end of the current epoch.
          ss1ShutdownTriggered :: !Bool
        } ->
        SeedState 'SeedStateVersion1

-- Note that we generate the below lenses manually, and combined with the usage of 'NoFieldSelectors'
-- we get type safe selector functions for the 'SeedState's present in this module.

-- | Number of slots in an epoch.
epochLength :: SimpleGetter (SeedState 'SeedStateVersion0) EpochLength
{-# INLINE epochLength #-}
epochLength = to $ \SeedStateV0{..} -> ss0EpochLength

-- | Lens for the current epoch of the seed state.
epoch :: Lens' (SeedState ssv) Epoch
{-# INLINE epoch #-}
epoch f SeedStateV0{..} = (\newEpoch -> SeedStateV0{ss0Epoch = newEpoch, ..}) <$> f ss0Epoch
epoch f SeedStateV1{..} = (\newEpoch -> SeedStateV1{ss1Epoch = newEpoch, ..}) <$> f ss1Epoch

-- | Lens for the current leadership election nonce of the seed state.
currentLeadershipElectionNonce :: Lens' (SeedState ssv) LeadershipElectionNonce
{-# INLINE currentLeadershipElectionNonce #-}
currentLeadershipElectionNonce f SeedStateV0{..} =
    (\newCLEN -> SeedStateV0{ss0CurrentLeadershipElectionNonce = newCLEN, ..})
        <$> f ss0CurrentLeadershipElectionNonce
currentLeadershipElectionNonce f SeedStateV1{..} =
    (\newCLEN -> SeedStateV1{ss1CurrentLeadershipElectionNonce = newCLEN, ..})
        <$> f ss1CurrentLeadershipElectionNonce

-- | Lens for the leadership election nonce updated with the block nonces
--  of blocks up to and including the trigger block.
updatedNonce :: Lens' (SeedState ssv) Hash
updatedNonce f SeedStateV0{..} =
    (\newUN -> SeedStateV0{ss0UpdatedNonce = newUN, ..})
        <$> f ss0UpdatedNonce
updatedNonce f SeedStateV1{..} =
    (\newUN -> SeedStateV1{ss1UpdatedNonce = newUN, ..})
        <$> f ss1UpdatedNonce

-- | Lens for the trigger block time. The first block in the epoch with timestamp at least this is
--  considered to be the trigger block for the epoch transition.
triggerBlockTime :: Lens' (SeedState 'SeedStateVersion1) Timestamp
triggerBlockTime f SeedStateV1{..} =
    (\newTBT -> SeedStateV1{ss1TriggerBlockTime = newTBT, ..}) <$> f ss1TriggerBlockTime

-- | Lens for the flag that indicates if a trigger block has been produced in the current epoch.
epochTransitionTriggered :: Lens' (SeedState 'SeedStateVersion1) Bool
epochTransitionTriggered f SeedStateV1{..} =
    (\newETT -> SeedStateV1{ss1EpochTransitionTriggered = newETT, ..})
        <$> f ss1EpochTransitionTriggered

-- | Lens for the flag that indicates if a trigger block has been produced in the current epoch.
shutdownTriggered :: Lens' (SeedState 'SeedStateVersion1) Bool
shutdownTriggered f SeedStateV1{..} =
    (\newST -> SeedStateV1{ss1ShutdownTriggered = newST, ..})
        <$> f ss1ShutdownTriggered

instance Eq (SeedState ssv) where
    (SeedStateV0 el1 e1 clen1 un1) == (SeedStateV0 el2 e2 clen2 un2) =
        el1 == el2 && e1 == e2 && clen1 == clen2 && un1 == un2
    (SeedStateV1 e1 clen1 un1 tbt1 ett1 st1) == (SeedStateV1 e2 clen2 un2 tbt2 ett2 st2) =
        e1 == e2 && clen1 == clen2 && un1 == un2 && tbt1 == tbt2 && ett1 == ett2 && st1 == st2

instance Show (SeedState ssv) where
    show SeedStateV0{..} =
        "SeedStateV0{epochLength = "
            ++ show ss0EpochLength
            ++ ", epoch = "
            ++ show ss0Epoch
            ++ ", currentLeadershipElectionNonce = "
            ++ show ss0CurrentLeadershipElectionNonce
            ++ ", updatedNonce = "
            ++ show ss0UpdatedNonce
            ++ "}"
    show SeedStateV1{..} =
        "SeedStateV1{epoch = "
            ++ show ss1Epoch
            ++ ", currentLeadershipElectionNonce = "
            ++ show ss1CurrentLeadershipElectionNonce
            ++ ", updatedNonce = "
            ++ show ss1UpdatedNonce
            ++ ", triggerBlockTime = "
            ++ show ss1TriggerBlockTime
            ++ ", epochTransitionTriggered = "
            ++ show ss1EpochTransitionTriggered
            ++ "}"

-- | Serialize a 'SeedState'.
serializeSeedState :: Putter (SeedState ssv)
serializeSeedState SeedStateV0{..} = do
    put ss0EpochLength
    put ss0Epoch
    put ss0CurrentLeadershipElectionNonce
    put ss0UpdatedNonce
serializeSeedState SeedStateV1{..} = do
    put ss1Epoch
    put ss1CurrentLeadershipElectionNonce
    put ss1UpdatedNonce
    put ss1TriggerBlockTime
    put ss1EpochTransitionTriggered
    put ss1ShutdownTriggered

-- | Deserialize a 'SeedState' of a given version.
deserializeSeedState :: SSeedStateVersion ssv -> Get (SeedState ssv)
deserializeSeedState SSeedStateVersion0 = do
    ss0EpochLength <- get
    ss0Epoch <- get
    ss0CurrentLeadershipElectionNonce <- get
    ss0UpdatedNonce <- get
    return SeedStateV0{..}
deserializeSeedState SSeedStateVersion1 = do
    ss1Epoch <- get
    ss1CurrentLeadershipElectionNonce <- get
    ss1UpdatedNonce <- get
    ss1TriggerBlockTime <- get
    ss1EpochTransitionTriggered <- get
    ss1ShutdownTriggered <- get
    return SeedStateV1{..}

instance (IsSeedStateVersion ssv) => Serialize (SeedState ssv) where
    put = serializeSeedState
    get = deserializeSeedState sing

-- | Instantiate a seed state: leadership election nonce should be random, epoch length should be long, but not too long...
initialSeedStateV0 :: LeadershipElectionNonce -> EpochLength -> SeedState 'SeedStateVersion0
initialSeedStateV0 nonce theEpochLength =
    SeedStateV0
        { ss0Epoch = 0,
          ss0EpochLength = theEpochLength,
          ss0CurrentLeadershipElectionNonce = nonce,
          ss0UpdatedNonce = nonce
        }

-- | Instantiate a seed state for consensus version 1, given the initial leadership election nonce
--  and the trigger time for the first epoch transition.
initialSeedStateV1 :: LeadershipElectionNonce -> Timestamp -> SeedState 'SeedStateVersion1
initialSeedStateV1 nonce triggerTime =
    SeedStateV1
        { ss1Epoch = 0,
          ss1CurrentLeadershipElectionNonce = nonce,
          ss1UpdatedNonce = nonce,
          ss1TriggerBlockTime = triggerTime,
          ss1EpochTransitionTriggered = False,
          ss1ShutdownTriggered = False
        }
