{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
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
import Concordium.Types.Conditionally

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
data SeedState (ssv :: SeedStateVersion) = SeedState
    { -- |Number of slots in an epoch. This is derived from genesis
      -- data and must not change.
      epochLength :: !(Conditionally (SupportsEpochLength ssv) EpochLength),
      -- |Current epoch
      epoch :: !Epoch,
      -- |Current leadership election nonce
      currentLeadershipElectionNonce :: !LeadershipElectionNonce,
      -- |The leadership election nonce updated with the block nonces
      -- of blocks in the first 2/3 of the current epoch.
      updatedNonce :: !Hash
    }
    deriving (Eq, Show)

putSeedState :: Putter (SeedState ssv)
putSeedState SeedState{..} = do
    mapM_ put epochLength
    put epoch
    put currentLeadershipElectionNonce
    put updatedNonce

getSeedState :: SSeedStateVersion ssv -> Get (SeedState ssv)
getSeedState ssv = do
    epochLength <- conditionallyA (sSupportsEpochLength ssv) get
    epoch <- get
    currentLeadershipElectionNonce <- get
    updatedNonce <- get
    return SeedState{..}

instance IsSeedStateVersion ssv => Serialize (SeedState ssv) where
    put = putSeedState
    get = getSeedState sing

-- |Instantiate a seed state: leadership election nonce should be random, epoch length should be long, but not too long...
initialSeedStateV0 :: LeadershipElectionNonce -> EpochLength -> SeedState 'SeedStateVersion0
initialSeedStateV0 nonce theEpochLength =
    SeedState
        { epoch = 0,
          epochLength = CTrue theEpochLength,
          currentLeadershipElectionNonce = nonce,
          updatedNonce = nonce
        }

-- |Instantiate a seed state: leadership election nonce should be random.
initialSeedStateV1 :: LeadershipElectionNonce -> SeedState 'SeedStateVersion1
initialSeedStateV1 nonce =
    SeedState
        { epoch = 0,
          epochLength = CFalse,
          currentLeadershipElectionNonce = nonce,
          updatedNonce = nonce
        }
