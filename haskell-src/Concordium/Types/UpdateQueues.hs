{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Implementation of the chain update mechanism: https://concordium.gitlab.io/whitepapers/update-mechanism/main.pdf
module Concordium.Types.UpdateQueues where

import Control.Monad
import Data.Aeson as AE
import Data.Aeson.Types as AE
import qualified Data.ByteString as BS
import Data.Foldable
import Data.Serialize
import Lens.Micro.Platform

import qualified Concordium.Crypto.SHA256 as H
import Concordium.Types
import qualified Concordium.Types.AnonymityRevokers as ARS
import Concordium.Types.HashableTo
import qualified Concordium.Types.IdentityProviders as IPS
import Concordium.Types.Parameters
import Concordium.Types.Updates
import Concordium.Utils.Serialization

-- | An update queue consists of pending future updates ordered by
--  the time at which they will take effect.
data UpdateQueue e = UpdateQueue
    { -- | The next available sequence number for an update.
      _uqNextSequenceNumber :: !UpdateSequenceNumber,
      -- | Pending updates, in ascending order of effective time.
      _uqQueue :: ![(TransactionTime, e)]
    }
    deriving (Show, Functor, Eq)

makeLenses ''UpdateQueue

-- | An optional queue. The queue is present if @pt@ is present for a @cpv@.
type OUpdateQueue (pt :: ParameterType) (cpv :: ChainParametersVersion) e = OParam pt cpv (UpdateQueue e)

instance (HashableTo H.Hash e) => HashableTo H.Hash (UpdateQueue e) where
    getHash UpdateQueue{..} = H.hash $ runPut $ do
        put _uqNextSequenceNumber
        putLength $ length _uqQueue
        mapM_ (\(t, e) -> put t >> put (getHash e :: H.Hash)) _uqQueue

-- | Serialize an update queue in V0 format.
putUpdateQueueV0 :: (Serialize e) => Putter (UpdateQueue e)
putUpdateQueueV0 = putUpdateQueueV0With put

-- | Serialize an update queue in V0 format.
putUpdateQueueV0With :: Putter e -> Putter (UpdateQueue e)
putUpdateQueueV0With putElem UpdateQueue{..} = do
    put _uqNextSequenceNumber
    forM_ _uqQueue $ \(tt, v) -> do
        putWord8 1
        put tt
        putElem v
    putWord8 0

-- | Deserialize an update queue in V0 format.
--  The parameter defines how entries in the queue are deserialized.
getUpdateQueueV0With :: Get e -> Get (UpdateQueue e)
getUpdateQueueV0With getElem = do
    _uqNextSequenceNumber <- get
    let loop lastTT =
            getWord8 >>= \case
                0 -> return []
                1 -> do
                    tt <- get
                    unless (lastTT < Just tt) $ fail "Update queue not in ascending order"
                    v <- getElem
                    ((tt, v) :) <$> loop (Just tt)
                _ -> fail "Invalid update queue"
    _uqQueue <- loop Nothing
    return UpdateQueue{..}

-- | Deserialize an update queue in V0 format.
getUpdateQueueV0 :: (Serialize e) => Get (UpdateQueue e)
getUpdateQueueV0 = getUpdateQueueV0With get

instance (ToJSON e) => ToJSON (UpdateQueue e) where
    toJSON UpdateQueue{..} =
        object
            [ "nextSequenceNumber" AE..= _uqNextSequenceNumber,
              "queue" AE..= [object ["effectiveTime" AE..= et, "update" AE..= u] | (et, u) <- _uqQueue]
            ]

instance (FromJSON e) => FromJSON (UpdateQueue e) where
    parseJSON = withObject "Update queue" $ \o -> do
        _uqNextSequenceNumber <- o AE..: "nextSequenceNumber"
        queue <- o AE..: "queue"
        _uqQueue <-
            withArray
                "queue"
                ( \vec -> forM (toList vec) $ withObject "Queue entry" $ \e -> do
                    tt <- e AE..: "effectiveTime"
                    upd <- e AE..: "update"
                    return (tt, upd)
                )
                queue
        return UpdateQueue{..}

-- | Update queue with no pending updates, and with the minimal next
--  sequence number.
emptyUpdateQueue :: UpdateQueue e
emptyUpdateQueue =
    UpdateQueue
        { _uqNextSequenceNumber = minUpdateSequenceNumber,
          _uqQueue = []
        }

-- | Add an update event to an update queue, incrementing the sequence number.
--  Any updates in the queue with later or equal effective times are removed
--  from the queue.
enqueue :: TransactionTime -> e -> UpdateQueue e -> UpdateQueue e
enqueue !t !e =
    (uqNextSequenceNumber +~ 1)
        . (uqQueue %~ \q -> let !r = takeWhile ((< t) . fst) q in r ++ [(t, e)])

-- | Update queues for all on-chain update types.
data PendingUpdates cpv = PendingUpdates
    { -- | Updates to the root keys.
      _pRootKeysUpdateQueue :: !(UpdateQueue (HigherLevelKeys RootKeysKind)),
      -- | Updates to the level 1 keys.
      _pLevel1KeysUpdateQueue :: !(UpdateQueue (HigherLevelKeys Level1KeysKind)),
      -- | Updates to the level 2 keys.
      _pLevel2KeysUpdateQueue :: !(UpdateQueue (Authorizations (AuthorizationsVersionFor cpv))),
      -- | Protocol updates.
      _pProtocolQueue :: !(UpdateQueue ProtocolUpdate),
      -- | Updates to the election difficulty parameter (CPV0 and CPV1 only).
      _pElectionDifficultyQueue :: !(OUpdateQueue 'PTElectionDifficulty cpv ElectionDifficulty),
      -- | Updates to the euro:energy exchange rate.
      _pEuroPerEnergyQueue :: !(UpdateQueue ExchangeRate),
      -- | Updates to the GTU:euro exchange rate.
      _pMicroGTUPerEuroQueue :: !(UpdateQueue ExchangeRate),
      -- | Updates to the foundation account.
      _pFoundationAccountQueue :: !(UpdateQueue AccountIndex),
      -- | Updates to the mint distribution.
      _pMintDistributionQueue :: !(UpdateQueue (MintDistribution (MintDistributionVersionFor cpv))),
      -- | Updates to the transaction fee distribution.
      _pTransactionFeeDistributionQueue :: !(UpdateQueue TransactionFeeDistribution),
      -- | Updates to the GAS rewards.
      _pGASRewardsQueue :: !(UpdateQueue (GASRewards (GasRewardsVersionFor cpv))),
      -- | Updates pool parameters.
      _pPoolParametersQueue :: !(UpdateQueue (PoolParameters cpv)),
      -- | Adds a new anonymity revoker.
      _pAddAnonymityRevokerQueue :: !(UpdateQueue ARS.ArInfo),
      -- | Adds a new identity provider.
      _pAddIdentityProviderQueue :: !(UpdateQueue IPS.IpInfo),
      -- | Updates to cooldown parameters (CPV1 onwards).
      _pCooldownParametersQueue :: !(OUpdateQueue 'PTCooldownParametersAccessStructure cpv (CooldownParameters cpv)),
      -- | Updates to time parameters (CPV1 onwards).
      _pTimeParametersQueue :: !(OUpdateQueue 'PTTimeParameters cpv TimeParameters),
      -- | Updates to the consensus version 2 timeout parameters (CPV2 onwards).
      _pTimeoutParametersQueue :: !(OUpdateQueue 'PTTimeoutParameters cpv TimeoutParameters),
      -- | Minimum block time for consensus version 2 (CPV2 onwards).
      _pMinBlockTimeQueue :: !(OUpdateQueue 'PTMinBlockTime cpv Duration),
      -- | Block energy limit (CPV2 onwards).
      _pBlockEnergyLimitQueue :: !(OUpdateQueue 'PTBlockEnergyLimit cpv Energy),
      -- | Finalization committee parameters queue (CPV2 onwards).
      _pFinalizationCommitteeParametersQueue :: !(OUpdateQueue 'PTFinalizationCommitteeParameters cpv FinalizationCommitteeParameters)
    }
    deriving (Show, Eq)

makeLenses ''PendingUpdates

instance (IsChainParametersVersion cpv) => HashableTo H.Hash (PendingUpdates cpv) where
    getHash PendingUpdates{..} =
        withCPVConstraints (chainParametersVersion @cpv) $
            H.hash $
                hsh _pRootKeysUpdateQueue
                    <> hsh _pLevel1KeysUpdateQueue
                    <> hsh _pLevel2KeysUpdateQueue
                    <> hsh _pProtocolQueue
                    <> optionalHash _pElectionDifficultyQueue
                    <> hsh _pEuroPerEnergyQueue
                    <> hsh _pMicroGTUPerEuroQueue
                    <> hsh _pFoundationAccountQueue
                    <> hsh _pMintDistributionQueue
                    <> hsh _pTransactionFeeDistributionQueue
                    <> hsh _pGASRewardsQueue
                    <> hsh _pPoolParametersQueue
                    <> hsh _pAddAnonymityRevokerQueue
                    <> hsh _pAddIdentityProviderQueue
                    <> optionalHash _pCooldownParametersQueue
                    <> optionalHash _pTimeParametersQueue
                    <> optionalHash _pTimeoutParametersQueue
                    <> optionalHash _pMinBlockTimeQueue
                    <> optionalHash _pBlockEnergyLimitQueue
                    <> optionalHash _pFinalizationCommitteeParametersQueue
      where
        hsh :: (HashableTo H.Hash a) => a -> BS.ByteString
        hsh = H.hashToByteString . getHash
        -- For SomeParam, produce the hash. For NoParam, produce the empty string.
        optionalHash :: (HashableTo H.Hash e) => OUpdateQueue pt cpv e -> BS.ByteString
        optionalHash = foldMap hsh

pendingUpdatesV0ToJSON :: PendingUpdates 'ChainParametersV0 -> Value
pendingUpdatesV0ToJSON PendingUpdates{..} =
    object
        [ "rootKeys" AE..= _pRootKeysUpdateQueue,
          "level1Keys" AE..= _pLevel1KeysUpdateQueue,
          "level2Keys" AE..= _pLevel2KeysUpdateQueue,
          "protocol" AE..= _pProtocolQueue,
          "electionDifficulty" AE..= unOParam _pElectionDifficultyQueue,
          "euroPerEnergy" AE..= _pEuroPerEnergyQueue,
          "microGTUPerEuro" AE..= _pMicroGTUPerEuroQueue,
          "foundationAccount" AE..= _pFoundationAccountQueue,
          "mintDistribution" AE..= _pMintDistributionQueue,
          "transactionFeeDistribution" AE..= _pTransactionFeeDistributionQueue,
          "gasRewards" AE..= _pGASRewardsQueue,
          "bakerStakeThreshold" AE..= _pPoolParametersQueue,
          "addAnonymityRevoker" AE..= _pAddAnonymityRevokerQueue,
          "addIdentityProvider" AE..= _pAddIdentityProviderQueue
        ]

pendingUpdatesV1ToJSON :: PendingUpdates 'ChainParametersV1 -> Value
pendingUpdatesV1ToJSON
    PendingUpdates
        { _pCooldownParametersQueue = SomeParam cpq,
          _pTimeParametersQueue = SomeParam tpq,
          ..
        } =
        object
            [ "rootKeys" AE..= _pRootKeysUpdateQueue,
              "level1Keys" AE..= _pLevel1KeysUpdateQueue,
              "level2Keys" AE..= _pLevel2KeysUpdateQueue,
              "protocol" AE..= _pProtocolQueue,
              "electionDifficulty" AE..= unOParam _pElectionDifficultyQueue,
              "euroPerEnergy" AE..= _pEuroPerEnergyQueue,
              "microGTUPerEuro" AE..= _pMicroGTUPerEuroQueue,
              "foundationAccount" AE..= _pFoundationAccountQueue,
              "mintDistribution" AE..= _pMintDistributionQueue,
              "transactionFeeDistribution" AE..= _pTransactionFeeDistributionQueue,
              "gasRewards" AE..= _pGASRewardsQueue,
              "poolParameters" AE..= _pPoolParametersQueue,
              "addAnonymityRevoker" AE..= _pAddAnonymityRevokerQueue,
              "addIdentityProvider" AE..= _pAddIdentityProviderQueue,
              "cooldownParameters" AE..= cpq,
              "timeParameters" AE..= tpq
            ]

pendingUpdatesV2ToJSON :: PendingUpdates 'ChainParametersV2 -> Value
pendingUpdatesV2ToJSON
    PendingUpdates
        { _pCooldownParametersQueue = SomeParam cpq,
          _pTimeParametersQueue = SomeParam tpq,
          ..
        } =
        object
            [ "rootKeys" AE..= _pRootKeysUpdateQueue,
              "level1Keys" AE..= _pLevel1KeysUpdateQueue,
              "level2Keys" AE..= _pLevel2KeysUpdateQueue,
              "protocol" AE..= _pProtocolQueue,
              "euroPerEnergy" AE..= _pEuroPerEnergyQueue,
              "microGTUPerEuro" AE..= _pMicroGTUPerEuroQueue,
              "foundationAccount" AE..= _pFoundationAccountQueue,
              "mintDistribution" AE..= _pMintDistributionQueue,
              "transactionFeeDistribution" AE..= _pTransactionFeeDistributionQueue,
              "gasRewards" AE..= _pGASRewardsQueue,
              "poolParameters" AE..= _pPoolParametersQueue,
              "addAnonymityRevoker" AE..= _pAddAnonymityRevokerQueue,
              "addIdentityProvider" AE..= _pAddIdentityProviderQueue,
              "cooldownParameters" AE..= cpq,
              "timeParameters" AE..= tpq,
              "consensus2TimingParameters" AE..= unOParam _pTimeoutParametersQueue,
              "finalizationCommitteeParameters" AE..= unOParam _pFinalizationCommitteeParametersQueue
            ]
pendingUpdatesV3ToJSON :: PendingUpdates 'ChainParametersV3 -> Value
pendingUpdatesV3ToJSON
    PendingUpdates
        { _pCooldownParametersQueue = SomeParam cpq,
          _pTimeParametersQueue = SomeParam tpq,
          ..
        } =
        object
            [ "rootKeys" AE..= _pRootKeysUpdateQueue,
              "level1Keys" AE..= _pLevel1KeysUpdateQueue,
              "level2Keys" AE..= _pLevel2KeysUpdateQueue,
              "protocol" AE..= _pProtocolQueue,
              "euroPerEnergy" AE..= _pEuroPerEnergyQueue,
              "microGTUPerEuro" AE..= _pMicroGTUPerEuroQueue,
              "foundationAccount" AE..= _pFoundationAccountQueue,
              "mintDistribution" AE..= _pMintDistributionQueue,
              "transactionFeeDistribution" AE..= _pTransactionFeeDistributionQueue,
              "gasRewards" AE..= _pGASRewardsQueue,
              "poolParameters" AE..= _pPoolParametersQueue,
              "addAnonymityRevoker" AE..= _pAddAnonymityRevokerQueue,
              "addIdentityProvider" AE..= _pAddIdentityProviderQueue,
              "cooldownParameters" AE..= cpq,
              "timeParameters" AE..= tpq,
              "consensus2TimingParameters" AE..= unOParam _pTimeoutParametersQueue,
              "finalizationCommitteeParameters" AE..= unOParam _pFinalizationCommitteeParametersQueue
            ]

instance (IsChainParametersVersion cpv) => ToJSON (PendingUpdates cpv) where
    toJSON = case chainParametersVersion @cpv of
        SChainParametersV0 -> pendingUpdatesV0ToJSON
        SChainParametersV1 -> pendingUpdatesV1ToJSON
        SChainParametersV2 -> pendingUpdatesV2ToJSON
        SChainParametersV3 -> pendingUpdatesV3ToJSON

parsePendingUpdatesV0 :: Value -> AE.Parser (PendingUpdates 'ChainParametersV0)
parsePendingUpdatesV0 = withObject "PendingUpdates" $ \o -> do
    _pRootKeysUpdateQueue <- o AE..: "rootKeys"
    _pLevel1KeysUpdateQueue <- o AE..: "level1Keys"
    _pLevel2KeysUpdateQueue <- o AE..: "level2Keys"
    _pProtocolQueue <- o AE..: "protocol"
    _pElectionDifficultyQueue <- SomeParam <$> o AE..: "electionDifficulty"
    _pEuroPerEnergyQueue <- o AE..: "euroPerEnergy"
    _pMicroGTUPerEuroQueue <- o AE..: "microGTUPerEuro"
    _pFoundationAccountQueue <- o AE..: "foundationAccount"
    _pMintDistributionQueue <- o AE..: "mintDistribution"
    _pTransactionFeeDistributionQueue <- o AE..: "transactionFeeDistribution"
    _pGASRewardsQueue <- o AE..: "gasRewards"
    _pPoolParametersQueue <- o AE..: "bakerStakeThreshold"
    _pAddAnonymityRevokerQueue <- o AE..: "addAnonymityRevoker"
    _pAddIdentityProviderQueue <- o AE..: "addIdentityProvider"
    let _pCooldownParametersQueue = NoParam
    let _pTimeParametersQueue = NoParam
    let _pTimeoutParametersQueue = NoParam
    let _pMinBlockTimeQueue = NoParam
    let _pBlockEnergyLimitQueue = NoParam
    let _pFinalizationCommitteeParametersQueue = NoParam
    return PendingUpdates{..}

parsePendingUpdatesV1 :: Value -> AE.Parser (PendingUpdates 'ChainParametersV1)
parsePendingUpdatesV1 = withObject "PendingUpdates" $ \o -> do
    _pRootKeysUpdateQueue <- o AE..: "rootKeys"
    _pLevel1KeysUpdateQueue <- o AE..: "level1Keys"
    _pLevel2KeysUpdateQueue <- o AE..: "level2Keys"
    _pProtocolQueue <- o AE..: "protocol"
    _pElectionDifficultyQueue <- SomeParam <$> o AE..: "electionDifficulty"
    _pEuroPerEnergyQueue <- o AE..: "euroPerEnergy"
    _pMicroGTUPerEuroQueue <- o AE..: "microGTUPerEuro"
    _pFoundationAccountQueue <- o AE..: "foundationAccount"
    _pMintDistributionQueue <- o AE..: "mintDistribution"
    _pTransactionFeeDistributionQueue <- o AE..: "transactionFeeDistribution"
    _pGASRewardsQueue <- o AE..: "gasRewards"
    _pPoolParametersQueue <- o AE..: "poolParameters"
    _pAddAnonymityRevokerQueue <- o AE..: "addAnonymityRevoker"
    _pAddIdentityProviderQueue <- o AE..: "addIdentityProvider"
    cooldownQueue <- o AE..: "cooldownParameters"
    timeQueue <- o AE..: "timeParameters"
    let _pCooldownParametersQueue = SomeParam cooldownQueue
    let _pTimeParametersQueue = SomeParam timeQueue
    let _pTimeoutParametersQueue = NoParam
    let _pMinBlockTimeQueue = NoParam
    let _pBlockEnergyLimitQueue = NoParam
    let _pFinalizationCommitteeParametersQueue = NoParam
    return PendingUpdates{..}

parsePendingUpdatesV2 :: Value -> AE.Parser (PendingUpdates 'ChainParametersV2)
parsePendingUpdatesV2 = withObject "PendingUpdates" $ \o -> do
    _pRootKeysUpdateQueue <- o AE..: "rootKeys"
    _pLevel1KeysUpdateQueue <- o AE..: "level1Keys"
    _pLevel2KeysUpdateQueue <- o AE..: "level2Keys"
    _pProtocolQueue <- o AE..: "protocol"
    let _pElectionDifficultyQueue = NoParam
    _pEuroPerEnergyQueue <- o AE..: "euroPerEnergy"
    _pMicroGTUPerEuroQueue <- o AE..: "microGTUPerEuro"
    _pFoundationAccountQueue <- o AE..: "foundationAccount"
    _pMintDistributionQueue <- o AE..: "mintDistribution"
    _pTransactionFeeDistributionQueue <- o AE..: "transactionFeeDistribution"
    _pGASRewardsQueue <- o AE..: "gasRewards"
    _pPoolParametersQueue <- o AE..: "poolParameters"
    _pAddAnonymityRevokerQueue <- o AE..: "addAnonymityRevoker"
    _pAddIdentityProviderQueue <- o AE..: "addIdentityProvider"
    cooldownQueue <- o AE..: "cooldownParameters"
    timeQueue <- o AE..: "timeParameters"
    let _pCooldownParametersQueue = SomeParam cooldownQueue
    let _pTimeParametersQueue = SomeParam timeQueue
    _pTimeoutParametersQueue <- SomeParam <$> o AE..: "timeoutParameters"
    _pMinBlockTimeQueue <- SomeParam <$> o AE..: "minBlockTime"
    _pBlockEnergyLimitQueue <- SomeParam <$> o AE..: "blockEnergyLimit"
    _pFinalizationCommitteeParametersQueue <- SomeParam <$> o AE..: "finalizationCommitteeParameters"
    return PendingUpdates{..}

parsePendingUpdatesV3 :: Value -> AE.Parser (PendingUpdates 'ChainParametersV3)
parsePendingUpdatesV3 = withObject "PendingUpdates" $ \o -> do
    _pRootKeysUpdateQueue <- o AE..: "rootKeys"
    _pLevel1KeysUpdateQueue <- o AE..: "level1Keys"
    _pLevel2KeysUpdateQueue <- o AE..: "level2Keys"
    _pProtocolQueue <- o AE..: "protocol"
    let _pElectionDifficultyQueue = NoParam
    _pEuroPerEnergyQueue <- o AE..: "euroPerEnergy"
    _pMicroGTUPerEuroQueue <- o AE..: "microGTUPerEuro"
    _pFoundationAccountQueue <- o AE..: "foundationAccount"
    _pMintDistributionQueue <- o AE..: "mintDistribution"
    _pTransactionFeeDistributionQueue <- o AE..: "transactionFeeDistribution"
    _pGASRewardsQueue <- o AE..: "gasRewards"
    _pPoolParametersQueue <- o AE..: "poolParameters"
    _pAddAnonymityRevokerQueue <- o AE..: "addAnonymityRevoker"
    _pAddIdentityProviderQueue <- o AE..: "addIdentityProvider"
    cooldownQueue <- o AE..: "cooldownParameters"
    timeQueue <- o AE..: "timeParameters"
    let _pCooldownParametersQueue = SomeParam cooldownQueue
    let _pTimeParametersQueue = SomeParam timeQueue
    _pTimeoutParametersQueue <- SomeParam <$> o AE..: "timeoutParameters"
    _pMinBlockTimeQueue <- SomeParam <$> o AE..: "minBlockTime"
    _pBlockEnergyLimitQueue <- SomeParam <$> o AE..: "blockEnergyLimit"
    _pFinalizationCommitteeParametersQueue <- SomeParam <$> o AE..: "finalizationCommitteeParameters"
    return PendingUpdates{..}

instance (IsChainParametersVersion cpv) => FromJSON (PendingUpdates cpv) where
    parseJSON = case chainParametersVersion @cpv of
        SChainParametersV0 -> parsePendingUpdatesV0
        SChainParametersV1 -> parsePendingUpdatesV1
        SChainParametersV2 -> parsePendingUpdatesV2
        SChainParametersV3 -> parsePendingUpdatesV3

-- | Initial pending updates with empty queues.
emptyPendingUpdates :: forall cpv. (IsChainParametersVersion cpv) => PendingUpdates cpv
emptyPendingUpdates =
    PendingUpdates
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        (whenSupported emptyUpdateQueue)
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        (whenSupported emptyUpdateQueue)
        (whenSupported emptyUpdateQueue)
        (whenSupported emptyUpdateQueue)
        (whenSupported emptyUpdateQueue)
        (whenSupported emptyUpdateQueue)
        (whenSupported emptyUpdateQueue)

-- | Current state of updatable parameters and update queues.
data Updates' (cpv :: ChainParametersVersion) = Updates
    { -- | Current update authorizations.
      _currentKeyCollection :: !(Hashed (UpdateKeysCollection (AuthorizationsVersionFor cpv))),
      -- | Current protocol update.
      _currentProtocolUpdate :: !(Maybe ProtocolUpdate),
      -- | Current chain parameters.
      _currentParameters :: !(ChainParameters' cpv),
      -- | Pending updates.
      _pendingUpdates :: !(PendingUpdates cpv)
    }
    deriving (Show, Eq)

makeLenses ''Updates'

type Updates (pv :: ProtocolVersion) = Updates' (ChainParametersVersionFor pv)

instance (IsChainParametersVersion cpv) => HashableTo H.Hash (Updates' cpv) where
    getHash Updates{..} =
        H.hash $
            hsh _currentKeyCollection
                <> case _currentProtocolUpdate of
                    Nothing -> "\x00"
                    Just cpu -> "\x01" <> hsh cpu
                <> hsh _currentParameters
                <> hsh _pendingUpdates
      where
        hsh :: (HashableTo H.Hash a) => a -> BS.ByteString
        hsh = H.hashToByteString . getHash

instance forall cpv. (IsChainParametersVersion cpv) => ToJSON (Updates' cpv) where
    toJSON Updates{..} =
        withIsAuthorizationsVersionFor (chainParametersVersion @cpv) $
            object $
                [ "keys" AE..= _unhashed _currentKeyCollection,
                  "chainParameters" AE..= _currentParameters,
                  "updateQueues" AE..= _pendingUpdates
                ]
                    <> toList (("protocolUpdate" AE..=) <$> _currentProtocolUpdate)

instance forall cpv. (IsChainParametersVersion cpv) => FromJSON (Updates' cpv) where
    parseJSON = withObject "Updates" $ \o -> do
        _currentKeyCollection <-
            withIsAuthorizationsVersionFor (chainParametersVersion @cpv) $
                makeHashed <$> o AE..: "keys"
        _currentProtocolUpdate <- o AE..:? "protocolUpdate"
        _currentParameters <- o AE..: "chainParameters"
        _pendingUpdates <- o AE..: "updateQueues"
        return Updates{..}

-- | An initial 'Updates' with the given initial 'Authorizations'
--  and 'ChainParameters'.
initialUpdates ::
    (IsChainParametersVersion cpv) =>
    UpdateKeysCollection (AuthorizationsVersionFor cpv) ->
    ChainParameters' cpv ->
    Updates' cpv
initialUpdates initialKeyCollection _currentParameters =
    Updates
        { _currentKeyCollection = makeHashed initialKeyCollection,
          _currentProtocolUpdate = Nothing,
          _pendingUpdates = emptyPendingUpdates,
          ..
        }

-- | The status of protocol updates on a chain.  Either an update has occurred, or zero or more
--  updates are pending.
data ProtocolUpdateStatus
    = -- | The specified protocol update has occurred.
      ProtocolUpdated !ProtocolUpdate
    | -- | No protocol update has occurred, but there may be pending updates.
      --  The list may be empty, and is ordered by the effective timestamp of the update.
      PendingProtocolUpdates ![(TransactionTime, ProtocolUpdate)]
    deriving (Eq, Show)
