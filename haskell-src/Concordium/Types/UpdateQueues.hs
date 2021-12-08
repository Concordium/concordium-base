{-# LANGUAGE TemplateHaskell, BangPatterns, DeriveFunctor, OverloadedStrings, ScopedTypeVariables, TypeApplications, KindSignatures, DataKinds, TypeFamilies, GADTs, StandaloneDeriving #-}
-- |Implementation of the chain update mechanism: https://concordium.gitlab.io/whitepapers/update-mechanism/main.pdf
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
import Concordium.Types.Updates
import Concordium.Utils.Serialization
import Concordium.Types.Parameters

-- |An update queue consists of pending future updates ordered by
-- the time at which they will take effect.
data UpdateQueue e = UpdateQueue {
    -- |The next available sequence number for an update.
    _uqNextSequenceNumber :: !UpdateSequenceNumber,
    -- |Pending updates, in ascending order of effective time.
    _uqQueue :: ![(TransactionTime, e)]
} deriving (Show, Functor, Eq)
makeLenses ''UpdateQueue

data UpdateQueueForCPV1 (cpv :: ChainParametersVersion) e where
  UpdateQueueForCPV1None :: UpdateQueueForCPV1 'ChainParametersV0 e
  UpdateQueueForCPV1Some :: !(UpdateQueue e) -> UpdateQueueForCPV1 'ChainParametersV1 e

updateQueueForCPV1 :: forall cpv e. IsChainParametersVersion cpv => UpdateQueue e -> UpdateQueueForCPV1 cpv e
updateQueueForCPV1 uq = case chainParametersVersion @cpv of
    SCPV0 -> UpdateQueueForCPV1None
    SCPV1 -> UpdateQueueForCPV1Some uq

noneOrEmptyQueueForCPV1 :: forall cpv e. IsChainParametersVersion cpv => UpdateQueueForCPV1 cpv e
noneOrEmptyQueueForCPV1 = updateQueueForCPV1 emptyUpdateQueue

someUpdateQueueForCPV1 :: UpdateQueueForCPV1 'ChainParametersV1 a -> UpdateQueue a
someUpdateQueueForCPV1 (UpdateQueueForCPV1Some uq) = uq

deriving instance Eq e => Eq (UpdateQueueForCPV1 cpv e)
deriving instance Show e => Show (UpdateQueueForCPV1 cpv e)

putUpdateQueueForCPV1 :: (Serialize e) => Putter (UpdateQueueForCPV1 cpv e)
putUpdateQueueForCPV1 UpdateQueueForCPV1None = return ()
putUpdateQueueForCPV1 (UpdateQueueForCPV1Some uq) = putUpdateQueueV0 uq

getUpdateQueueForCPV1 :: forall cpv e. (Serialize e, IsChainParametersVersion cpv) => Get (UpdateQueueForCPV1 cpv e)
getUpdateQueueForCPV1 = case chainParametersVersion @cpv of
  SCPV0 -> return UpdateQueueForCPV1None
  SCPV1 -> UpdateQueueForCPV1Some <$> getUpdateQueueV0

instance HashableTo H.Hash e => HashableTo H.Hash (UpdateQueue e) where
    getHash UpdateQueue{..} = H.hash $ runPut $ do
        put _uqNextSequenceNumber
        putLength $ length _uqQueue
        mapM_ (\(t, e) -> put t >> put (getHash e :: H.Hash)) _uqQueue

-- |Serialize an update queue in V0 format.
putUpdateQueueV0 :: (Serialize e) => Putter (UpdateQueue e)
putUpdateQueueV0 UpdateQueue{..} = do
        put _uqNextSequenceNumber
        forM_ _uqQueue $ \(tt, v) -> do
            putWord8 1
            put tt
            put v
        putWord8 0

-- |Deserialize an update queue in V0 format.
getUpdateQueueV0 :: (Serialize e) => Get (UpdateQueue e)
getUpdateQueueV0 = do
        _uqNextSequenceNumber <- get
        let loop lastTT = getWord8 >>= \case
                0 -> return []
                1 -> do
                    tt <- get
                    unless (lastTT < Just tt) $ fail "Update queue not in ascending order"
                    v <- get
                    ((tt, v) :) <$> loop (Just tt)
                _ -> fail "Invalid update queue"
        _uqQueue <- loop Nothing
        return UpdateQueue{..}

instance ToJSON e => ToJSON (UpdateQueue e) where
    toJSON UpdateQueue{..} = object [
            "nextSequenceNumber" AE..= _uqNextSequenceNumber,
            "queue" AE..= [object ["effectiveTime" AE..= et, "update" AE..= u] | (et, u) <- _uqQueue]
        ]

instance FromJSON e => FromJSON (UpdateQueue e) where
    parseJSON = withObject "Update queue" $ \o -> do
        _uqNextSequenceNumber <- o AE..: "nextSequenceNumber"
        queue <- o AE..: "queue"
        _uqQueue <- withArray "queue" (\vec -> forM (toList vec) $ withObject "Queue entry" $ \e -> do
                tt <- e AE..: "effectiveTime"
                upd <- e AE..: "update"
                return (tt, upd)
            ) queue
        return UpdateQueue{..}

-- |Update queue with no pending updates, and with the minimal next
-- sequence number.
emptyUpdateQueue :: UpdateQueue e
emptyUpdateQueue = UpdateQueue {
        _uqNextSequenceNumber = minUpdateSequenceNumber,
        _uqQueue = []
    }

-- |Add an update event to an update queue, incrementing the sequence number.
-- Any updates in the queue with later or equal effective times are removed
-- from the queue.
enqueue :: TransactionTime -> e -> UpdateQueue e -> UpdateQueue e
enqueue !t !e = (uqNextSequenceNumber +~ 1)
            . (uqQueue %~ \q -> let !r = takeWhile ((< t) . fst) q in r ++ [(t, e)])

-- |Update queues for all on-chain update types.
data PendingUpdates cpv = PendingUpdates {
    -- |Updates to the root keys.
    _pRootKeysUpdateQueue :: !(UpdateQueue (HigherLevelKeys RootKeysKind)),
    -- |Updates to the level 1 keys.
    _pLevel1KeysUpdateQueue :: !(UpdateQueue (HigherLevelKeys Level1KeysKind)),
    -- |Updates to the level 2 keys.
    _pLevel2KeysUpdateQueue :: !(UpdateQueue (Authorizations cpv)),
    -- |Protocol updates.
    _pProtocolQueue :: !(UpdateQueue ProtocolUpdate),
    -- |Updates to the election difficulty parameter.
    _pElectionDifficultyQueue :: !(UpdateQueue ElectionDifficulty),
    -- |Updates to the euro:energy exchange rate.
    _pEuroPerEnergyQueue :: !(UpdateQueue ExchangeRate),
    -- |Updates to the GTU:euro exchange rate.
    _pMicroGTUPerEuroQueue :: !(UpdateQueue ExchangeRate),
    -- |Updates to the foundation account.
    _pFoundationAccountQueue :: !(UpdateQueue AccountIndex),
    -- |Updates to the mint distribution.
    _pMintDistributionQueue :: !(UpdateQueue MintDistribution),
    -- |Updates to the transaction fee distribution.
    _pTransactionFeeDistributionQueue :: !(UpdateQueue TransactionFeeDistribution),
    -- |Updates to the GAS rewards.
    _pGASRewardsQueue :: !(UpdateQueue GASRewards),
    -- |Updates pool parameters.
    _pPoolParametersQueue :: !(UpdateQueue (PoolParameters cpv)),
    -- |Adds a new anonymity revoker.
    _pAddAnonymityRevokerQueue :: !(UpdateQueue ARS.ArInfo),
    -- |Adds a new identity provider.
    _pAddIdentityProviderQueue :: !(UpdateQueue IPS.IpInfo),
    -- |Updates to cooldown parameters for chain parameters version 1.
    _pCooldownParametersQueue :: !(UpdateQueueForCPV1 cpv (CooldownParameters 'ChainParametersV1)),
    -- |Updates to time parameters for chain parameters version 1.
    _pTimeParametersQueue :: !(UpdateQueueForCPV1 cpv (TimeParameters 'ChainParametersV1))
} deriving (Show, Eq)
makeLenses ''PendingUpdates

instance HashableTo H.Hash (PendingUpdates cpv) where
    getHash PendingUpdates{..} = H.hash $
            hsh _pRootKeysUpdateQueue
            <> hsh _pLevel1KeysUpdateQueue
            <> hsh _pLevel2KeysUpdateQueue
            <> hsh _pProtocolQueue
            <> hsh _pElectionDifficultyQueue
            <> hsh _pEuroPerEnergyQueue
            <> hsh _pMicroGTUPerEuroQueue
            <> hsh _pFoundationAccountQueue
            <> hsh _pMintDistributionQueue
            <> hsh _pTransactionFeeDistributionQueue
            <> hsh _pGASRewardsQueue
            <> hsh _pPoolParametersQueue
            <> hsh _pAddAnonymityRevokerQueue
            <> hsh _pAddIdentityProviderQueue
            <> hshMaybe _pCooldownParametersQueue
            <> hshMaybe _pTimeParametersQueue
        where
            hsh :: HashableTo H.Hash a => a -> BS.ByteString
            hsh = H.hashToByteString . getHash
            hshMaybe :: HashableTo H.Hash e => UpdateQueueForCPV1 cpv e -> BS.ByteString
            hshMaybe UpdateQueueForCPV1None = BS.empty
            hshMaybe (UpdateQueueForCPV1Some uq) = hsh uq


-- |Serialize the pending updates.
putPendingUpdatesV0 :: IsChainParametersVersion cpv => Putter (PendingUpdates cpv)
putPendingUpdatesV0 PendingUpdates{..} = do
        putUpdateQueueV0 _pRootKeysUpdateQueue
        putUpdateQueueV0 _pLevel1KeysUpdateQueue
        putUpdateQueueV0 _pLevel2KeysUpdateQueue
        putUpdateQueueV0 _pProtocolQueue
        putUpdateQueueV0 _pElectionDifficultyQueue
        putUpdateQueueV0 _pEuroPerEnergyQueue
        putUpdateQueueV0 _pMicroGTUPerEuroQueue
        putUpdateQueueV0 _pFoundationAccountQueue
        putUpdateQueueV0 _pMintDistributionQueue
        putUpdateQueueV0 _pTransactionFeeDistributionQueue
        putUpdateQueueV0 _pGASRewardsQueue
        putUpdateQueueV0 _pPoolParametersQueue
        putUpdateQueueV0 _pAddAnonymityRevokerQueue
        putUpdateQueueV0 _pAddIdentityProviderQueue
        putUpdateQueueForCPV1 _pCooldownParametersQueue
        putUpdateQueueForCPV1 _pTimeParametersQueue

-- |Deserialize pending updates.
getPendingUpdatesV0 :: IsChainParametersVersion cpv => Get (PendingUpdates cpv)
getPendingUpdatesV0 = do
        _pRootKeysUpdateQueue <- getUpdateQueueV0
        _pLevel1KeysUpdateQueue <- getUpdateQueueV0
        _pLevel2KeysUpdateQueue <- getUpdateQueueV0
        _pProtocolQueue <- getUpdateQueueV0
        _pElectionDifficultyQueue <- getUpdateQueueV0
        _pEuroPerEnergyQueue <- getUpdateQueueV0
        _pMicroGTUPerEuroQueue <- getUpdateQueueV0
        _pFoundationAccountQueue <- getUpdateQueueV0
        _pMintDistributionQueue <- getUpdateQueueV0
        _pTransactionFeeDistributionQueue <- getUpdateQueueV0
        _pGASRewardsQueue <- getUpdateQueueV0
        _pPoolParametersQueue <- getUpdateQueueV0
        _pAddAnonymityRevokerQueue <- getUpdateQueueV0
        _pAddIdentityProviderQueue <- getUpdateQueueV0
        _pCooldownParametersQueue <- getUpdateQueueForCPV1
        _pTimeParametersQueue <- getUpdateQueueForCPV1
        return PendingUpdates{..}

pendingUpdatesV0ToJSON :: PendingUpdates 'ChainParametersV0 -> Value
pendingUpdatesV0ToJSON PendingUpdates{..} = object [
        "rootKeys" AE..= _pRootKeysUpdateQueue,
        "level1Keys" AE..= _pLevel1KeysUpdateQueue,
        "level2Keys" AE..= _pLevel2KeysUpdateQueue,
        "protocol" AE..= _pProtocolQueue,
        "electionDifficulty" AE..= _pElectionDifficultyQueue,
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
pendingUpdatesV1ToJSON PendingUpdates{_pCooldownParametersQueue = UpdateQueueForCPV1Some cpq,
    _pTimeParametersQueue = UpdateQueueForCPV1Some tpq, ..} = object [
        "rootKeys" AE..= _pRootKeysUpdateQueue,
        "level1Keys" AE..= _pLevel1KeysUpdateQueue,
        "level2Keys" AE..= _pLevel2KeysUpdateQueue,
        "protocol" AE..= _pProtocolQueue,
        "electionDifficulty" AE..= _pElectionDifficultyQueue,
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

instance IsChainParametersVersion cpv => ToJSON (PendingUpdates cpv) where
    toJSON = case chainParametersVersion @cpv of
        SCPV0 -> pendingUpdatesV0ToJSON
        SCPV1 -> pendingUpdatesV1ToJSON

parsePendingUpdatesV0 ::Value -> AE.Parser (PendingUpdates 'ChainParametersV0)
parsePendingUpdatesV0 = withObject "PendingUpdates" $ \o -> do
        _pRootKeysUpdateQueue <- o AE..: "rootKeys"
        _pLevel1KeysUpdateQueue <- o AE..: "level1Keys"
        _pLevel2KeysUpdateQueue <- o AE..: "level2Keys"
        _pProtocolQueue <- o AE..: "protocol"
        _pElectionDifficultyQueue <- o AE..: "electionDifficulty"
        _pEuroPerEnergyQueue <- o AE..: "euroPerEnergy"
        _pMicroGTUPerEuroQueue <- o AE..: "microGTUPerEuro"
        _pFoundationAccountQueue <- o AE..: "foundationAccount"
        _pMintDistributionQueue <- o AE..: "mintDistribution"
        _pTransactionFeeDistributionQueue <- o AE..: "transactionFeeDistribution"
        _pGASRewardsQueue <- o AE..: "gasRewards"
        _pPoolParametersQueue <- o AE..: "bakerStakeThreshold"
        _pAddAnonymityRevokerQueue <- o AE..: "addAnonymityRevoker"
        _pAddIdentityProviderQueue <- o AE..: "addIdentityProvider"
        let _pCooldownParametersQueue = UpdateQueueForCPV1None
        let _pTimeParametersQueue = UpdateQueueForCPV1None
        return PendingUpdates{..}

parsePendingUpdatesV1 :: Value -> AE.Parser (PendingUpdates 'ChainParametersV1)
parsePendingUpdatesV1 = withObject "PendingUpdates" $ \o -> do
        _pRootKeysUpdateQueue <- o AE..: "rootKeys"
        _pLevel1KeysUpdateQueue <- o AE..: "level1Keys"
        _pLevel2KeysUpdateQueue <- o AE..: "level2Keys"
        _pProtocolQueue <- o AE..: "protocol"
        _pElectionDifficultyQueue <- o AE..: "electionDifficulty"
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
        let _pCooldownParametersQueue = UpdateQueueForCPV1Some cooldownQueue
        let _pTimeParametersQueue = UpdateQueueForCPV1Some timeQueue
        return PendingUpdates{..}

instance IsChainParametersVersion cpv => FromJSON (PendingUpdates cpv) where
    parseJSON = case chainParametersVersion @cpv of
        SCPV0 -> parsePendingUpdatesV0
        SCPV1 -> parsePendingUpdatesV1

-- |Initial pending updates with empty queues.
emptyPendingUpdates :: forall cpv. IsChainParametersVersion cpv => PendingUpdates cpv
emptyPendingUpdates = PendingUpdates
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue 
        emptyUpdateQueue 
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        noneOrEmptyQueueForCPV1
        noneOrEmptyQueueForCPV1

-- |Current state of updatable parameters and update queues.
data Updates' (cpv :: ChainParametersVersion) = Updates {
    -- |Current update authorizations.
    _currentKeyCollection :: !(Hashed (UpdateKeysCollection cpv)),
    -- |Current protocol update.
    _currentProtocolUpdate :: !(Maybe ProtocolUpdate),
    -- |Current chain parameters.
    _currentParameters :: !(ChainParameters' cpv),
    -- |Pending updates.
    _pendingUpdates :: !(PendingUpdates cpv)
} deriving (Show, Eq)
makeClassy ''Updates'

type Updates (pv :: ProtocolVersion) = Updates' (ChainParametersVersionFor pv)

instance HashableTo H.Hash (Updates' cpv) where
    getHash Updates{..} = H.hash $
            hsh _currentKeyCollection
            <> case _currentProtocolUpdate of
                    Nothing -> "\x00"
                    Just cpu -> "\x01" <> hsh cpu
            <> hsh _currentParameters
            <> hsh _pendingUpdates
        where
            hsh :: HashableTo H.Hash a => a -> BS.ByteString
            hsh = H.hashToByteString . getHash

-- |Serialize 'Updates' in V0 format.
putUpdatesV0 :: IsChainParametersVersion cpv => Putter (Updates' cpv)
putUpdatesV0 Updates{..} = do
        put (_currentKeyCollection ^. unhashed)
        case _currentProtocolUpdate of
            Nothing -> putWord8 0
            Just cpu -> putWord8 1 >> put cpu
        putChainParameters _currentParameters
        putPendingUpdatesV0 _pendingUpdates

-- |Deserialize 'Updates' in V0 format.
getUpdatesV0 :: IsChainParametersVersion cpv => Get (Updates' cpv)
getUpdatesV0 = do
        _currentKeyCollection <- makeHashed <$> get
        _currentProtocolUpdate <- getWord8 >>= \case
            0 -> return Nothing
            1 -> Just <$> get
            _ -> fail "Invalid Updates"
        _currentParameters <- getChainParameters
        _pendingUpdates <- getPendingUpdatesV0
        return Updates{..}

instance forall cpv. IsChainParametersVersion cpv => ToJSON (Updates' cpv) where
    toJSON Updates{..} = object $ [
            "keys" AE..= _unhashed _currentKeyCollection,
            chainParametersJSON,
            "updateQueues" AE..= _pendingUpdates
        ] <> toList (("protocolUpdate" AE..=) <$> _currentProtocolUpdate)
      where
        chainParametersJSON = case chainParametersVersion @cpv of
            SCPV0 -> "chainParameters" AE..= _currentParameters
            SCPV1 -> "chainParameters" AE..= _currentParameters

instance forall cpv. IsChainParametersVersion cpv => FromJSON (Updates' cpv) where
    parseJSON = withObject "Updates" $ \o -> do
        _currentKeyCollection <- makeHashed <$> o AE..: "keys"
        _currentProtocolUpdate <- o AE..:? "protocolUpdate"
        _currentParameters <- case chainParametersVersion @cpv of
          SCPV0 -> o AE..: "chainParameters"
          SCPV1 -> o AE..: "chainParameters"
        _pendingUpdates <- o AE..: "updateQueues"
        return Updates{..}

-- |An initial 'Updates' with the given initial 'Authorizations'
-- and 'ChainParameters'.
initialUpdates
    :: IsChainParametersVersion cpv
    => UpdateKeysCollection cpv
    -> ChainParameters' cpv
    -> Updates' cpv
initialUpdates initialKeyCollection _currentParameters = Updates {
        _currentKeyCollection = makeHashed initialKeyCollection,
        _currentProtocolUpdate = Nothing,
        _pendingUpdates = emptyPendingUpdates,
        ..
    }

-- |The status of protocol updates on a chain.  Either an update has occurred, or zero or more
-- updates are pending.
data ProtocolUpdateStatus
    = -- |The specified protocol update has occurred.
      ProtocolUpdated !ProtocolUpdate
    | -- |No protocol update has occurred, but there may be pending updates.
      -- The list may be empty, and is ordered by the effective timestamp of the update.
      PendingProtocolUpdates ![(TransactionTime, ProtocolUpdate)]
    deriving (Eq, Show)
