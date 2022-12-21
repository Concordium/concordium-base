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
import Concordium.Genesis.Data
import Concordium.Types
import qualified Concordium.Types.AnonymityRevokers as ARS
import Concordium.Types.HashableTo
import qualified Concordium.Types.IdentityProviders as IPS
import Concordium.Types.Migration
import Concordium.Types.Parameters
import Concordium.Types.Updates
import Concordium.Utils.Serialization

-- |An update queue consists of pending future updates ordered by
-- the time at which they will take effect.
data UpdateQueue e = UpdateQueue
    { -- |The next available sequence number for an update.
      _uqNextSequenceNumber :: !UpdateSequenceNumber,
      -- |Pending updates, in ascending order of effective time.
      _uqQueue :: ![(TransactionTime, e)]
    }
    deriving (Show, Functor, Eq)

makeLenses ''UpdateQueue

type OUpdateQueue (pt :: ParameterType) (cpv :: ChainParametersVersion) e = OParam pt cpv (UpdateQueue e)

instance HashableTo H.Hash e => HashableTo H.Hash (UpdateQueue e) where
    getHash UpdateQueue{..} = H.hash $ runPut $ do
        put _uqNextSequenceNumber
        putLength $ length _uqQueue
        mapM_ (\(t, e) -> put t >> put (getHash e :: H.Hash)) _uqQueue

-- |Serialize an update queue in V0 format.
putUpdateQueueV0 :: (Serialize e) => Putter (UpdateQueue e)
putUpdateQueueV0 = putUpdateQueueV0With put

-- |Serialize an update queue in V0 format.
putUpdateQueueV0With :: Putter e -> Putter (UpdateQueue e)
putUpdateQueueV0With putElem UpdateQueue{..} = do
    put _uqNextSequenceNumber
    forM_ _uqQueue $ \(tt, v) -> do
        putWord8 1
        put tt
        putElem v
    putWord8 0

-- |Deserialize an update queue in V0 format.
-- The parameter defines how entries in the queue are deserialized.
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

-- |Deserialize an update queue in V0 format.
getUpdateQueueV0 :: Serialize e => Get (UpdateQueue e)
getUpdateQueueV0 = getUpdateQueueV0With get

instance ToJSON e => ToJSON (UpdateQueue e) where
    toJSON UpdateQueue{..} =
        object
            [ "nextSequenceNumber" AE..= _uqNextSequenceNumber,
              "queue" AE..= [object ["effectiveTime" AE..= et, "update" AE..= u] | (et, u) <- _uqQueue]
            ]

instance FromJSON e => FromJSON (UpdateQueue e) where
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

-- |Update queue with no pending updates, and with the minimal next
-- sequence number.
emptyUpdateQueue :: UpdateQueue e
emptyUpdateQueue =
    UpdateQueue
        { _uqNextSequenceNumber = minUpdateSequenceNumber,
          _uqQueue = []
        }

-- |Add an update event to an update queue, incrementing the sequence number.
-- Any updates in the queue with later or equal effective times are removed
-- from the queue.
enqueue :: TransactionTime -> e -> UpdateQueue e -> UpdateQueue e
enqueue !t !e =
    (uqNextSequenceNumber +~ 1)
        . (uqQueue %~ \q -> let !r = takeWhile ((< t) . fst) q in r ++ [(t, e)])

-- |Update queues for all on-chain update types.
data PendingUpdates cpv = PendingUpdates
    { -- |Updates to the root keys.
      _pRootKeysUpdateQueue :: !(UpdateQueue (HigherLevelKeys RootKeysKind)),
      -- |Updates to the level 1 keys.
      _pLevel1KeysUpdateQueue :: !(UpdateQueue (HigherLevelKeys Level1KeysKind)),
      -- |Updates to the level 2 keys.
      _pLevel2KeysUpdateQueue :: !(UpdateQueue (Authorizations cpv)),
      -- |Protocol updates.
      _pProtocolQueue :: !(UpdateQueue ProtocolUpdate),
      -- |Updates to the election difficulty parameter (CPV0 and CPV1 only).
      _pElectionDifficultyQueue :: !(OUpdateQueue 'PTElectionDifficulty cpv ElectionDifficulty),
      -- |Updates to the euro:energy exchange rate.
      _pEuroPerEnergyQueue :: !(UpdateQueue ExchangeRate),
      -- |Updates to the GTU:euro exchange rate.
      _pMicroGTUPerEuroQueue :: !(UpdateQueue ExchangeRate),
      -- |Updates to the foundation account.
      _pFoundationAccountQueue :: !(UpdateQueue AccountIndex),
      -- |Updates to the mint distribution.
      _pMintDistributionQueue :: !(UpdateQueue (MintDistribution cpv)),
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
      -- |Updates to cooldown parameters (CPV1 onwards).
      _pCooldownParametersQueue :: !(OUpdateQueue 'PTCooldownParametersAccessStructure cpv (CooldownParameters cpv)),
      -- |Updates to time parameters (CPV1 onwards).
      _pTimeParametersQueue :: !(OUpdateQueue 'PTTimeParameters cpv (TimeParameters cpv)),
      -- |Updates to the consensus version 2 timeout parameters (CPV2 onwards).
      _pTimeoutParametersQueue :: !(OUpdateQueue 'PTTimeoutParameters cpv TimeoutParameters),
      -- |Minimum block time for consensus version 2 (CPV2 onwards).
      _pMinBlockTimeQueue :: !(OUpdateQueue 'PTMinBlockTime cpv Duration),
      -- |Block energy limit (CPV2 onwards).
      _pBlockEnergyLimitQueue :: !(OUpdateQueue 'PTBlockEnergyLimit cpv Energy)
    }
    deriving (Show, Eq)

makeLenses ''PendingUpdates

instance IsChainParametersVersion cpv => HashableTo H.Hash (PendingUpdates cpv) where
    getHash PendingUpdates{..} =
        H.hash $
            hsh _pRootKeysUpdateQueue
                <> hsh _pLevel1KeysUpdateQueue
                <> hsh _pLevel2KeysUpdateQueue
                <> hsh _pProtocolQueue
                <> ohsh _pElectionDifficultyQueue
                <> hsh _pEuroPerEnergyQueue
                <> hsh _pMicroGTUPerEuroQueue
                <> hsh _pFoundationAccountQueue
                <> hsh _pMintDistributionQueue
                <> hsh _pTransactionFeeDistributionQueue
                <> hsh _pGASRewardsQueue
                <> hsh _pPoolParametersQueue
                <> hsh _pAddAnonymityRevokerQueue
                <> hsh _pAddIdentityProviderQueue
                <> ohsh _pCooldownParametersQueue
                <> ohsh _pTimeParametersQueue
                <> ohsh _pTimeoutParametersQueue
      where
        hsh :: HashableTo H.Hash a => a -> BS.ByteString
        hsh = H.hashToByteString . getHash
        -- For CPV1, produce the hash. For CPV0, produce the empty string.
        ohsh :: HashableTo H.Hash e => OUpdateQueue pt cpv e -> BS.ByteString
        ohsh = foldMap hsh

-- ohsh NoParam = BS.empty
-- ohsh (SomeParam uq) = hsh uq

-- |Serialize the pending updates.
putPendingUpdatesV0 :: IsChainParametersVersion cpv => Putter (PendingUpdates cpv)
putPendingUpdatesV0 PendingUpdates{..} = do
    putUpdateQueueV0 _pRootKeysUpdateQueue
    putUpdateQueueV0 _pLevel1KeysUpdateQueue
    putUpdateQueueV0With putAuthorizations _pLevel2KeysUpdateQueue
    putUpdateQueueV0 _pProtocolQueue
    mapM_ putUpdateQueueV0 _pElectionDifficultyQueue
    putUpdateQueueV0 _pEuroPerEnergyQueue
    putUpdateQueueV0 _pMicroGTUPerEuroQueue
    putUpdateQueueV0 _pFoundationAccountQueue
    putUpdateQueueV0 _pMintDistributionQueue
    putUpdateQueueV0 _pTransactionFeeDistributionQueue
    putUpdateQueueV0 _pGASRewardsQueue
    putUpdateQueueV0 _pPoolParametersQueue
    putUpdateQueueV0 _pAddAnonymityRevokerQueue
    putUpdateQueueV0 _pAddIdentityProviderQueue
    mapM_ putUpdateQueueV0 _pCooldownParametersQueue
    mapM_ putUpdateQueueV0 _pTimeParametersQueue
    mapM_ putUpdateQueueV0 _pTimeoutParametersQueue

-- |Deserialize pending updates. The 'StateMigrationParameters' allow an old format to be
-- deserialized as a new format by applying the migration.
getPendingUpdates :: forall oldpv pv. (IsProtocolVersion oldpv) => StateMigrationParameters oldpv pv -> Get (PendingUpdates (ChainParametersVersionFor pv))
getPendingUpdates migration = do
    _pRootKeysUpdateQueue <- getUpdateQueueV0 @(HigherLevelKeys RootKeysKind)
    _pLevel1KeysUpdateQueue <- getUpdateQueueV0 @(HigherLevelKeys Level1KeysKind)
    -- Any pending updates to the authorizations are migrated.
    _pLevel2KeysUpdateQueue <- getUpdateQueueV0With (migrateAuthorizations migration <$> getAuthorizations)
    _pProtocolQueue <- getUpdateQueueV0 @ProtocolUpdate
    oldElectionDifficultyQueue <- whenSupported @'PTElectionDifficulty @(ChainParametersVersionFor oldpv) $ getUpdateQueueV0 @ElectionDifficulty
    _pEuroPerEnergyQueue <- getUpdateQueueV0 @ExchangeRate
    _pMicroGTUPerEuroQueue <- getUpdateQueueV0 @ExchangeRate
    _pFoundationAccountQueue <- getUpdateQueueV0 @AccountIndex
    _pMintDistributionQueue <- getUpdateQueueV0With (migrateMintDistribution migration <$> get)
    _pTransactionFeeDistributionQueue <- getUpdateQueueV0 @TransactionFeeDistribution
    _pGASRewardsQueue <- getUpdateQueueV0 @GASRewards
    _pPoolParametersQueue <- getUpdateQueueV0With (migratePoolParameters migration <$> get)
    _pAddAnonymityRevokerQueue <- getUpdateQueueV0 @ARS.ArInfo
    _pAddIdentityProviderQueue <- getUpdateQueueV0 @IPS.IpInfo
    oldCooldownParametersQueue <-
        whenSupported @'PTCooldownParametersAccessStructure @(ChainParametersVersionFor oldpv) $
            getUpdateQueueV0 @(CooldownParameters (ChainParametersVersionFor oldpv))
    oldTimeParametersQueue <-
        whenSupported @'PTTimeParameters @(ChainParametersVersionFor oldpv) $
            getUpdateQueueV0 @(TimeParameters (ChainParametersVersionFor oldpv))
    oldTimeoutParametersQueue <-
        whenSupported @'PTTimeoutParameters @(ChainParametersVersionFor oldpv) $
            getUpdateQueueV0 @TimeoutParameters
    oldMinBlockTimeQueue <-
        whenSupported @'PTMinBlockTime @(ChainParametersVersionFor oldpv) $
            getUpdateQueueV0 @Duration
    oldBlockEnergyLimitQueue <-
        whenSupported @'PTBlockEnergyLimit @(ChainParametersVersionFor oldpv) $
            getUpdateQueueV0 @Energy
    -- Cooldown and time parameters are only part of CPV1 and onwards.
    case migration of
        StateMigrationParametersTrivial -> do
            let _pElectionDifficultyQueue = oldElectionDifficultyQueue
            let _pCooldownParametersQueue = oldCooldownParametersQueue
            let _pTimeParametersQueue = oldTimeParametersQueue
            let _pTimeoutParametersQueue = oldTimeoutParametersQueue
            let _pMinBlockTimeQueue = oldMinBlockTimeQueue
            let _pBlockEnergyLimitQueue = oldBlockEnergyLimitQueue
            return PendingUpdates{..}
        StateMigrationParametersP1P2 -> do
            let _pElectionDifficultyQueue = SomeParam (unOParam oldElectionDifficultyQueue)
            _pCooldownParametersQueue <- whenSupported getUpdateQueueV0
            _pTimeParametersQueue <- whenSupported getUpdateQueueV0
            let _pTimeoutParametersQueue = NoParam
            let _pMinBlockTimeQueue = oldMinBlockTimeQueue
            let _pBlockEnergyLimitQueue = oldBlockEnergyLimitQueue
            return PendingUpdates{..}
        StateMigrationParametersP2P3 -> do
            let _pElectionDifficultyQueue = SomeParam (unOParam oldElectionDifficultyQueue)
            _pCooldownParametersQueue <- whenSupported getUpdateQueueV0
            _pTimeParametersQueue <- whenSupported getUpdateQueueV0
            let _pTimeoutParametersQueue = NoParam
            let _pMinBlockTimeQueue = oldMinBlockTimeQueue
            let _pBlockEnergyLimitQueue = oldBlockEnergyLimitQueue
            return PendingUpdates{..}
        StateMigrationParametersP3ToP4 _ -> do
            let _pElectionDifficultyQueue = SomeParam (unOParam oldElectionDifficultyQueue)
            let _pCooldownParametersQueue = SomeParam emptyUpdateQueue
            let _pTimeParametersQueue = SomeParam emptyUpdateQueue
            let _pTimeoutParametersQueue = NoParam
            let _pMinBlockTimeQueue = NoParam
            let _pBlockEnergyLimitQueue = NoParam
            return PendingUpdates{..}
        StateMigrationParametersP4ToP5 -> do
            let _pElectionDifficultyQueue = SomeParam (unOParam oldElectionDifficultyQueue)
            _pCooldownParametersQueue <- whenSupported getUpdateQueueV0
            _pTimeParametersQueue <- whenSupported getUpdateQueueV0
            let _pTimeoutParametersQueue = NoParam
            let _pMinBlockTimeQueue = oldMinBlockTimeQueue
            let _pBlockEnergyLimitQueue = oldBlockEnergyLimitQueue
            return PendingUpdates{..}

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
              "consensus2TimingParameters" AE..= unOParam _pTimeoutParametersQueue
            ]

instance IsChainParametersVersion cpv => ToJSON (PendingUpdates cpv) where
    toJSON = case chainParametersVersion @cpv of
        SChainParametersV0 -> pendingUpdatesV0ToJSON
        SChainParametersV1 -> pendingUpdatesV1ToJSON
        SChainParametersV2 -> pendingUpdatesV2ToJSON

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
    return PendingUpdates{..}

instance IsChainParametersVersion cpv => FromJSON (PendingUpdates cpv) where
    parseJSON = case chainParametersVersion @cpv of
        SChainParametersV0 -> parsePendingUpdatesV0
        SChainParametersV1 -> parsePendingUpdatesV1
        SChainParametersV2 -> parsePendingUpdatesV2

-- |Initial pending updates with empty queues.
emptyPendingUpdates :: forall cpv. IsChainParametersVersion cpv => PendingUpdates cpv
emptyPendingUpdates =
    PendingUpdates
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        (pureWhenSupported emptyUpdateQueue)
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        emptyUpdateQueue
        (pureWhenSupported emptyUpdateQueue)
        (pureWhenSupported emptyUpdateQueue)
        (pureWhenSupported emptyUpdateQueue)
        (pureWhenSupported emptyUpdateQueue)
        (pureWhenSupported emptyUpdateQueue)

-- |Current state of updatable parameters and update queues.
data Updates' (cpv :: ChainParametersVersion) = Updates
    { -- |Current update authorizations.
      _currentKeyCollection :: !(Hashed (UpdateKeysCollection cpv)),
      -- |Current protocol update.
      _currentProtocolUpdate :: !(Maybe ProtocolUpdate),
      -- |Current chain parameters.
      _currentParameters :: !(ChainParameters' cpv),
      -- |Pending updates.
      _pendingUpdates :: !(PendingUpdates cpv)
    }
    deriving (Show, Eq)

makeLenses ''Updates'

type Updates (pv :: ProtocolVersion) = Updates' (ChainParametersVersionFor pv)

instance IsChainParametersVersion cpv => HashableTo H.Hash (Updates' cpv) where
    getHash Updates{..} =
        H.hash $
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
    putUpdateKeysCollection (_currentKeyCollection ^. unhashed)
    case _currentProtocolUpdate of
        Nothing -> putWord8 0
        Just cpu -> putWord8 1 >> put cpu
    putChainParameters _currentParameters
    putPendingUpdatesV0 _pendingUpdates

-- |Deserialize 'Updates', applying a migration as necessary.
getUpdates ::
    forall oldpv pv.
    (IsProtocolVersion oldpv, IsProtocolVersion pv) =>
    StateMigrationParameters oldpv pv ->
    Get (Updates' (ChainParametersVersionFor pv))
getUpdates migration = do
    _currentKeyCollection <- makeHashed . migrateUpdateKeysCollection migration <$> getUpdateKeysCollection
    _currentProtocolUpdate <-
        getWord8 >>= \case
            0 -> return Nothing
            1 -> Just <$> get
            _ -> fail "Invalid Updates"
    _currentParameters <- migrateChainParameters migration <$> getChainParameters @(ChainParametersVersionFor oldpv)
    _pendingUpdates <- getPendingUpdates migration
    return Updates{..}

instance forall cpv. IsChainParametersVersion cpv => ToJSON (Updates' cpv) where
    toJSON Updates{..} =
        object $
            [ "keys" AE..= _unhashed _currentKeyCollection,
              "chainParameters" AE..= _currentParameters,
              "updateQueues" AE..= _pendingUpdates
            ]
                <> toList (("protocolUpdate" AE..=) <$> _currentProtocolUpdate)

instance forall cpv. IsChainParametersVersion cpv => FromJSON (Updates' cpv) where
    parseJSON = withObject "Updates" $ \o -> do
        _currentKeyCollection <- makeHashed <$> o AE..: "keys"
        _currentProtocolUpdate <- o AE..:? "protocolUpdate"
        _currentParameters <- o AE..: "chainParameters"
        _pendingUpdates <- o AE..: "updateQueues"
        return Updates{..}

-- |An initial 'Updates' with the given initial 'Authorizations'
-- and 'ChainParameters'.
initialUpdates ::
    IsChainParametersVersion cpv =>
    UpdateKeysCollection cpv ->
    ChainParameters' cpv ->
    Updates' cpv
initialUpdates initialKeyCollection _currentParameters =
    Updates
        { _currentKeyCollection = makeHashed initialKeyCollection,
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
