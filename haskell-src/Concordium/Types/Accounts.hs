{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

-- |Types for representing the results of consensus queries.
module Concordium.Types.Accounts (
    BakerInfo (..),
    -- |Identity of the baker. This is actually the account index of
    -- the account controlling the baker.
    bakerIdentity,
    -- |The baker's public VRF key
    bakerElectionVerifyKey,
    -- |The baker's public signature key
    bakerSignatureVerifyKey,
    -- |The baker's public key for finalization record aggregation
    bakerAggregationVerifyKey,
    BakerPendingChange (..),
    AccountBaker (..),
    -- |The amount staked by the baker.
    stakedAmount,
    -- |Whether baker and finalizer rewards are added to the stake.
    stakeEarnings,
    -- |The baker's keys and identity.
    accountBakerInfo,
    -- |The pending change (if any) to the baker's status.
    bakerPendingChange,
    AccountBakerHash,
    makeAccountBakerHash,
    nullAccountBakerHash,
    AccountInfo (..),
    accountInfoPairs,
) where

import Data.Aeson
import qualified Data.Map as Map
import Data.Serialize
import Lens.Micro.Platform (makeLenses, (^.))

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.ID.Types
import Concordium.Types
import Concordium.Types.Accounts.Releases
import Concordium.Types.HashableTo

-- |The 'BakerId' of a baker and its public keys.
data BakerInfo = BakerInfo
    { -- |Identity of the baker. This is actually the account index of
      -- the account controlling the baker.
      _bakerIdentity :: !BakerId,
      -- |The baker's public VRF key
      _bakerElectionVerifyKey :: !BakerElectionVerifyKey,
      -- |The baker's public signature key
      _bakerSignatureVerifyKey :: !BakerSignVerifyKey,
      -- |The baker's public key for finalization record aggregation
      _bakerAggregationVerifyKey :: !BakerAggregationVerifyKey
    }
    deriving (Eq, Show)

instance Serialize BakerInfo where
    put BakerInfo{..} = do
        put _bakerIdentity
        put _bakerElectionVerifyKey
        put _bakerSignatureVerifyKey
        put _bakerAggregationVerifyKey
    get = do
        _bakerIdentity <- get
        _bakerElectionVerifyKey <- get
        _bakerSignatureVerifyKey <- get
        _bakerAggregationVerifyKey <- get
        return BakerInfo{..}

makeLenses ''BakerInfo

-- |Pending changes to the baker associated with an account.
-- Changes are effective on the actual bakers, two epochs after the specified epoch,
-- however, the changes will be made to the 'AccountBaker' at the specified epoch.
data BakerPendingChange
    = -- |There is no change pending to the baker.
      NoChange
    | -- |The stake will be decreased to the given amount.
      ReduceStake !Amount !Epoch
    | -- |The baker will be removed.
      RemoveBaker !Epoch
    deriving (Eq, Ord, Show)

instance Serialize BakerPendingChange where
    put NoChange = putWord8 0
    put (ReduceStake amt epoch) = putWord8 1 >> put amt >> put epoch
    put (RemoveBaker epoch) = putWord8 2 >> put epoch

    get =
        getWord8 >>= \case
            0 -> return NoChange
            1 -> ReduceStake <$> get <*> get
            2 -> RemoveBaker <$> get
            _ -> fail "Invalid BakerPendingChange"

-- |A baker associated with an account.
data AccountBaker = AccountBaker
    { -- |The amount staked by the baker.
      _stakedAmount :: !Amount,
      -- |Whether baker and finalizer rewards are added to the stake.
      _stakeEarnings :: !Bool,
      -- |The baker's keys and identity.
      _accountBakerInfo :: !BakerInfo,
      -- |The pending change (if any) to the baker's status.
      _bakerPendingChange :: !BakerPendingChange
    }
    deriving (Eq, Show)

makeLenses ''AccountBaker

instance Serialize AccountBaker where
    put AccountBaker{..} = do
        put _stakedAmount
        put _stakeEarnings
        put _accountBakerInfo
        put _bakerPendingChange
    get = do
        _stakedAmount <- get
        _stakeEarnings <- get
        _accountBakerInfo <- get
        _bakerPendingChange <- get
        -- If there is a pending reduction, check that it is actually a reduction.
        case _bakerPendingChange of
            ReduceStake amt _
                | amt > _stakedAmount -> fail "Pending stake reduction is not a reduction in stake"
            _ -> return ()
        return AccountBaker{..}

-- |Helper function for 'ToJSON' instance for 'AccountBaker'.
{-# INLINE accountBakerPairs #-}
accountBakerPairs :: KeyValue kv => AccountBaker -> [kv]
accountBakerPairs ab =
    [ "stakedAmount" .= (ab ^. stakedAmount),
      "restakeEarnings" .= (ab ^. stakeEarnings),
      "bakerId" .= (ab ^. accountBakerInfo . bakerIdentity),
      "bakerElectionVerifyKey" .= (ab ^. accountBakerInfo . bakerElectionVerifyKey),
      "bakerSignatureVerifyKey" .= (ab ^. accountBakerInfo . bakerSignatureVerifyKey),
      "bakerAggregationVerifyKey" .= (ab ^. accountBakerInfo . bakerAggregationVerifyKey)
    ]
        <> case ab ^. bakerPendingChange of
            NoChange -> []
            ReduceStake amt ep ->
                [ "pendingChange"
                    .= object
                        ["change" .= String "ReduceStake", "newStake" .= amt, "epoch" .= ep]
                ]
            RemoveBaker ep ->
                [ "pendingChange"
                    .= object
                        ["change" .= String "RemoveBaker", "epoch" .= ep]
                ]

-- |ToJSON instance supporting consensus queries.
instance ToJSON AccountBaker where
    toJSON ab = object $ accountBakerPairs ab
    toEncoding ab = pairs $ mconcat $ accountBakerPairs ab

instance HashableTo AccountBakerHash AccountBaker where
    getHash AccountBaker{..} =
        makeAccountBakerHash
            _stakedAmount
            _stakeEarnings
            _accountBakerInfo
            _bakerPendingChange

type AccountBakerHash = Hash.Hash

-- |Make an 'AccountBakerHash' for a baker.
makeAccountBakerHash :: Amount -> Bool -> BakerInfo -> BakerPendingChange -> AccountBakerHash
makeAccountBakerHash amt stkEarnings binfo bpc =
    Hash.hashLazy $
        runPutLazy $
            put amt >> put stkEarnings >> put binfo >> put bpc

-- |An 'AccountBakerHash' that is used when an account has no baker.
-- This is defined as the hash of the empty string.
nullAccountBakerHash :: AccountBakerHash
nullAccountBakerHash = Hash.hash ""

-- |The details of the state of an account on the chain, as may be returned by a query.
data AccountInfo = AccountInfo
    { -- |The next nonce for the account
      aiAccountNonce :: Nonce,
      -- |The total non-encrypted balance on the account
      aiAccountAmount :: Amount,
      -- |The release schedule for locked amounts on the account
      aiAccountReleaseSchedule :: AccountReleaseSchedule,
      -- |The credentials on the account
      aiAccountCredentials :: Map.Map CredentialIndex (Versioned AccountCredential),
      -- |Number of credentials required to sign a valid transaction
      aiAccountThreshold :: AccountThreshold,
      -- |The encrypted amount on the account
      aiAccountEncryptedAmount :: AccountEncryptedAmount,
      -- |The encryption key for the account
      aiAccountEncryptionKey :: AccountEncryptionKey,
      -- |The account index
      aiAccountIndex :: AccountIndex,
      -- |The baker associated with the account (if any)
      aiBaker :: Maybe AccountBaker
    }
    deriving (Eq, Show)

-- |Helper function for 'ToJSON' instance for 'AccountInfo'.
accountInfoPairs :: (KeyValue kv) => AccountInfo -> [kv]
accountInfoPairs AccountInfo{..} =
    [ "accountNonce" .= aiAccountNonce,
      "accountAmount" .= aiAccountAmount,
      "accountReleaseSchedule" .= aiAccountReleaseSchedule,
      "accountCredentials" .= aiAccountCredentials,
      "accountThreshold" .= aiAccountThreshold,
      "accountEncryptedAmount" .= aiAccountEncryptedAmount,
      "accountEncryptionKey" .= aiAccountEncryptionKey,
      "accountIndex" .= aiAccountIndex
    ]
        <> maybe [] (\b -> ["accountBaker" .= b]) aiBaker

instance ToJSON AccountInfo where
    toJSON ai = object $ accountInfoPairs ai
    toEncoding ai = pairs $ mconcat $ accountInfoPairs ai
