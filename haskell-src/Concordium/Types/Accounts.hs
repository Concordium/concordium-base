{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

-- |Types for representing the results of consensus queries.
module Concordium.Types.Accounts where

import Data.Aeson
import Data.Serialize
import qualified Data.Map as Map
import qualified Lens.Micro.Platform as Lens
import Concordium.Common.Version
-- import Concordium.GlobalState.Account
-- import Concordium.GlobalState.Basic.BlockState.AccountReleaseSchedule (AccountReleaseSchedule (..))
-- import Concordium.GlobalState.Basic.BlockState.Updates (Updates)
-- import Concordium.GlobalState.Finalization
import Concordium.ID.Types
    ( AccountCredential,
      AccountEncryptionKey,
      AccountThreshold,
      CredentialIndex )
import Concordium.Types
    ( Epoch,
      Amount,
      AccountEncryptedAmount,
      Nonce,
      AccountIndex,
      BakerAggregationVerifyKey,
      BakerElectionVerifyKey,
      BakerSignVerifyKey,
      BakerId,
      AccountReleaseSchedule )
import Concordium.Types.HashableTo
import qualified Concordium.Crypto.SHA256 as Hash

data BakerInfo = BakerInfo {
    -- |Identity of the baker. This is actually the account index of
    -- the account controlling the baker.
    _bakerIdentity :: !BakerId,
    -- |The baker's public VRF key
    _bakerElectionVerifyKey :: !BakerElectionVerifyKey,
    -- |The baker's public signature key
    _bakerSignatureVerifyKey :: !BakerSignVerifyKey,
    -- |The baker's public key for finalization record aggregation
    _bakerAggregationVerifyKey :: !BakerAggregationVerifyKey
} deriving (Eq, Show)

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

Lens.makeLenses ''BakerInfo


-- |Pending changes to the baker associated with an account.
-- Changes are effective on the actual bakers, two epochs after the specified epoch,
-- however, the changes will be made to the 'AccountBaker' at the specified epoch.
data BakerPendingChange
  = NoChange
  -- ^There is no change pending to the baker.
  | ReduceStake !Amount !Epoch
  -- ^The stake will be decreased to the given amount.
  | RemoveBaker !Epoch
  -- ^The baker will be removed.
  deriving (Eq, Ord, Show)

instance Serialize BakerPendingChange where
  put NoChange = putWord8 0
  put (ReduceStake amt epoch) = putWord8 1 >> put amt >> put epoch
  put (RemoveBaker epoch) = putWord8 2 >> put epoch

  get = getWord8 >>= \case
    0 -> return NoChange
    1 -> ReduceStake <$> get <*> get
    2 -> RemoveBaker <$> get
    _ -> fail "Invalid BakerPendingChange"

-- |A baker associated with an account.
data AccountBaker = AccountBaker {
  _stakedAmount :: !Amount,
  _stakeEarnings :: !Bool,
  _accountBakerInfo :: !BakerInfo,
  _bakerPendingChange :: !BakerPendingChange
} deriving (Eq, Show)

Lens.makeLenses ''AccountBaker

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

-- |ToJSON instance supporting consensus queries.
instance ToJSON AccountBaker where
    toJSON ab = object
        ( [ "stakedAmount" .= (ab Lens.^. stakedAmount),
            "restakeEarnings" .= (ab Lens.^. stakeEarnings),
            "bakerId" .= (ab Lens.^. accountBakerInfo . bakerIdentity),
            "bakerElectionVerifyKey" .= (ab Lens.^. accountBakerInfo . bakerElectionVerifyKey),
            "bakerSignatureVerifyKey" .= (ab Lens.^. accountBakerInfo . bakerSignatureVerifyKey),
            "bakerAggregationVerifyKey" .= (ab Lens.^. accountBakerInfo . bakerAggregationVerifyKey)
            ]
            <> case ab Lens.^. bakerPendingChange of
                NoChange -> []
                ReduceStake amt ep -> ["pendingChange" .= object ["change" .= String "ReduceStake", "newStake" .= amt, "epoch" .= ep]]
                RemoveBaker ep -> ["pendingChange" .= object ["change" .= String "RemoveBaker", "epoch" .= ep]]
        )
    toEncoding ab = pairs $
        "stakedAmount" .= (ab Lens.^. stakedAmount) <>
            "restakeEarnings" .= (ab Lens.^. stakeEarnings) <>
            "bakerId" .= (ab Lens.^. accountBakerInfo . bakerIdentity) <>
            "bakerElectionVerifyKey" .= (ab Lens.^. accountBakerInfo . bakerElectionVerifyKey) <>
            "bakerSignatureVerifyKey" .= (ab Lens.^. accountBakerInfo . bakerSignatureVerifyKey) <>
            "bakerAggregationVerifyKey" .= (ab Lens.^. accountBakerInfo . bakerAggregationVerifyKey)
            <> case ab Lens.^. bakerPendingChange of
                NoChange -> mempty
                ReduceStake amt ep -> "pendingChange" .= object ["change" .= String "ReduceStake", "newStake" .= amt, "epoch" .= ep]
                RemoveBaker ep -> "pendingChange" .= object ["change" .= String "RemoveBaker", "epoch" .= ep]

instance HashableTo AccountBakerHash AccountBaker where
  getHash AccountBaker{..}
    = makeAccountBakerHash
        _stakedAmount
        _stakeEarnings
        _accountBakerInfo
        _bakerPendingChange

type AccountBakerHash = Hash.Hash

-- |Make an 'AccountBakerHash' for a baker.
makeAccountBakerHash :: Amount -> Bool -> BakerInfo -> BakerPendingChange -> AccountBakerHash
makeAccountBakerHash amt stkEarnings binfo bpc = Hash.hashLazy $ runPutLazy $
  put amt >> put stkEarnings >> put binfo >> put bpc

-- |An 'AccountBakerHash' that is used when an account has no baker.
-- This is defined as the hash of the empty string.
nullAccountBakerHash :: AccountBakerHash
nullAccountBakerHash = Hash.hash ""


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

instance ToJSON AccountInfo where
    toJSON AccountInfo{..} =
        object $
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
    toEncoding AccountInfo{..} =
        pairs $
            "accountNonce" .= aiAccountNonce
                <> "accountAmount" .= aiAccountAmount
                <> "accountReleaseSchedule" .= aiAccountReleaseSchedule
                <> "accountCredentials" .= aiAccountCredentials
                <> "accountThreshold" .= aiAccountThreshold
                <> "accountEncryptedAmount" .= aiAccountEncryptedAmount
                <> "accountEncryptionKey" .= aiAccountEncryptionKey
                <> "accountIndex" .= aiAccountIndex
                <> maybe mempty ("accountBaker" .=) aiBaker
