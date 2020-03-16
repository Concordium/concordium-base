{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -Wno-deprecations #-}
module Types.TransactionGen where

import Test.QuickCheck

import Concordium.Crypto.SHA256(hash)
import Concordium.Types.Transactions
import Concordium.Crypto.SignatureScheme
import Data.Time.Clock

import Concordium.Types
import Concordium.ID.Types

import Control.Monad
import qualified Data.FixedByteString as FBS
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as BSS
import Data.Serialize(encode)

schemes :: [SchemeId]
schemes = [Ed25519]

genSchemeId :: Gen SchemeId
genSchemeId = elements schemes 

genAccountAddress :: Gen (AccountAddress, SchemeId)
genAccountAddress = do
  tsScheme <- genSchemeId
  addr <- AccountAddress <$> (FBS.pack . (fromIntegral (fromEnum tsScheme) :) <$> vector 20)
  return (addr, tsScheme)

genTransactionHeader :: Gen TransactionHeader
genTransactionHeader = do
  (thSender, _) <- genAccountAddress
  thPayloadSize <- PayloadSize . (`mod` 5000) <$> arbitrary
  thNonce <- Nonce <$> arbitrary
  thEnergyAmount <- Energy <$> arbitrary
  thExpiry <- TransactionExpiryTime <$> arbitrary
  return $ TransactionHeader{..}

genBareTransaction :: Gen BareTransaction
genBareTransaction = do
  btrHeader <- genTransactionHeader
  btrPayload <- EncodedPayload . BSS.pack <$> vector (fromIntegral (thPayloadSize btrHeader))
  numKeys <- choose (1, 255)
  btrSignature <- TransactionSignature <$> replicateM numKeys (do
    idx <- KeyIndex <$> arbitrary
    sLen <- choose (50,70)
    sig <- Signature . BSS.pack <$> vector sLen
    return (idx, sig))
  return $! BareTransaction{..}

baseTime :: UTCTime
baseTime = read "2019-09-23 13:27:13.257285424 UTC"

genTransaction :: Gen Transaction
genTransaction = do
  wmdData <- genBareTransaction
  wmdArrivalTime <- arbitrary
  let body = encode wmdData
  let wmdHash = hash body
  let wmdSize = BS.length body
  return $ WithMetadata{..}
