{-# LANGUAGE OverloadedStrings #-}
module Types.AccountEncryptedAmountSpec where

import qualified Data.Aeson as AE
import qualified Data.Serialize as S
import qualified Data.Sequence as Seq
import Test.Hspec
import Test.QuickCheck as QC

import Concordium.ID.Parameters
import Concordium.Crypto.EncryptedTransfers
import Concordium.Types

-- This generates an encryption with zero randomness, but that is sufficient for
-- our testing since we assume serialization of encrypted amounts themselves is
-- fine, and we are only checking the account structure.
genEncryptedAmount :: Gen EncryptedAmount
genEncryptedAmount = do
  amnt <- Amount <$> arbitrary
  return $ encryptAmountZeroRandomness globalContext amnt

genAccountEncryptedAmount :: Gen AccountEncryptedAmount
genAccountEncryptedAmount = do
  _selfAmount <- genEncryptedAmount
  _startIndex <- EncryptedAmountAggIndex <$> arbitrary
  len <- choose (0,100)
  _incomingEncryptedAmounts <- Seq.replicateM len genEncryptedAmount
  numAgg <- arbitrary
  if numAgg == Just 1 || numAgg == Just 0 then
    return AccountEncryptedAmount{_numAggregated = Nothing,..}
  else
    return AccountEncryptedAmount{_numAggregated = numAgg,..}

testBinarySerialization :: Property
testBinarySerialization = forAll genAccountEncryptedAmount $ \acc ->
  let bs = S.encode acc
  in Right acc === S.decode bs

testJSONSerialization :: Property
testJSONSerialization = forAll genAccountEncryptedAmount $ \acc ->
  let bs = AE.encode acc
  in Right acc === AE.eitherDecode bs

tests :: Spec
tests = parallel $ do
  specify "AccountEncryptedAmount binary serialization" $ withMaxSuccess 1000 $ testBinarySerialization
  specify "AccountEncryptedAmount JSON serialization" $ withMaxSuccess 1000 $ testJSONSerialization

