{-# OPTIONS_GHC -fno-warn-orphans #-}

module Types.TransactionSummarySpec where

import Data.Serialize
import Test.Hspec
import Test.QuickCheck

import Concordium.Types.Execution

import Types.Generators


testTransactionTypesSerialIdentity :: Expectation
testTransactionTypesSerialIdentity = mapM_ testEncDec transactionTypes
  where
    testEncDec tt = decode (encode tt) `shouldBe` Right tt


-- |Test that decoding is the inverse of encoding for 'Event's.
testEventSerializationIdentity :: Event -> Property
testEventSerializationIdentity e = decode (encode e) === Right e


-- |Test that decoding is the inverse of encoding for 'RejectReason's.
testRejectReasonSerializationIdentity :: RejectReason -> Property
testRejectReasonSerializationIdentity e = decode (encode e) === Right e


-- |Test that decoding is the inverse of encoding for 'ValidResult's.
testValidResultSerializationIdentity :: ValidResult -> Property
testValidResultSerializationIdentity e = decode (encode e) === Right e


-- |Test that decoding is the inverse of encoding for 'TransactionSummary's.
testTransactionSummarySerializationIdentity :: TransactionSummary -> Property
testTransactionSummarySerializationIdentity e = decode (encode e) === Right e

tests :: Spec
tests = describe "Transaction summaries" $ do
    specify "TransactionType: serialize then deserialize is identity" testTransactionTypesSerialIdentity
    specify "Event: serialize then deserialize is identity" $ withMaxSuccess 10000 testEventSerializationIdentity
    specify "RejectReason: serialize then deserialize is identity" $ withMaxSuccess 10000 testRejectReasonSerializationIdentity
    specify "ValidResult: serialize then deserialize is identity" $ withMaxSuccess 1000 testValidResultSerializationIdentity
    specify "TransactionSummary: serialize then deserialize is identity" $ withMaxSuccess 1000 testTransactionSummarySerializationIdentity
