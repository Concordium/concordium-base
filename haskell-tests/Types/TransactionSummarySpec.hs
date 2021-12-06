{-# OPTIONS_GHC -fno-warn-orphans #-}

module Types.TransactionSummarySpec where

import Data.Serialize
import Test.Hspec
import Test.QuickCheck

import Concordium.Types.Execution
import Concordium.Types.ProtocolVersion

import Generators


testTransactionTypesSerialIdentity :: Expectation
testTransactionTypesSerialIdentity = mapM_ testEncDec transactionTypes
  where
    testEncDec tt = decode (encode tt) `shouldBe` Right tt


-- |Test that decoding is the inverse of encoding for 'Event's.
testEventSerializationIdentity :: SProtocolVersion pv -> Property
testEventSerializationIdentity spv = forAll (genEvent spv) $ \e -> runGet (getEvent spv) (runPut $ putEvent e) === Right e


-- |Test that decoding is the inverse of encoding for 'RejectReason's.
testRejectReasonSerializationIdentity :: RejectReason -> Property
testRejectReasonSerializationIdentity e = decode (encode e) === Right e


-- |Test that decoding is the inverse of encoding for 'ValidResult's.
testValidResultSerializationIdentity :: SProtocolVersion pv -> Property
testValidResultSerializationIdentity spv = forAll (genValidResult spv) $ \e -> runGet (getValidResult spv) (runPut $ putValidResult e) === Right e


-- |Test that decoding is the inverse of encoding for 'TransactionSummary's.
testTransactionSummarySerializationIdentity :: SProtocolVersion pv -> Property
testTransactionSummarySerializationIdentity spv = forAll (genTransactionSummary spv) $ \e ->  runGet (getTransactionSummary spv) (runPut $ putTransactionSummary e) === Right e

tests :: Spec
tests = describe "Transaction summaries" $ do
    specify "TransactionType: serialize then deserialize is identity" testTransactionTypesSerialIdentity
    specify "Event: serialize then deserialize is identity in P1" $ withMaxSuccess 10000 $ testEventSerializationIdentity SP1
    specify "Event: serialize then deserialize is identity in P2" $ withMaxSuccess 10000 $ testEventSerializationIdentity SP2
    specify "Event: serialize then deserialize is identity in P3" $ withMaxSuccess 10000 $ testEventSerializationIdentity SP3
    specify "Event: serialize then deserialize is identity in P4" $ withMaxSuccess 10000 $ testEventSerializationIdentity SP4
    specify "RejectReason: serialize then deserialize is identity" $ withMaxSuccess 10000 $ testRejectReasonSerializationIdentity
    specify "ValidResult: serialize then deserialize is identity in P1" $ withMaxSuccess 1000 $ testValidResultSerializationIdentity SP1
    specify "ValidResult: serialize then deserialize is identity in P2" $ withMaxSuccess 1000 $ testValidResultSerializationIdentity SP2
    specify "ValidResult: serialize then deserialize is identity in P3" $ withMaxSuccess 1000 $ testValidResultSerializationIdentity SP3
    specify "ValidResult: serialize then deserialize is identity in P4" $ withMaxSuccess 1000 $ testValidResultSerializationIdentity SP4
    specify "TransactionSummary: serialize then deserialize is identity in P1" $ withMaxSuccess 1000 $ testTransactionSummarySerializationIdentity SP1
    specify "TransactionSummary: serialize then deserialize is identity in P2" $ withMaxSuccess 1000 $ testTransactionSummarySerializationIdentity SP2
    specify "TransactionSummary: serialize then deserialize is identity in P3" $ withMaxSuccess 1000 $ testTransactionSummarySerializationIdentity SP3
    specify "TransactionSummary: serialize then deserialize is identity in P4" $ withMaxSuccess 1000 $ testTransactionSummarySerializationIdentity SP4
