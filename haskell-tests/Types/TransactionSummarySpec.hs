{-# OPTIONS_GHC -fno-warn-orphans #-}

module Types.TransactionSummarySpec where

import qualified Data.Aeson as AE
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
testEventSerializationIdentity :: IsProtocolVersion pv => SProtocolVersion pv -> Property
testEventSerializationIdentity spv = forAll (genEvent spv) $ \e -> runGet (getEvent spv) (runPut $ putEvent e) === Right e

-- |Test that decoding is the inverse of encoding for 'Event's.
testEventJSONSerializationIdentity :: IsProtocolVersion pv => SProtocolVersion pv -> Property
testEventJSONSerializationIdentity spv = forAll (genEvent spv) $ \e -> AE.eitherDecode (AE.encode e) === Right e

-- |Test that decoding is the inverse of encoding for 'RejectReason's.
testRejectReasonSerializationIdentity :: RejectReason -> Property
testRejectReasonSerializationIdentity e = decode (encode e) === Right e

-- |Test that decoding is the inverse of encoding for 'ValidResult's.
testValidResultSerializationIdentity :: IsProtocolVersion pv => SProtocolVersion pv -> Property
testValidResultSerializationIdentity spv = forAll (genValidResult spv) $ \e -> runGet (getValidResult spv) (runPut $ putValidResult e) === Right e

-- |Test that decoding is the inverse of encoding for 'TransactionSummary's.
testTransactionSummarySerializationIdentity :: IsProtocolVersion pv => SProtocolVersion pv -> Property
testTransactionSummarySerializationIdentity spv = forAll (genTransactionSummary spv) $ \e -> runGet (getTransactionSummary spv) (runPut $ putTransactionSummary e) === Right e

tests :: Spec
tests = describe "Transaction summaries" $ do
    specify "TransactionType: serialize then deserialize is identity" testTransactionTypesSerialIdentity
    -- Since the JSON serialization is the same for all protocol versions, we just test for P4,
    -- since this includes all events.
    specify "Event: JSON serialize then deserialize is identity" $ withMaxSuccess 10000 $ testEventJSONSerializationIdentity SP4
    specify "RejectReason: serialize then deserialize is identity" $ withMaxSuccess 10000 testRejectReasonSerializationIdentity
    versionedTests SP1
    versionedTests SP2
    versionedTests SP3
    versionedTests SP4
  where
    versionedTests spv = describe (show $ demoteProtocolVersion spv) $ do
        specify "Event: serialize then deserialize is identity" $ withMaxSuccess 10000 $ testEventSerializationIdentity spv
        specify "ValidResult: serialize then deserialize is identity" $ withMaxSuccess 1000 $ testValidResultSerializationIdentity spv
        specify "TransactionSummary: serialize then deserialize is identity" $ withMaxSuccess 1000 $ testTransactionSummarySerializationIdentity spv
