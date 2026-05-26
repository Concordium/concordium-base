{-# LANGUAGE MonoLocalBinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Types.TransactionSummarySpec where

import Control.Monad
import qualified Data.Aeson as AE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as BS16
import qualified Data.ByteString.Short as BSS
import Data.Serialize
import Test.Hspec
import Test.QuickCheck

import Concordium.Types
import Concordium.Types.Execution
import Concordium.Types.Tokens (TokenAmount (..))
import qualified Data.FixedByteString as FBS

import Generators

-- | Deserialize a value, ensuring that the input is fully consumed.
decodeFull :: (Serialize a) => BS.ByteString -> Either String a
decodeFull = decodeFull' get

decodeFull' :: Get a -> BS.ByteString -> Either String a
decodeFull' getter =
    runGet
        ( do
            g <- getter
            done <- isEmpty
            unless done $ fail "Input was not fully consumed"
            return g
        )

testTransactionTypesSerialIdentity :: Expectation
testTransactionTypesSerialIdentity = mapM_ testEncDec transactionTypes
  where
    testEncDec tt = decodeFull (encode tt) `shouldBe` Right tt

-- | Test that decoding is the inverse of encoding for 'Event's.
testEventSerializationIdentity :: (IsProtocolVersion pv) => SProtocolVersion pv -> Property
testEventSerializationIdentity spv = forAll (genEvent spv) $ \e -> decodeFull' (getEvent spv) (runPut $ putEvent e) === Right e

testExemplarEventSerialization :: Spec
testExemplarEventSerialization = do
    it "Simple TokenTransfer" $
        testEncoding
            "27000008746f6b656e696431000101010101010101010101010101010101010101010101010101010101010101000202020202020202020202020202020202020202020202020202020202020202876804"
            ( TokenTransfer
                { ettTokenId = TokenId "tokenid1",
                  ettFrom = HolderAccount $ AccountAddress $ FBS.pack $ repeat 0x01,
                  ettTo = HolderAccount $ AccountAddress $ FBS.pack $ repeat 0x02,
                  ettAmount = TokenAmount{taValue = 1000, taDecimals = 4},
                  ettMemo = Nothing,
                  ettFromLock = Nothing,
                  ettToLock = Nothing
                }
            )
    it "TokenTransfer with memo" $
        testEncoding
            "27000108746f6b656e6964310001010101010101010101010101010101010101010101010101010101010101010002020202020202020202020202020202020202020202020202020202020202028768040003010203"
            ( TokenTransfer
                { ettTokenId = TokenId "tokenid1",
                  ettFrom = HolderAccount $ AccountAddress $ FBS.pack $ repeat 0x01,
                  ettTo = HolderAccount $ AccountAddress $ FBS.pack $ repeat 0x02,
                  ettAmount = TokenAmount{taValue = 1000, taDecimals = 4},
                  ettMemo = Just (Memo "\x01\x02\x03"),
                  ettFromLock = Nothing,
                  ettToLock = Nothing
                }
            )
    it "TokenTransfer from lock" $
        testEncoding
            "27000208746f6b656e6964310001010101010101010101010101010101010101010101010101010101010101010002020202020202020202020202020202020202020202020202020202020202028768040f0e0d0c0b0a0908112233445566778899aabbccddeeff00"
            ( TokenTransfer
                { ettTokenId = TokenId "tokenid1",
                  ettFrom = HolderAccount $ AccountAddress $ FBS.pack $ repeat 0x01,
                  ettTo = HolderAccount $ AccountAddress $ FBS.pack $ repeat 0x02,
                  ettAmount = TokenAmount{taValue = 1000, taDecimals = 4},
                  ettMemo = Nothing,
                  ettFromLock = Just (LockId{liAccountIndex = 0x0f0e0d0c0b0a0908, liSequenceNumber = 0x1122334455667788, liCreationOrder = 0x99aabbccddeeff00}),
                  ettToLock = Nothing
                }
            )
    it "TokenTransfer to lock" $
        testEncoding
            "27000408746f6b656e69643100010101010101010101010101010101010101010101010101010101010101010100020202020202020202020202020202020202020202020202020202020202020287680499aabbccddeeff000f0e0d0c0b0a09081122334455667788"
            ( TokenTransfer
                { ettTokenId = TokenId "tokenid1",
                  ettFrom = HolderAccount $ AccountAddress $ FBS.pack $ repeat 0x01,
                  ettTo = HolderAccount $ AccountAddress $ FBS.pack $ repeat 0x02,
                  ettAmount = TokenAmount{taValue = 1000, taDecimals = 4},
                  ettMemo = Nothing,
                  ettFromLock = Nothing,
                  ettToLock = Just (LockId{liAccountIndex = 0x99aabbccddeeff00, liSequenceNumber = 0x0f0e0d0c0b0a0908, liCreationOrder = 0x1122334455667788})
                }
            )
    it "TokenTransfer with everything" $
        testEncoding
            "27\
            \000706546573745454\
            \000d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d\
            \004040404040404040404040404040404040404040404040404040404040404040\
            \81ffffffffffffffff7fff\
            \0100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff\
            \0f0e0d0c0b0a0908112233445566778899aabbccddeeff00\
            \707172737475767788898a8b8c8d8e8f9f9e9d9c9b9a9998"
            ( TokenTransfer
                { ettTokenId = TokenId "TestTT",
                  ettFrom = HolderAccount $ AccountAddress $ FBS.pack $ repeat 13,
                  ettTo = HolderAccount $ AccountAddress $ FBS.pack $ repeat 64,
                  ettAmount = TokenAmount{taValue = maxBound, taDecimals = 255},
                  ettMemo = Just (Memo $ BSS.pack $ [0x00 .. 0xff]),
                  ettFromLock = Just LockId{liAccountIndex = 0x0f0e0d0c0b0a0908, liSequenceNumber = 0x1122334455667788, liCreationOrder = 0x99aabbccddeeff00},
                  ettToLock = Just LockId{liAccountIndex = 0x7071727374757677, liSequenceNumber = 0x88898a8b8c8d8e8f, liCreationOrder = 0x9f9e9d9c9b9a9998}
                }
            )
  where
    testEncoding hex expected = do
        BS16.encode (runPut $ putEvent expected) `shouldBe` hex
        decodeFull' (getEvent SP11) (BS16.decodeLenient hex) `shouldBe` Right expected

-- | Test that decoding is the inverse of encoding for 'Event's.
testEventJSONSerializationIdentity :: (IsProtocolVersion pv) => SProtocolVersion pv -> Property
testEventJSONSerializationIdentity spv = forAll (genEvent spv) $ \e -> AE.eitherDecode (AE.encode e) === Right e

-- | Test that decoding is the inverse of encoding for 'RejectReason's.
testRejectReasonSerializationIdentity :: RejectReason -> Property
testRejectReasonSerializationIdentity e = decodeFull (encode e) === Right e

-- | Test that decoding is the inverse of encoding for 'ValidResult's.
testValidResultSerializationIdentity :: (IsProtocolVersion pv) => SProtocolVersion pv -> Property
testValidResultSerializationIdentity spv = forAll (genValidResult spv) $ \e -> decodeFull' (getValidResult spv) (runPut $ putValidResult e) === Right e

-- | Test that decoding is the inverse of encoding for 'TransactionSummary's.
testTransactionSummarySerializationIdentity :: (IsProtocolVersion pv) => SProtocolVersion pv -> Property
testTransactionSummarySerializationIdentity spv = forAll (genTransactionSummary spv) $ \e -> decodeFull' (getTransactionSummary spv) (runPut $ putTransactionSummary e) === Right e

tests :: Spec
tests = describe "Transaction summaries" $ do
    specify "TransactionType: serialize then deserialize is identity" testTransactionTypesSerialIdentity
    -- Since the JSON serialization is the same for all protocol versions, we just test for P9,
    -- since this includes all events.
    specify "Event: JSON serialize then deserialize is identity" $ withMaxSuccess 10000 $ testEventJSONSerializationIdentity SP9
    specify "RejectReason: serialize then deserialize is identity" $ withMaxSuccess 10000 testRejectReasonSerializationIdentity
    versionedTests SP1
    versionedTests SP2
    versionedTests SP3
    versionedTests SP4
    versionedTests SP5
    versionedTests SP6
    versionedTests SP7
    versionedTests SP8
    versionedTests SP9
    versionedTests SP10
    versionedTests SP11
    testExemplarEventSerialization
  where
    versionedTests spv = describe (show $ demoteProtocolVersion spv) $ do
        specify "Event: serialize then deserialize is identity" $ withMaxSuccess 10000 $ testEventSerializationIdentity spv
        specify "ValidResult: serialize then deserialize is identity" $ withMaxSuccess 1000 $ testValidResultSerializationIdentity spv
        specify "TransactionSummary: serialize then deserialize is identity" $ withMaxSuccess 1000 $ testTransactionSummarySerializationIdentity spv
