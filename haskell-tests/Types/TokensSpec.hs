{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Types.TokensSpec where

import Control.Monad
import qualified Data.Aeson as AE
import Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as BSS
import Data.Serialize
import Data.Word

import Test.HUnit
import Test.Hspec
import Test.QuickCheck as QuickCheck hiding ((.&.))

import Concordium.Types
import Concordium.Types.Tokens
import Generators

-- | Shrink a UTF-8 string by removing one character in every possible way.
shrinkUtf8String :: [Word8] -> [[Word8]]
shrinkUtf8String [] = []
shrinkUtf8String (a : r)
    | a .&. 0b10000000 == 0 = r : ((a :) <$> shrinkUtf8String r)
shrinkUtf8String (a : b : r)
    | a .&. 0b11100000 == 0b11000000 = r : ((\r' -> a : b : r') <$> shrinkUtf8String r)
shrinkUtf8String (a : b : c : r)
    | a .&. 0b11110000 == 0b11100000 = r : ((\r' -> a : b : c : r') <$> shrinkUtf8String r)
shrinkUtf8String (a : b : c : d : r)
    | a .&. 0b11111000 == 0b11110000 = r : ((\r' -> a : b : c : d : r') <$> shrinkUtf8String r)
shrinkUtf8String _ = error "shrinkUtf8String: invalid UTF-8 string"

instance Arbitrary TokenId where
    arbitrary = genTokenId
    shrink (TokenId tid) = [TokenId (BSS.pack shrunk) | shrunk <- shrinkUtf8String (BSS.unpack tid)]

-- | Deserialize a value, ensuring that the input is fully consumed.
decodeFull :: Get a -> BS.ByteString -> Either String a
decodeFull getter =
    runGet
        ( do
            g <- getter
            done <- isEmpty
            unless done $ fail "Input was not fully consumed"
            return g
        )

-- | Test serializing and deserializing a valid 'TokenId'.
testTokenIdEncodeDecode :: Property
testTokenIdEncodeDecode = property $ \(tid :: TokenId) ->
    decodeFull get (encode tid) == Right tid

-- | Test serializing and unsafe-deserializing a valid 'TokenId'.
testTokenIdEncodeDecodeUnsafe :: Property
testTokenIdEncodeDecodeUnsafe = property $ \(tid :: TokenId) ->
    decodeFull unsafeGetTokenId (encode tid) == Right tid

-- | Test some invalid 'TokenId's
testInvalidTokenIds :: Spec
testInvalidTokenIds = do
    -- Not a valid byte
    checkInvalid "\xff"
    -- Surrogate codepoint
    checkInvalid "\xed\xbf\xbf"
    -- Expect additional bytes
    checkInvalid "\xcf"
    checkInvalid "\xe0\xa0"
    -- Overlong encoding
    checkInvalid "\xc2\x01"
    -- Too long
    checkInvalid $ BSS.pack (replicate 256 0x41)
  where
    checkInvalid sbs = it ("makeTokenId invalid case: " ++ show sbs) $ case makeTokenId sbs of
        Left _ -> return ()
        Right _ -> assertFailure "makeTokenId should fail."

-- | Test that encoding and decoding a 'TokenRawAmount' value works as expected.
testTokenRawAmountEncodeDecode :: Property
testTokenRawAmountEncodeDecode = forAll genTokenRawAmount $ \a ->
    let encoded = encode a
    in  QuickCheck.label ("encoded length " ++ show (BS.length encoded)) $
            decodeFull get encoded === Right a

-- | Test cases where decoding a 'TokenRawAmount' fails.
testTokenRawAmountDecodeFailures :: Spec
testTokenRawAmountDecodeFailures =
    describe "Failing TokenRawAmount deserialization cases" $ mapM_ testFail examples
  where
    testFail (bytes, expct) =
        it ("Decoding " ++ show bytes) $
            decodeFull (get @TokenRawAmount) (BS.pack bytes) `shouldBe` Left expct
    examples =
        [ ([0x80], noPadding),
          ([0x80, 0x00], noPadding),
          ([0x81], unexpectedEnd),
          ([0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00], outOfRange),
          ([0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80], outOfRange),
          ([0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00], outOfRange)
        ]
    noPadding = "Failed reading: Padding bytes are not allowed\nEmpty call stack\n"
    unexpectedEnd = "too few bytes\nFrom:\tdemandInput\n\n"
    outOfRange = "Failed reading: Value out of range\nEmpty call stack\n"

-- | Test the JSON encoding and decoding of 'TokenAmount'.
testTokenAmountJSONEncodeDecode :: Property
testTokenAmountJSONEncodeDecode = forAll genTokenAmount $ \a ->
    let encoded = AE.encode a
    in  counterexample (show encoded) $
            case AE.eitherDecode encoded of
                Left err -> counterexample ("decoding error: " ++ err) False
                Right decoded ->
                    a === decoded

testTokenAmountJSONDecodeCases :: Spec
testTokenAmountJSONDecodeCases = do
    it "value out of bounds" $
        AE.eitherDecode "{\"value\": \"1000000000000000000000\", \"decimals\": 0}"
            `shouldBe` (Left "Error in $.value: TokenRawAmount out of bounds." :: Either String TokenAmount)
    it "decimals out of bounds" $
        AE.eitherDecode "{\"value\": \"10000\", \"decimals\": 256}"
            `shouldBe` (Left "Error in $.decimals: parsing Word8 failed, value is either floating or will cause over or underflow 256.0" :: Either String TokenAmount)

-- | Test the binary serialization and deserialization of 'TokenAmount'.
testTokenAmountEncodeDecode :: Property
testTokenAmountEncodeDecode = forAll genTokenAmount $ \a ->
    decodeFull get (encode a) == Right a

-- | Tests for token types.
tests :: Spec
tests = parallel $ do
    describe "TokenId" $ do
        it "Serialization and deserialization of valid TokenIds" $
            withMaxSuccess 10000 testTokenIdEncodeDecode
        it "Serialization and unsafe deserialization of valid TokenIds" $
            withMaxSuccess 10000 testTokenIdEncodeDecodeUnsafe
        testInvalidTokenIds
    describe "TokenRawAmount" $ do
        it "Serialization and deserialization of valid TokenRawAmounts" $
            withMaxSuccess 10000 testTokenRawAmountEncodeDecode
        testTokenRawAmountDecodeFailures
    describe "TokenAmount" $ do
        it "JSON Serialization and deserialization of valid TokenAmounts" $
            withMaxSuccess 10000 testTokenAmountJSONEncodeDecode
        testTokenAmountJSONDecodeCases
        it "Binary Serialization and deserialization of valid TokenAmounts" $
            withMaxSuccess 10000 testTokenAmountEncodeDecode
