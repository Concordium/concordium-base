{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Types.TokenIdSpec where

import Control.Monad
import Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as BSS
import Data.Serialize
import Data.Word

import Test.HUnit
import Test.Hspec
import Test.QuickCheck hiding ((.&.))

import Concordium.Types
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
testEncodeDecode :: Property
testEncodeDecode = property $ \(tid :: TokenId) ->
    decodeFull get (encode tid) == Right tid

-- | Test serializing and unsafe-deserializing a valid 'TokenId'.
testEncodeDecodeUnsafe :: Property
testEncodeDecodeUnsafe = property $ \(tid :: TokenId) ->
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

-- | Tests for 'TokenId's.
tests :: Spec
tests = describe "TokenId" $ do
    it "Serialization and deserialization of valid TokenIds" $ withMaxSuccess 10000 testEncodeDecode
    it "Serialization and unsafe deserialization of valid TokenIds" $ withMaxSuccess 10000 testEncodeDecodeUnsafe
    testInvalidTokenIds
