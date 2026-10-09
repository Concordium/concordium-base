{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module ConcordiumTests.Data.ULEB128 where

import qualified Data.ByteString as BS
import Data.Word
import Test.Hspec
import Test.QuickCheck

import qualified Data.ULEB128 as ULEB128

testRoundTrip :: Property
testRoundTrip = property $ \(w :: Word64) ->
    ULEB128.decode (ULEB128.encode w) === Just (w, BS.empty)

tests :: Spec
tests = describe "Concordium.Data.ULEB128" $ do
    it "round-trips Word64 values" $ withMaxSuccess 100000 testRoundTrip
    it "encodes known fixtures" $ do
        ULEB128.encode 0 `shouldBe` BS.pack [0x00]
        ULEB128.encode 1 `shouldBe` BS.pack [0x01]
        ULEB128.encode 127 `shouldBe` BS.pack [0x7f]
        ULEB128.encode 128 `shouldBe` BS.pack [0x80, 0x01]
        ULEB128.encode 624485 `shouldBe` BS.pack [0xe5, 0x8e, 0x26]
    it "decodes known fixtures" $ do
        ULEB128.decode (BS.pack [0x00]) `shouldBe` Just (0, BS.empty)
        ULEB128.decode (BS.pack [0x01]) `shouldBe` Just (1, BS.empty)
        ULEB128.decode (BS.pack [0x7f]) `shouldBe` Just (127, BS.empty)
        ULEB128.decode (BS.pack [0x80, 0x01]) `shouldBe` Just (128, BS.empty)
        ULEB128.decode (BS.pack [0xe5, 0x8e, 0x26]) `shouldBe` Just (624485, BS.empty)
    it "preserves trailing bytes" $
        ULEB128.decode (BS.pack [0x80, 0x01, 0xaa, 0xbb]) `shouldBe` Just (128, BS.pack [0xaa, 0xbb])
    it "rejects truncated encodings" $
        ULEB128.decode (BS.pack [0x80]) `shouldBe` Nothing
    it "rejects out-of-range encodings" $
        ULEB128.decode (BS.pack [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02]) `shouldBe` Nothing
