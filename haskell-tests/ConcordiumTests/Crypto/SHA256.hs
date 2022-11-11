{-# LANGUAGE OverloadedStrings #-}

module ConcordiumTests.Crypto.SHA256 where

import qualified Concordium.Crypto.SHA256 as Hash

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Char
import qualified Data.FixedByteString as FBS
import Data.Serialize
import Data.Word
import Test.Hspec
import Test.QuickCheck
import Text.Read hiding (get)

testSerialize :: Property
testSerialize = property $ ck
  where
    ck :: [Word8] -> Property
    ck doc =
        let doc' = BS.pack doc
        in  let hsh = Hash.hash doc'
            in  Right hsh === runGet get (runPut $ put hsh)

testStrictLazy :: Property
testStrictLazy = property ck
  where
    ck :: [Word8] -> Property
    ck doc = Hash.hash (BS.pack doc) === Hash.hashLazy (LBS.pack doc)

testReadShow :: Property
testReadShow = property ck
  where
    ck :: [Word8] -> Property
    ck doc =
        let hsh = Hash.hash (BS.pack doc)
        in  Just hsh === readMaybe (show hsh)

testReadLowerShow :: Property
testReadLowerShow = property ck
  where
    ck :: [Word8] -> Property
    ck doc =
        let hsh = Hash.hash (BS.pack doc)
        in  Just hsh === readMaybe (toLower <$> show hsh)

testReadUpperShow :: Property
testReadUpperShow = property ck
  where
    ck :: [Word8] -> Property
    ck doc =
        let hsh = Hash.hash (BS.pack doc)
        in  Just hsh === readMaybe (toUpper <$> show hsh)

emptyStringHash :: Hash.Hash
emptyStringHash = Hash.Hash (FBS.pack [0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55])

tests :: Spec
tests = describe "Concordium.Crypto.SHA256" $ do
    it "serialization" $ withMaxSuccess 100000 $ testSerialize
    it "strict vs lazy" $ withMaxSuccess 100000 $ testStrictLazy
    it "show then read" $ withMaxSuccess 100000 $ testReadShow
    it "show -> lowercase -> read" $ withMaxSuccess 100000 $ testReadLowerShow
    it "show -> uppercase -> read" $ withMaxSuccess 100000 $ testReadUpperShow
    describe "known values" $ do
        -- Note that BS.empty here is specifically to prevent a regression since BS.empty has
        -- an underlying null pointer representation, but "" does not.
        -- There was a bug where calling Hash.hash on BS.empty caused a null-pointer exception in rust code.
        -- due to the FFI boundary.
        it "SHA-256 of empty string" $ Hash.hash BS.empty `shouldBe` emptyStringHash
        it "SHA-256 \"abc\"" $ Hash.hash "abc" `shouldBe` Hash.Hash (FBS.pack [0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad])
        it "SHA-256 \"\"" $ Hash.hash "" `shouldBe` emptyStringHash
        it "SHA-256 \"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\"" $ Hash.hash "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" `shouldBe` Hash.Hash (FBS.pack [0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1])
        it "SHA-256 \"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu\"" $ Hash.hash "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" `shouldBe` Hash.Hash (FBS.pack [0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80, 0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04, 0x92, 0x37, 0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51, 0xaf, 0xac, 0x45, 0x03, 0x7a, 0xfe, 0xe9, 0xd1])
        it "SHA-256 \"a\"*1000000" $ Hash.hash (BS.pack $ take 1000000 $ repeat 0x61) `shouldBe` Hash.Hash (FBS.pack [0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0])
        it "SHA-256 \"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\"*16777216 (lazy)" $ Hash.hashLazy (mconcat $ take 16777216 $ repeat "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno") `shouldBe` Hash.Hash (FBS.pack [0x50, 0xe7, 0x2a, 0x0e, 0x26, 0x44, 0x2f, 0xe2, 0x55, 0x2d, 0xc3, 0x93, 0x8a, 0xc5, 0x86, 0x58, 0x22, 0x8c, 0x0c, 0xbf, 0xb1, 0xd2, 0xca, 0x87, 0x2a, 0xe4, 0x35, 0x26, 0x6f, 0xcd, 0x05, 0x5e])
