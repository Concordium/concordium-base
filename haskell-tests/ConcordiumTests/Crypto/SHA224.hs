{-# LANGUAGE OverloadedStrings #-}
module ConcordiumTests.Crypto.SHA224 where

import qualified Concordium.Crypto.SHA224 as Hash

import Data.Serialize
import qualified Data.ByteString as BS
import qualified Data.FixedByteString as FBS
import qualified Data.ByteString.Lazy as LBS
import Data.Word
import Test.QuickCheck
import Test.Hspec
import Test.Hspec.Expectations
import Text.Read hiding (get)
import Data.Char

testSerialize :: Property
testSerialize = property $ ck
    where
        ck :: [Word8] -> Property
        ck doc = let doc' = BS.pack doc in
                    let hsh = Hash.hash doc' in
                        Right hsh === runGet get (runPut $ put hsh)

testStrictLazy :: Property
testStrictLazy = property ck
    where
        ck :: [Word8] -> Property
        ck doc = Hash.hash (BS.pack doc) === Hash.hashLazy (LBS.pack doc)

testReadShow :: Property
testReadShow = property ck
    where
        ck :: [Word8] -> Property
        ck doc = let hsh = Hash.hash (BS.pack doc) in
            Just hsh === readMaybe (show hsh)

testReadLowerShow :: Property
testReadLowerShow = property ck
    where
        ck :: [Word8] -> Property
        ck doc = let hsh = Hash.hash (BS.pack doc) in
            Just hsh === readMaybe (toLower <$> show hsh)

testReadUpperShow :: Property
testReadUpperShow = property ck
    where
        ck :: [Word8] -> Property
        ck doc = let hsh = Hash.hash (BS.pack doc) in
            Just hsh === readMaybe (toUpper <$> show hsh)

tests = parallel $ describe "Concordium.Crypto.SHA224" $ do
            it "serialization" $ withMaxSuccess 100000 $ testSerialize
            it "strict vs lazy" $ withMaxSuccess 100000 $ testStrictLazy
            it "show then read" $ withMaxSuccess 100000 $ testReadShow
            it "show -> lowercase -> read" $ withMaxSuccess 100000 $ testReadLowerShow
            it "show -> uppercase -> read" $ withMaxSuccess 100000 $ testReadUpperShow
            describe "known values" $ do
                it "SHA-224 \"abc\"" $ Hash.hash "abc" `shouldBe` Hash.Hash (FBS.pack [0x23,0x09,0x7d,0x22,0x34,0x05,0xd8,0x22,0x86,0x42,0xa4,0x77,0xbd,0xa2,0x55,0xb3,0x2a,0xad,0xbc,0xe4,0xbd,0xa0,0xb3,0xf7,0xe3,0x6c,0x9d,0xa7])
                it "SHA-224 \"\"" $ Hash.hash "" `shouldBe` Hash.Hash (FBS.pack [0xd1,0x4a,0x02,0x8c,0x2a,0x3a,0x2b,0xc9,0x47,0x61,0x02,0xbb,0x28,0x82,0x34,0xc4,0x15,0xa2,0xb0,0x1f,0x82,0x8e,0xa6,0x2a,0xc5,0xb3,0xe4,0x2f])
                it "SHA-224 \"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\"" $ Hash.hash "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" `shouldBe` Hash.Hash (FBS.pack [0x75,0x38,0x8b,0x16,0x51,0x27,0x76,0xcc,0x5d,0xba,0x5d,0xa1,0xfd,0x89,0x01,0x50,0xb0,0xc6,0x45,0x5c,0xb4,0xf5,0x8b,0x19,0x52,0x52,0x25,0x25])
                it "SHA-224 \"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu\"" $ Hash.hash "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" `shouldBe` Hash.Hash (FBS.pack [0xc9,0x7c,0xa9,0xa5,0x59,0x85,0x0c,0xe9,0x7a,0x04,0xa9,0x6d,0xef,0x6d,0x99,0xa9,0xe0,0xe0,0xe2,0xab,0x14,0xe6,0xb8,0xdf,0x26,0x5f,0xc0,0xb3])
