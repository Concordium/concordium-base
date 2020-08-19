{-# LANGUAGE ScopedTypeVariables #-}
module ConcordiumTests.Crypto.FFIDataTypes where

import Concordium.Crypto.FFIDataTypes

import Data.Serialize
import Test.QuickCheck.Monadic
import Test.QuickCheck
import Test.Hspec

import Data.Word

testSerialize :: (Serialize a, Eq a, Show a) => (Int -> IO a) -> Property
testSerialize f = property $ \(n :: Word8) -> monadicIO $ do
        key <- run $ f (fromIntegral (n `mod` 20))
        return $ Right key === runGet get (runPut $ put key)

testSerializePedersenKey :: Property
testSerializePedersenKey = testSerialize generatePedersenKey

testSerializePsSigKey :: Property
testSerializePsSigKey = testSerialize generatePsSigKey

testSerializeElgamalSecond :: Property
testSerializeElgamalSecond = testSerialize (const generateElgamalSecond)

testSerializeElgamalPublicKey :: Property
testSerializeElgamalPublicKey = testSerialize (const generateElgamalPublicKey)

testSerializeElgamalCipher :: Property
testSerializeElgamalCipher = testSerialize (const generateElgamalCipher)


tests :: Spec
tests = describe "Concordium.Crypto.FFIDataTypes" $ do
    describe "serialization" $ do
        it "pedersen key" testSerializePedersenKey
        it "ps sig key key" testSerializePsSigKey
        it "elgamal key second" testSerializeElgamalSecond
        it "elgamal public key" testSerializeElgamalPublicKey
        it "elgamal cipher" testSerializeElgamalCipher
