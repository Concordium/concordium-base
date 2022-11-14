{-# LANGUAGE ScopedTypeVariables #-}

module ConcordiumTests.Crypto.FFIDataTypes where

import Concordium.Crypto.FFIDataTypes
import Concordium.ID.DummyData (globalContext)

import Data.Serialize
import Test.Hspec
import Test.QuickCheck
import Test.QuickCheck.Monadic

import Data.Word

testSerialize :: (Serialize a, Eq a, Show a) => (Int -> IO a) -> Property
testSerialize f = property $ \(n :: Word8) -> monadicIO $ do
    key <- run $ f (fromIntegral (n `mod` 20))
    return $ Right key === runGet get (runPut $ put key)

testSerializeDet :: (Serialize a, Eq a, Show a, Arbitrary gen, Show gen) => (gen -> a) -> Property
testSerializeDet f = property $ \g ->
    let val = f g
    in  Right val === runGet get (runPut $ put val)

testSerializePedersenKey :: Property
testSerializePedersenKey = testSerialize generatePedersenKey

testSerializePsSigKey :: Property
testSerializePsSigKey = testSerialize generatePsSigKey

testSerializeGroupElement :: Property
testSerializeGroupElement = testSerializeDet $ generateGroupElementFromSeed globalContext

testSerializeElgamalSecretKey :: Property
testSerializeElgamalSecretKey = testSerializeDet (generateElgamalSecretKeyFromSeed globalContext)

testSerializeElgamalPublicKey :: Property
testSerializeElgamalPublicKey = testSerializeDet (deriveElgamalPublicKey globalContext . generateGroupElementFromSeed globalContext)

testSerializeElgamalCipher :: Property
testSerializeElgamalCipher = testSerialize (const generateElgamalCipher)

tests :: Spec
tests = describe "Concordium.Crypto.FFIDataTypes" $ do
    describe "serialization" $ do
        it "pedersen key" testSerializePedersenKey
        it "ps sig key key" testSerializePsSigKey
        it "group element" testSerializeGroupElement
        it "elgamal secret key" testSerializeElgamalSecretKey
        it "elgamal public key" testSerializeElgamalPublicKey
        it "elgamal cipher" testSerializeElgamalCipher
