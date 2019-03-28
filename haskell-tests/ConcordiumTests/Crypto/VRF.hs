{-# LANGUAGE ScopedTypeVariables #-}
module ConcordiumTests.Crypto.VRF where

import qualified Concordium.Crypto.VRF as VRF

import Data.Serialize
import qualified Data.ByteString as BS
import Test.QuickCheck
import Test.Hspec
import System.Random

instance Arbitrary VRF.KeyPair where
    arbitrary = fst . VRF.randomKeyPair . mkStdGen <$> arbitrary

testSerializePublicKey :: Property
testSerializePublicKey = property $ \kp -> Right (VRF.publicKey kp) === runGet get (runPut $ put $ VRF.publicKey kp)

testSerializePrivateKey :: Property
testSerializePrivateKey = property $ \kp -> Right (VRF.privateKey kp) === runGet get (runPut $ put $ VRF.privateKey kp)

testSerializeKeyPair :: Property
testSerializeKeyPair = property $ \(kp :: VRF.KeyPair) -> Right kp === runGet get (runPut $ put kp)

testSerializeProof :: Property
testSerializeProof = property $ \kp doc -> let pf = VRF.prove kp (BS.pack doc) in Right pf === runGet get (runPut $ put pf)

testGenVerifyKey :: Property
testGenVerifyKey = property $ \kp -> VRF.verifyKey (VRF.publicKey kp)

testProveVerify :: Property
testProveVerify = property $ \kp doc0 ->
                    let
                        doc = BS.pack doc0
                        pf = VRF.prove kp doc
                    in VRF.verify (VRF.publicKey kp) doc pf

tests :: Spec
tests = parallel $ describe "Concordium.Crypto.VRF" $ do
    describe "serialization" $ do
        it "public key" testSerializePublicKey
        it "private key" testSerializePrivateKey
        it "keypair" testSerializeKeyPair
        it "proof" testSerializeProof
    it "verify generated public key" testGenVerifyKey
    it "verify proof" testProveVerify
