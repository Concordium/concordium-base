{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -Wno-deprecations #-}

module ConcordiumTests.Crypto.VRF where

import qualified Concordium.Crypto.VRF as VRF

import qualified Data.Aeson as AE
import qualified Data.ByteString as BS
import Data.Serialize
import Test.Hspec
import Test.QuickCheck

testSerializePublicKey :: Property
testSerializePublicKey = property $ \kp -> Right (VRF.publicKey kp) === runGet get (runPut $ put $ VRF.publicKey kp)

testSerializePrivateKey :: Property
testSerializePrivateKey = property $ \kp -> Right (VRF.privateKey kp) === runGet get (runPut $ put $ VRF.privateKey kp)

testSerializePublicKeyJSON :: Property
testSerializePublicKeyJSON = property $ \kp -> Just (VRF.publicKey kp) === AE.decode (AE.encode (VRF.publicKey kp))

testSerializePrivateKeyJSON :: Property
testSerializePrivateKeyJSON = property $ \kp -> Just (VRF.privateKey kp) === AE.decode (AE.encode (VRF.privateKey kp))

testSerializeKeyPair :: Property
testSerializeKeyPair = property $ \(kp :: VRF.KeyPair) -> Right kp === runGet get (runPut $ put kp)

testSerializeProof :: Property
testSerializeProof = property $ \kp doc ->
    let pf = VRF.prove kp (BS.pack doc)
    in  Right pf === runGet get (runPut $ put pf)

testGenVerifyKey :: Property
testGenVerifyKey = property $ \kp -> VRF.verifyKey (VRF.publicKey kp)

testProveVerify :: Property
testProveVerify = property $ \kp doc0 ->
    let doc = BS.pack doc0
        pf = VRF.prove kp doc
    in  VRF.verify (VRF.publicKey kp) doc pf

testPublicKeyOrd :: Property
testPublicKeyOrd = property $ \(kp1, kp2) ->
    let k1 = case compare (VRF.publicKey kp1) (VRF.publicKey kp2) of
            LT -> property True
            GT -> property True
            EQ -> kp1 === kp2
        k2 = compare (VRF.publicKey kp1) (VRF.publicKey kp1) === EQ
        k3 = compare (VRF.publicKey kp2) (VRF.publicKey kp2) === EQ
    in  k1 .&&. k2 .&&. k3

testProofOrd :: Property
testProofOrd = property $ \kp doc0 doc1 ->
    let doc = BS.pack doc0
        doc' = BS.pack doc1
        pf1 = VRF.prove kp doc
        pf2 = VRF.prove kp doc'
        k1 = case compare pf1 pf2 of
            LT -> property True
            GT -> property True
            EQ -> pf1 === pf2
        k2 = compare pf1 pf1 === EQ
        k3 = compare pf2 pf2 === EQ
    in  (k1 .&&. k2 .&&. k3)

testProveDeterministic :: Property
testProveDeterministic = property $ \kp doc0 ->
    let doc = BS.pack doc0
        pf1 = VRF.prove kp doc
        pf2 = VRF.prove kp doc
    in  pf1 === pf2

-- Generate a bunch of proofs and convert them to hashes. They should be
-- different. This is really regression testing the FFI bug where a generated
-- proof was not valid.
stressTest :: Property
stressTest = property $ \kp doc0 doc1 ->
    let doc = BS.pack doc0
        doc' = BS.pack doc1
        pf1 = VRF.prove kp doc
        pf2 = VRF.prove kp doc'
    in  (VRF.proofToHash pf1 == VRF.proofToHash pf2) == (doc == doc')

tests :: Spec
tests = describe "Concordium.Crypto.VRF" $ do
    describe "serialization" $ do
        it "public key" testSerializePublicKey
        it "private key" testSerializePrivateKey
        it "keypair" testSerializeKeyPair
        it "proof" testSerializeProof
        it "public key JSON" testSerializePublicKeyJSON
        it "private key JSON" testSerializePrivateKeyJSON
    describe "Ord instance compatibility with Eq" $ do
        it "public key" testPublicKeyOrd
        it "proof" testProofOrd
    it "verify generated public key" testGenVerifyKey
    it "verify proof" testProveVerify
    it "VRF proofs are deterministic" testProveDeterministic
    parallel $ do
        it "stress testing vrf proof to hash 1 " $ withMaxSuccess 100000 stressTest
        it "stress testing vrf proof to hash 2" $ withMaxSuccess 100000 stressTest
        it "stress testing vrf proof to hash 3" $ withMaxSuccess 100000 stressTest
        it "stress testing vrf proof to hash 4" $ withMaxSuccess 100000 stressTest
        it "stress testing vrf proof to hash 5" $ withMaxSuccess 100000 stressTest
