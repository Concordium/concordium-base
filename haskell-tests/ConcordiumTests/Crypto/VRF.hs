{-# LANGUAGE ScopedTypeVariables #-}
module ConcordiumTests.Crypto.VRF where

import qualified Concordium.Crypto.VRF as VRF

import Data.Serialize
import qualified Data.ByteString as BS
import Test.QuickCheck.Monadic
import Test.QuickCheck
import Test.Hspec

testSerializePublicKey :: Property
testSerializePublicKey = property $ \kp -> Right (VRF.publicKey kp) === runGet get (runPut $ put $ VRF.publicKey kp)

testSerializePrivateKey :: Property
testSerializePrivateKey = property $ \kp -> Right (VRF.privateKey kp) === runGet get (runPut $ put $ VRF.privateKey kp)

testSerializeKeyPair :: Property
testSerializeKeyPair = property $ \(kp :: VRF.KeyPair) -> Right kp === runGet get (runPut $ put kp)

testSerializeProof :: Property
testSerializeProof = property $ \kp doc -> monadicIO $ do
        pf <- run $ VRF.prove kp (BS.pack doc)
        return $ Right pf === runGet get (runPut $ put pf)

testGenVerifyKey :: Property
testGenVerifyKey = property $ \kp -> VRF.verifyKey (VRF.publicKey kp)

testProveVerify :: Property
testProveVerify = property $ \kp doc0 -> monadicIO $ do
                    let doc = BS.pack doc0
                    pf <- run $ VRF.prove kp doc
                    return $ VRF.verify (VRF.publicKey kp) doc pf

testProofToHashDeterministic :: Property
testProofToHashDeterministic = property $ \kp doc0 -> monadicIO $ do
        let doc = BS.pack doc0
        pf1 <- run $ VRF.prove kp doc
        pf2 <- run $ VRF.prove kp doc
        return $ VRF.proofToHash pf1 === VRF.proofToHash pf2

-- Generate a bunch of proofs and convert them to hashes. They should be
-- different. This is really regression testing the FFI bug where a generated
-- proof was not valid.
stressTest :: Property
stressTest = property $ \kp doc0 doc1 -> monadicIO $
        let doc = BS.pack doc0
            doc' = BS.pack doc1 in do
              pf1 <- run $ VRF.prove kp doc
              pf2 <- run $ VRF.prove kp doc'
              return $ (VRF.proofToHash pf1 == VRF.proofToHash pf2) == (doc == doc')


tests :: Spec
tests = describe "Concordium.Crypto.VRF" $ do
    describe "serialization" $ do
        it "public key" testSerializePublicKey
        it "private key" testSerializePrivateKey
        it "keypair" testSerializeKeyPair
        it "proof" testSerializeProof
    it "verify generated public key" testGenVerifyKey
    it "verify proof" testProveVerify
    it "output of VRF is independent of proof" testProofToHashDeterministic
    parallel $ do
      it "stress testing vrf proof to hash 1 " $ withMaxSuccess 100000 stressTest
      it "stress testing vrf proof to hash 2" $ withMaxSuccess 100000 stressTest
      it "stress testing vrf proof to hash 3" $ withMaxSuccess 100000 stressTest
      it "stress testing vrf proof to hash 4" $ withMaxSuccess 100000 stressTest
      it "stress testing vrf proof to hash 5" $ withMaxSuccess 100000 stressTest
