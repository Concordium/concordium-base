{-# OPTIONS_GHC -Wno-deprecations #-}

module ConcordiumTests.Crypto.BlsSignature where

import Concordium.Crypto.BlsSignature
import Concordium.Crypto.DummyData
import qualified Data.Aeson as AE
import qualified Data.ByteString as BS
import Data.Serialize
import Test.Hspec
import Test.QuickCheck
import Test.QuickCheck.Monadic

genSecretKey :: Gen SecretKey
genSecretKey = secretBlsKeyGen

genKeyPair :: Gen (SecretKey, PublicKey)
genKeyPair = fmap (\sk -> (sk, derivePublicKey sk)) genSecretKey

forAllSK :: Testable prop => (SecretKey -> prop) -> Property
forAllSK = forAll genSecretKey

forAllKP :: Testable prop => ((SecretKey, PublicKey) -> prop) -> Property
forAllKP = forAll genKeyPair

-- Checks that two different keys doesn't produce the same signature on the same
-- message
testKeyCollision :: Property
testKeyCollision = forAllSK $ \key1 ->
    forAllSK $ \key2 m ->
        key1 /= key2 ==> sign (BS.pack m) key1 /= sign (BS.pack m) key2

-- Checks that two different documents doesn't have identical signatures under
-- the same key
testNoSignatureCollision :: Property
testNoSignatureCollision = forAllSK $ \key m1 m2 ->
    m1 /= m2 ==> sign (BS.pack m1) key /= sign (BS.pack m2) key

testSignAndVerify :: Property
testSignAndVerify = forAllKP $ \(sk, pk) m ->
    verify (BS.pack m) pk (sign (BS.pack m) sk)

testSignAndVerifyCollision :: Property
testSignAndVerifyCollision = forAllKP $ \(sk, pk) m1 m2 ->
    m1 /= m2 ==>
        let sig1 = sign (BS.pack m1) sk
            sig2 = sign (BS.pack m2) sk
        in  not (verify (BS.pack m1) pk sig2) && not (verify (BS.pack m2) pk sig1)

testProofSoundness :: Property
testProofSoundness = forAllKP $ \(sk, pk) c -> monadicIO $ do
    let b = BS.pack c
    proof <- run (proveKnowledgeOfSK b sk)
    return $ checkProofOfKnowledgeSK b proof pk

testProofNoContextCollision :: Property
testProofNoContextCollision = forAllKP $ \(sk, pk) c1 c2 ->
    let b1 = BS.pack c1
        b2 = BS.pack c2
    in  b1 /= b2 ==> monadicIO $ do
            proof <- run (proveKnowledgeOfSK b1 sk)
            return (not $ checkProofOfKnowledgeSK b2 proof pk)

testProofWrongKey :: Property
testProofWrongKey = forAllSK $ \sk1 ->
    forAllKP $ \(sk2, pk2) c ->
        sk1 /= sk2 ==> monadicIO $ do
            let b = BS.pack c
            proof <- run (proveKnowledgeOfSK b sk1)
            return . not $ checkProofOfKnowledgeSK b proof pk2

testSerializeSecretKey :: Property
testSerializeSecretKey = forAllSK $ \sk ->
    Right sk === runGet get (runPut $ put sk)

testSerializePublicKey :: Property
testSerializePublicKey = forAllKP $ \(_, pk) ->
    Right pk === runGet get (runPut $ put pk)

testSerializeSignature :: Property
testSerializeSignature = forAllSK $ \sk d ->
    let sig = sign (BS.pack d) sk
    in  Right sig === runGet get (runPut $ put sig)

testSerializeProof :: Property
testSerializeProof = forAllSK $ \sk d -> monadicIO $ do
    proof <- run (proveKnowledgeOfSK (BS.pack d) sk)
    return $ Right proof === runGet get (runPut $ put proof)

testSerializePublicKeyJSON :: Property
testSerializePublicKeyJSON = forAllSK $ \sk ->
    Just sk === AE.decode (AE.encode sk)

testSerializeSecretKeyJSON :: Property
testSerializeSecretKeyJSON = forAllKP $ \(_, pk) ->
    Just pk === AE.decode (AE.encode pk)

testSerializeSignatureJSON :: Property
testSerializeSignatureJSON = forAllSK $ \sk d ->
    let sig = sign (BS.pack d) sk
    in  Just sig === AE.decode (AE.encode sig)

testSerializeProofJSON :: Property
testSerializeProofJSON = forAllSK $ \sk d -> monadicIO $ do
    proof <- run (proveKnowledgeOfSK (BS.pack d) sk)
    return $ Just proof === AE.decode (AE.encode proof)

tests :: Spec
tests = describe "Concordium.Crypto.BlsSignature" $ do
    it "bls_key_collision" $ withMaxSuccess 10000 $ testKeyCollision
    it "bls_signature_collision" $ withMaxSuccess 10000 $ testNoSignatureCollision
    it "bls_sign_and_verify" $ withMaxSuccess 10000 $ testSignAndVerify
    it "bls_sign_and_verify_collision" $ withMaxSuccess 10000 $ testSignAndVerifyCollision
    it "bls_serialize_sk" $ withMaxSuccess 10000 $ testSerializeSecretKey
    it "bls_serialize_pk" $ withMaxSuccess 10000 $ testSerializePublicKey
    it "bls_serialize_sig" $ withMaxSuccess 10000 $ testSerializeSignature
    it "bls_json_pk" $ withMaxSuccess 10000 $ testSerializePublicKeyJSON
    it "bls_json_sk" $ withMaxSuccess 10000 $ testSerializeSecretKeyJSON
    it "bls_json_sig" $ withMaxSuccess 10000 $ testSerializeSignatureJSON
    it "bls_serialize_proof" $ withMaxSuccess 10000 $ testSerializeProof
    it "bls_json_proof" $ withMaxSuccess 10000 $ testSerializeProofJSON
    it "bls_proof_sound" $ withMaxSuccess 10000 $ testProofSoundness
    it "bls_proof_no_context_collision" $ withMaxSuccess 10000 $ testProofNoContextCollision
    it "bls_wrong_proof" $ withMaxSuccess 10000 $ testProofWrongKey
