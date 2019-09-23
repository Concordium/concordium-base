module ConcordiumTests.Crypto.BlsSignature where

import Concordium.Crypto.BlsSignature
import qualified Data.ByteString as BS
import Test.QuickCheck
import Test.Hspec
import System.Random
import Data.Serialize

genSecretKey :: Gen BlsSecretKey
genSecretKey = fst . randomSecretKey . mkStdGen <$> arbitrary

randomSecretKey :: RandomGen g => g -> (BlsSecretKey, g)
randomSecretKey gen = (sk, gen')
  where
    (nextSeed, gen') = random gen
    sk = generateBlsSecretKeyFromSeed nextSeed

genKeyPair :: Gen (BlsSecretKey, BlsPublicKey)
genKeyPair =
  let gen = randomSecretKey . mkStdGen
  in makePair . fst . gen <$> arbitrary
    where
      makePair :: BlsSecretKey -> (BlsSecretKey, BlsPublicKey)
      makePair sk = (sk, deriveBlsPublicKey sk)

forAllSK :: Testable prop => (BlsSecretKey -> prop) -> Property
forAllSK = forAll genSecretKey

forAllKP :: Testable prop => ((BlsSecretKey, BlsPublicKey) -> prop) -> Property
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
    in not (verify (BS.pack m1) pk sig2 or verify (BS.pack m2) pk sig1)

testSerializeSecretKey :: Property
testSerializeSecretKey = forAllSK $ \sk ->
  Right sk === runGet get (runPut $ put sk)

testSerializePublicKey :: Property
testSerializePublicKey = forAllKP $ \(_, pk) ->
  Right pk === runGet get (runPut $ put pk)

testSerializeSignature :: Property
testSerializeSignature = forAllSK $ \sk d ->
  let sig = sign (BS.pack d) sk in
  Right sig === runGet get (runPut $ put sig)

tests :: Spec
tests = describe "Concordium.Crypto.BlsSignature" $ do
            it "bls_key_collision" $ withMaxSuccess 10000 $ testKeyCollision
            it "bls_signature_collision" $ withMaxSuccess 10000 $ testNoSignatureCollision
            it "bls_sign_and_verify" $ withMaxSuccess 10000 $ testSignAndVerify
            it "bls_sign_and_verify_collision" $ withMaxSuccess 10000 $ testSignAndVerifyCollision
            it "bls_serialize_sk" $ withMaxSuccess 10000 $ testSerializeSecretKey
            it "bls_serialize_pk" $ withMaxSuccess 10000 $ testSerializePublicKey
            it "bls_serialize_sig" $ withMaxSuccess 10000 $ testSerializeSignature
