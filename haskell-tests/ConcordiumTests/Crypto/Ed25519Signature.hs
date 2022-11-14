{-# OPTIONS_GHC -Wno-deprecations #-}

module ConcordiumTests.Crypto.Ed25519Signature where

import Concordium.Crypto.DummyData
import Concordium.Crypto.SignatureScheme
import qualified Data.ByteString as BS
import Data.Serialize
import Data.Word
import Test.Hspec
import Test.QuickCheck

forallKP :: Testable prop => (KeyPair -> prop) -> Property
forallKP = forAll (uncurry KeyPairEd25519 <$> genEd25519KeyPair)

testSerializeSignKeyEd25519 :: Property
testSerializeSignKeyEd25519 = forallKP $ ck
  where
    ck :: KeyPair -> Property
    ck kp = Right (signKey kp) === runGet get (runPut $ put (signKey kp))

testSerializeVerifyKeyEd25519 :: Property
testSerializeVerifyKeyEd25519 = forallKP $ ck
  where
    ck :: KeyPair -> Property
    ck kp = Right (verifyKey kp) === runGet get (runPut $ put (verifyKey kp))

testSerializeKeyPairEd25519 :: Property
testSerializeKeyPairEd25519 = forallKP $ ck
  where
    ck :: KeyPair -> Property
    ck kp = Right kp === runGet get (runPut $ put kp)

testSerializeSignatureEd25519 :: Property
testSerializeSignatureEd25519 = forallKP $ ck
  where
    ck :: KeyPair -> [Word8] -> Property
    ck kp doc0 =
        let doc = BS.pack doc0
        in  let sig = sign kp doc
            in  Right sig === runGet get (runPut $ put sig)

testNoDocCollisionEd25519 :: Property
testNoDocCollisionEd25519 = forallKP $ \kp d1 d2 -> d1 /= d2 ==> sign kp (BS.pack d1) /= sign kp (BS.pack d2)

testNoKeyPairCollisionEd25519 :: Property
testNoKeyPairCollisionEd25519 =
    forallKP $
        \kp1 ->
            forallKP $
                \kp2 d -> kp1 /= kp2 ==> sign kp1 (BS.pack d) /= sign kp2 (BS.pack d)

testSignVerifyEd25519 :: Property
testSignVerifyEd25519 = forallKP $ ck
  where
    ck :: KeyPair -> [Word8] -> Bool
    ck kp doc0 =
        let doc = BS.pack doc0
        in  verify (VerifyKeyEd25519 (verifyKey kp)) doc (sign kp doc)

testSignVerifyEd25519DocumentCollision :: Property
testSignVerifyEd25519DocumentCollision = forallKP $ ck
  where
    ck :: KeyPair -> [Word8] -> [Word8] -> Property
    ck kp doc0 doc1 =
        -- check that if we sign doc0 and then check the
        -- signature of doc1, this only succeeds
        -- if doc0 == doc1
        let doc = BS.pack doc0
            sig = sign kp doc
        in  doc0 /= doc1 ==> not (verify (VerifyKeyEd25519 (verifyKey kp)) (BS.pack doc1) sig)

tests :: Spec
tests = describe "Concordium.Crypto.Ed25519Signature" $ do
    describe "serialization" $ do
        it "sign key" $ testSerializeSignKeyEd25519
        it "verify key" $ testSerializeVerifyKeyEd25519
        it "key pair" $ testSerializeKeyPairEd25519
        it "signature" $ testSerializeSignatureEd25519
    it "verify signature" $ withMaxSuccess 10000 $ testSignVerifyEd25519
    it "verify fails when checking different document" $ withMaxSuccess 10000 $ testSignVerifyEd25519DocumentCollision
    it "no collision on document" $ withMaxSuccess 10000 $ testNoDocCollisionEd25519
    it "no collision on key pair" $ withMaxSuccess 10000 $ testNoKeyPairCollisionEd25519
