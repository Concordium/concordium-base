module ConcordiumTests.Crypto.Signature where

import qualified Concordium.Crypto.Signature as Sig

import Data.Serialize
import qualified Data.ByteString as BS
import Data.Word
import Test.QuickCheck
import Test.Hspec

testSerializeSignKey :: Property
testSerializeSignKey = property $ ck
    where
        ck :: Sig.KeyPair -> Property
        ck kp = Right (Sig.signKey kp) === runGet get (runPut $ put (Sig.signKey kp))

testSerializeVerifyKey :: Property
testSerializeVerifyKey = property $ ck
    where
        ck :: Sig.KeyPair -> Property
        ck kp = Right (Sig.verifyKey kp) === runGet get (runPut $ put (Sig.verifyKey kp))

testSerializeKeyPair :: Property
testSerializeKeyPair = property $ ck
    where
        ck :: Sig.KeyPair -> Property
        ck kp = Right kp === runGet get (runPut $ put kp)

testSerializeSignature :: Property
testSerializeSignature = property $ ck
    where
        ck :: Sig.KeyPair -> [Word8] -> Property
        ck kp doc0 = let doc = BS.pack doc0 in
                        let sig = Sig.sign kp doc in
                            Right sig === runGet get (runPut $ put sig)

testNoDocCollision :: Property
testNoDocCollision = property $ \kp d1 d2 -> d1 /= d2 ==> Sig.sign kp (BS.pack d1) /= Sig.sign kp (BS.pack d2)

testNoKeyPairCollision :: Property
testNoKeyPairCollision = property $ \kp1 kp2 d -> kp1 /= kp2 ==> Sig.sign kp1 (BS.pack d) /= Sig.sign kp2 (BS.pack d)

testSignVerify :: Property
testSignVerify = property $ ck
    where
        ck :: Sig.KeyPair -> [Word8] -> Bool
        ck kp doc0 = let doc = BS.pack doc0 in
                        Sig.verify (Sig.verifyKey kp) doc (Sig.sign kp doc)

tests :: Spec
tests = parallel $ describe "Concordium.Crypto.Signature" $ do
            describe "serialization" $ do
                it "sign key" $ testSerializeSignKey
                it "verify key" $ testSerializeVerifyKey
                it "key pair" $ testSerializeKeyPair
                it "signature" $ testSerializeSignature
            it "verify signature" $ withMaxSuccess 10000 $ testSignVerify
            it "no collision on document" $ withMaxSuccess 10000 $ testNoDocCollision
            it "no collision on key pair" $ withMaxSuccess 10000 $ testNoKeyPairCollision
