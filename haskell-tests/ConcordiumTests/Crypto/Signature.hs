module ConcordiumTests.Crypto.Signature where

import qualified Concordium.Crypto.Signature as Sig

import Data.Serialize
import qualified Data.ByteString as BS
import Data.Word
import Test.QuickCheck
import Test.Hspec
import System.Random

instance Arbitrary Sig.KeyPair where
    arbitrary = do
        seed <- arbitrary
        return $ fst $ Sig.randomKeyPair (mkStdGen seed)

testSerializeSignKey :: Property
testSerializeSignKey = property $ ck
    where
        ck :: Sig.KeyPair -> Bool
        ck kp = Right (Sig.signKey kp) == runGet get (runPut $ put (Sig.signKey kp))

testSerializeVerifyKey :: Property
testSerializeVerifyKey = property $ ck
    where
        ck :: Sig.KeyPair -> Bool
        ck kp = Right (Sig.verifyKey kp) == runGet get (runPut $ put (Sig.verifyKey kp))

testSerializeKeyPair :: Property
testSerializeKeyPair = property $ ck
    where
        ck :: Sig.KeyPair -> Bool
        ck kp = Right kp == runGet get (runPut $ put kp)

testSerializeSignature :: Property
testSerializeSignature = property $ ck
    where
        ck :: Sig.KeyPair -> [Word8] -> Bool
        ck kp doc0 = let doc = BS.pack doc0 in
                        let sig = Sig.sign kp doc in
                            Right sig == runGet get (runPut $ put sig)

tests = parallel $ describe "Concordium.Crypto.SHA256" $ do
            describe "serialization" $ do
                it "sign key" $ testSerializeSignKey
                it "verify key" $ testSerializeVerifyKey
                it "key pair" $ testSerializeKeyPair
                it "signature" $ testSerializeSignature
