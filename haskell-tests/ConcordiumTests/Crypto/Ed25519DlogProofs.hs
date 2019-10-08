module ConcordiumTests.Crypto.Ed25519DlogProofs where

import           Concordium.Crypto.Ed25519Signature
import           Concordium.Crypto.SignatureScheme (KeyPair(..)) 
import qualified Concordium.Crypto.VRF as VRF
import Concordium.Crypto.Proofs
import qualified Data.ByteString as BS
import Data.Word
import Test.QuickCheck
import Test.QuickCheck.Monadic
import Test.Hspec

forallKP :: Testable prop => (KeyPair -> prop) -> Property
forallKP = forAll genKeyPair

forallKPVRF :: Testable prop => (VRF.KeyPair -> prop) -> Property
forallKPVRF = forAll arbitrary


testProveVerifyEd25519 :: Property
testProveVerifyEd25519 = forallKP $ ck
    where
        ck :: KeyPair -> [Word8] -> Property
        ck kp challenge' = monadicIO $ do
          let challenge = BS.pack challenge'
          Just proof <- run (proveDlog25519KP challenge kp)
          return (checkDlog25519ProofSig challenge (verifyKey kp) proof === True)

testProveVerifyWrongChallengeEd25519 :: Property
testProveVerifyWrongChallengeEd25519 = forallKP $ ck
    where
        ck :: KeyPair -> [Word8] -> [Word8] -> Property
        ck kp challenge' challenge1' = monadicIO $ do
          let challenge = BS.pack challenge'
          let challenge1 = BS.pack challenge1'
          Just proof <- run (proveDlog25519KP challenge kp)
          return (challenge /= challenge1 ==> not (checkDlog25519ProofSig challenge1 (verifyKey kp) proof))


testProveVerifyEd25519VRF :: Property
testProveVerifyEd25519VRF = forallKPVRF $ ck
    where
        ck :: VRF.KeyPair -> [Word8] -> Property
        ck kp challenge' = monadicIO $ do
          let challenge = BS.pack challenge'
          Just proof <- run (proveDlog25519VRF challenge kp)
          return (checkDlog25519ProofVRF challenge (VRF.publicKey kp) proof === True)

testProveVerifyWrongChallengeEd25519VRF :: Property
testProveVerifyWrongChallengeEd25519VRF = forallKPVRF $ ck
    where
        ck :: VRF.KeyPair -> [Word8] -> [Word8] -> Property
        ck kp challenge' challenge1' = monadicIO $ do
          let challenge = BS.pack challenge'
          let challenge1 = BS.pack challenge1'
          Just proof <- run (proveDlog25519VRF challenge kp)
          return (challenge /= challenge1 ==> not (checkDlog25519ProofVRF challenge1 (VRF.publicKey kp) proof))

tests :: Spec
tests = describe "Concordium.Crypto.Ed25519Dlog" $ do
            it "verify proof" $ withMaxSuccess 10000 $ testProveVerifyEd25519
            it "proof with incorrenct challenge fails" $ withMaxSuccess 10000 $ testProveVerifyWrongChallengeEd25519
            it "verify proof (VRF)" $ withMaxSuccess 10000 $ testProveVerifyEd25519VRF
            it "proof with incorrenct challenge fails (VRF)" $ withMaxSuccess 10000 $ testProveVerifyWrongChallengeEd25519VRF
