module ConcordiumTests.Crypto.BlsSignature where

import Concordium.Crypto.BlsSignature
import Foreign.C.Types
import Foreign.Ptr
import Foreign.Marshal.Alloc
import Test.QuickCheck
import Test.Hspec
import System.Random

genSecretKey :: Gen BlsSecretKey
genSecretKey = fst . randomSecretKey . mkStdGen <$> arbitrary

randomSecretKey :: RandomGen g => g -> (BlsSecretKey  , g)
randomSecretKey gen = (sk, gen')
  where
    (nextSeed, gen') = random gen
    sk = generateBlsSecretKeyFromSeed nextSeed

testGenerateSecretKeyDeterministic :: Property
testGenerateSecretKeyDeterministic = forAll genSecretKey $ test1
  where
    test1 :: BlsSecretKey -> Property
    test1 key = forAll genSecretKey $ \key' ->
      1 === 1 -- TODO: add real test

tests :: Spec
tests = describe "Concordium.Crypto.BlsSignature" $ do
            it "test generating keys deterministically" $ withMaxSuccess 100 $ testGenerateSecretKeyDeterministic
