{-# LANGUAGE ScopedTypeVariables #-}
module ConcordiumTests.Crypto.PedersenOverBLS12G2 where

import Concordium.Crypto.PedersenOverBLS12G2

import qualified Data.FixedByteString as FBS

import Data.Serialize

import Test.QuickCheck.Monadic
import Test.QuickCheck
import Test.Hspec
import Test.Hspec.QuickCheck

import Control.Monad

-- check that the commitments can be opened

setup :: Int -> IO (CommitmentKey, Values, Commitment, Randomness)
setup n = do
  commitmentKey <- newCommitmentKey n
  values <- randomValues n
  CommitSuccess commitment randomness <- commit commitmentKey values
  return (commitmentKey, values, commitment, randomness)


testCorrectCommitment :: Property
testCorrectCommitment =
  conjoin . map test $ [1..11]
  where test = \n -> 
          monadicIO $ do
            (commitmentKey, values, commitment, randomness) <- run $ setup n
            assert (open commitmentKey randomness values commitment == OK)

randomRandomness :: Gen Randomness
randomRandomness = Randomness . FBS.pack <$> vector randomnessSize

randomValue :: Gen Value
randomValue = Value . FBS.pack <$> vector (FBS.fixedLength (undefined :: ValueSize))

-- Check that the commitment can only be validated with randomness that was
-- generated during the commitment phase.
-- TODO: This is currently testing with random values, which is less than ideal
-- since they are not necessarily valid group elements.
testCorrectRandomness :: CommitmentKey -> Randomness -> Values -> Commitment -> Property
testCorrectRandomness commitmentKey targetRandomness values commitment =
  forAll randomRandomness $ \randomness -> targetRandomness /= randomness ==> let res = open commitmentKey randomness values commitment
                                                                              in res /= InvalidRandomness ==> res === Reject
                                -- using quickcheck implication ensures that if there are too many
                                -- invalid values for randomness the test will fail.

testCorrectRandomness' :: Int -> Spec
testCorrectRandomness' n = do
  (commitmentKey, values, commitment, targetRandomness) <- runIO $ setup n
  specify ("n = " ++ show n) $ testCorrectRandomness commitmentKey targetRandomness values commitment

shortListOf :: Gen a -> Gen [a]
shortListOf gen = do
  n <- choose (0,11)
  replicateM n gen

-- Check that if the commited value changes then opening a commitment will fail.
-- TODO: This is currently testing with random values, which is less than ideal
-- since they are not necessarily valid group elements.
testCommitedValueChange :: CommitmentKey -> Randomness -> Values -> Commitment -> Int -> Property
testCommitedValueChange commitmentKey randomness targetValues commitment n =
  monadicIO $ do
     values <- run $ randomValues n
     return $ targetValues /= values ==> let res = open commitmentKey randomness values commitment
                                         in res /= InvalidValues ==> res === Reject

testCommitedValueChange' :: Int -> Spec
testCommitedValueChange' n = do
  (commitmentKey, targetValues, commitment, randomness) <- runIO $ (setup n)
  specify ("n = " ++ show n) $ testCommitedValueChange commitmentKey randomness targetValues commitment n



randomCommitment :: Gen Commitment
randomCommitment = Commitment . FBS.pack <$> vector (FBS.fixedLength (undefined :: CommitmentSize))

testSerializeCommitment :: Property
testSerializeCommitment =
  forAll randomCommitment $ \commitment -> Right commitment === runGet get (runPut $ put $ commitment)

testSerializeValues :: Property
testSerializeValues =
  forAll (shortListOf randomValue) $ \vals -> Right vals === runGet get (runPut $ put $ vals)

testSerializeRandomness :: Property
testSerializeRandomness =
  forAll randomRandomness $ \rand -> Right rand === runGet get (runPut $ put $ rand)

tests :: Spec
tests = modifyMaxSuccess (const 500) $ 
  describe "Crypto.PedersenOverBLS12G2" $ do
    describe "Serialization" $ do
      specify "Serialization of commitments" testSerializeCommitment
      specify "Serialization of values" testSerializeValues
      specify "Serialization of randomness" testSerializeRandomness

    modifyMaxSuccess (const 100) (specify "Commitments can be opened." testCorrectCommitment)

    describe "Commitments only validate with correct randomness." $
        mapM_ testCorrectRandomness' [1..11]

    describe "Commitments only validate with commited values." $
        mapM_ testCommitedValueChange' [1..11]
