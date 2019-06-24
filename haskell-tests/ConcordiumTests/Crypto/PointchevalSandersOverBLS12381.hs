{-# LANGUAGE ScopedTypeVariables #-}
module ConcordiumTests.Crypto.PointchevalSandersOverBLS12381 where

import Concordium.Crypto.PointchevalSandersOverBLS12381

import qualified Data.FixedByteString as FBS

import Test.QuickCheck.Monadic
import Test.QuickCheck
import Test.Hspec
import Test.Hspec.QuickCheck

import Control.Monad

-- check that the commitments can be opened

setup :: Int -> IO (SecretKey, PublicKey, CommitmentKey, Commitment, EncodedValues, Randomness, Signature, Signature)
setup n = do
  secretKey <- newSecretKey n
  let Just publicKey = derivePublicKey n secretKey
  let Just commitmentKey = deriveCommitmentKey n publicKey
  values <- randomValues n
  CommitSuccess commitment randomness <- commitWithPublicKey n publicKey values
  SignSuccess knownMsgSig <- signKnownMessage n secretKey values
  SignSuccess unknownMsgSig <- signUnknownMessage secretKey commitment
  return (secretKey, publicKey, commitmentKey, commitment, values, randomness, knownMsgSig, unknownMsgSig)

genPublicKey :: Int -> IO PublicKey
genPublicKey n = do
  secretKey <- newSecretKey n
  let Just publicKey = derivePublicKey n secretKey
  return publicKey

testCorrectSignature :: Property
testCorrectSignature =
  conjoin . map test $ [1..20]
  where test = \n -> 
          monadicIO $ do
            (_, publicKey, _, _, values, randomness, knownMsgSig, unknownMsgSig) <- run $ setup n
            assert (verifySignature n publicKey knownMsgSig values == VerifySignatureOK)
            let RetrieveSignatureOK retrievedSig = retrieveSignature unknownMsgSig randomness
            let res = verifySignature n publicKey retrievedSig values
            assert (res == VerifySignatureOK)


randomRandomness :: Gen Randomness
randomRandomness = Randomness . FBS.pack <$> vector randomnessSize

randomSignature :: Gen Signature
randomSignature = Signature . FBS.pack <$> vector signatureSize

randomValue :: Gen EncodedValue
randomValue = EncodedValue . FBS.pack <$> vector (FBS.fixedLength (undefined :: ValueSize))

-- Check that the signature of unknown message validates only with
-- correct randomness generated during the commitment phase.
-- TODO: This is currently testing with random values, which is less than ideal
-- since they are not necessarily valid field elements.
testCorrectRandomness :: Int -> PublicKey -> Signature -> Randomness -> EncodedValues -> Property
testCorrectRandomness n publicKey unknownMsgSig targetRandomness values =
  forAll randomRandomness $ \randomness -> targetRandomness /= randomness ==>
                                           let rs = retrieveSignature unknownMsgSig randomness
                                           in rs /= RetrieveRandomnessMalformed ==>
                                             case rs of
                                               RetrieveSignatureOK retrievedSig ->
                                                 let res = verifySignature n publicKey retrievedSig values
                                                 in res === VerifySignatureIncorrect
                                               _ -> counterexample "Retrieving signature failed." False
                                             
                                -- using quickcheck implication ensures that if there are too many
                                -- invalid values for randomness the test will fail.

testCorrectRandomness' :: Int -> Spec
testCorrectRandomness' n = do
  (_, publicKey, _, _, values, randomness, _, unknownMsgSig) <- runIO $ setup n
  specify ("n = " ++ show n) $ testCorrectRandomness n publicKey unknownMsgSig randomness values



-- TODO: THis does not work well because random signatures are not valid group elements.
-- check that verify only succeeds with correct signature
-- testOtherSignature :: Int -> PublicKey -> Signature -> EncodedValues -> Property
-- testOtherSignature n publicKey knownMsgSig  values =
--   forAll randomSignature $
--     \randomSig ->
--       randomSig /= knownMsgSig ==>
--       let res = verifySignature n publicKey randomSig values
--       in res /= VerifySignatureMalformed ==> res === VerifySignatureIncorrect

-- testOtherSignature' :: Int -> Spec
-- testOtherSignature' n = do
--   (_, publicKey, _, _, values, _, knownMsgSig, _) <- runIO $ setup n
--   specify ("n = " ++ show n) $ testOtherSignature n publicKey knownMsgSig values


-- check that verify only succeeds with correct values
testRandomValues :: Int -> PublicKey -> Signature -> Randomness -> EncodedValues -> Property
testRandomValues n publicKey unknownMsgSig randomness targetValues =
  forAll (replicateM n randomValue) $
    \randomVals ->
      targetValues /= randomVals ==>
      let rs = retrieveSignature unknownMsgSig randomness
      in case rs of
           RetrieveSignatureOK retrievedSig ->
               let res = verifySignature n publicKey retrievedSig randomVals
               in res /= VerifyMessageMalformed ==> res === VerifySignatureIncorrect
           _ -> counterexample "Retrieving signature failed where it should not." False
           -- using quickcheck implication ensures that if there are too many
           -- invalid values for randomness the test will fail.

testRandomValues' :: Int -> Spec
testRandomValues' n = do
  (_, publicKey, _, _, values, randomness, _, unknownMsgSig) <- runIO $ setup n
  specify ("n = " ++ show n) $ testRandomValues n publicKey unknownMsgSig randomness values

tests :: Spec
tests = parallel $
  describe "Crypto.PointchevalSandersOverBLS12381" $ do
    describe "Correct signatures validate." $ 
      forM_ [1..10] $ \n ->
      replicateM_ 10 $ do
      (_, publicKey, _, _, values, randomness, knownMsgSig, unknownMsgSig) <- runIO $ setup n
      specify ("Signature of known message checks out, n = " ++ show n) $
          verifySignature n publicKey knownMsgSig values `shouldBe` VerifySignatureOK
      let RetrieveSignatureOK retrievedSig = retrieveSignature unknownMsgSig randomness
      specify ("Signature of unknown message, retrieved, checks out, n = " ++ show n) $
          verifySignature n publicKey retrievedSig values `shouldBe` VerifySignatureOK

    modifyMaxSuccess (const 500) $ describe "Signature only validates with correct randomness." $
      mapM_ testCorrectRandomness' [1..11]
    -- modifyMaxSuccess (const 500) $ describe "Signature cannot be changed." $
    --   mapM_ testOtherSignature' [1..11]
    modifyMaxSuccess (const 500) $ describe "Values cannot be changed with unknown sig." $
      mapM_ testRandomValues' [1..2] -- only go up to 2 because we generate random values and probablity of generating valid ones diminishes quickly

    describe "Changing public key invalidates signature of known message." $ do
      forM_ [1..10] $ \n -> do
      (_, publicKey, _, _, values, _, knownMsgSig, _) <- runIO $ setup n
      publicKey' <- runIO $ genPublicKey n
      when (publicKey /= publicKey') $
        specify ("Different public keys, verify should fail, n = " ++ show n) $
        verifySignature n publicKey' knownMsgSig values `shouldBe` VerifySignatureIncorrect

    describe "Changing public key invalidates signature of unknown message." $ do
      forM_ [1..10] $ \n -> do
      (_, publicKey, _, _, values, randomness, _, unknownMsgSig) <- runIO $ setup n
      publicKey' <- runIO $ genPublicKey n
      when (publicKey /= publicKey') $
        specify ("Different public keys, verify should fail, n = " ++ show n) $
        let RetrieveSignatureOK retrievedSig = retrieveSignature unknownMsgSig randomness
        in verifySignature n publicKey' retrievedSig values `shouldBe` VerifySignatureIncorrect
