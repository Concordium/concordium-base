module ConcordiumTests.Crypto.SigmaProtocols.DLogBLS12G1 where

import Concordium.Crypto.SigmaProtocols.DLogOverBLS12381G1
import Concordium.Crypto.Curve
import Test.QuickCheck
import Test.Hspec

import Data.Proxy

import Test.QuickCheck.Monadic
import Control.Monad

testSerialization :: Property
testSerialization =
  conjoin $ replicate 10 test
  where test =
          monadicIO $ do

          public <- run generateGroupElem
          secret <- run $ generateFieldElem (Proxy :: Proxy G1)
          base <- run generateGroupElem
          proof <- run $ prove public secret base

          case getProof (putProof proof) :: Maybe (DLogProof G1) of
            Nothing -> fail "Cannot deserialize proof."
            Just proof' -> return (putProof proof' === putProof proof)

testNonDeterminism :: Property
testNonDeterminism =
  conjoin $ replicate 10 test
  where test =
          monadicIO $ do

          public <- run generateGroupElem
          secret <- run $ generateFieldElem (Proxy :: Proxy G1)
          base <- run generateGroupElem
          proof <- run $ prove public secret base
          proof' <- run $ prove public secret base
          when (putProof proof' == putProof proof)
              $ fail "Proving twice generates the same proof. This should very unlikely."


testVerify :: Property
testVerify =
  conjoin $ replicate 10 test
  where test =
          monadicIO $ do

          secret <- run $ generateFieldElem (Proxy :: Proxy G1)
          base <- run generateGroupElem
          let public = derivePublic base secret
          proof <- run $ prove public secret base
          let r = verify base public proof
          unless r
              $ fail "Failed to verify generated proof."
          public' <- run $ generateGroupElem
          when (verify base public' proof)
              $ fail "Verification with random public info succeeded."

tests :: Spec
tests = describe "Concordium.Crypto.SigmaProtocols.DLog.G1" $ do
            specify "Generation and serialization of proofs over" $
              withMaxSuccess 100 testSerialization

            specify "Proofs are nondeterministic" $
              withMaxSuccess 100 testNonDeterminism

            specify "Verify succeeds, and verify with random public fails" $
              withMaxSuccess 100 testVerify
