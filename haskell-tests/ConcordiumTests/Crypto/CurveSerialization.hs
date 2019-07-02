{-# LANGUAGE ScopedTypeVariables #-}
module ConcordiumTests.Crypto.CurveSerialization where

import Concordium.Crypto.Curve
import Test.QuickCheck
import Test.Hspec

import Data.Proxy
import Data.Serialize

import Test.QuickCheck.Monadic

testSerialization :: forall a . (Serialize a, Show a) => IO a -> Property
testSerialization gen =
  conjoin $ replicate 10 test
  where test =
          monadicIO $ do
          g <- run gen
          case decode (encode g) :: Either String a of
            Left err -> fail err
            Right g' -> return (encode g === encode g')

tests :: Spec
tests = describe "Concordium.Crypto.Curve" $ do
            specify "Serialization of G1 group of BLS" $
              withMaxSuccess 100 (testSerialization (generateGroupElem :: IO (GroupElement G1)))
            specify "Serialization of BLS group field elements" $
              withMaxSuccess 100 (testSerialization (generateFieldElem (Proxy :: Proxy G1)))
