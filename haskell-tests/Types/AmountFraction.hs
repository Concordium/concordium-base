{-# LANGUAGE OverloadedStrings #-}

-- |Test the JSON encoding and decoding of 'AmountFraction'.
module Types.AmountFraction where

import qualified Data.Aeson as AE
import qualified Data.ByteString.Lazy as LBS
import Test.Hspec
import Test.QuickCheck as QC

import Concordium.Types

import Generators

testAmountFractionToFromJSON :: Property
testAmountFractionToFromJSON = forAll genAmountFraction check
  where
    check f = AE.decode (AE.encode f) === Just f

amountFractionExamples :: [(LBS.ByteString, Maybe AmountFraction)]
amountFractionExamples =
    [ ("0", Just $ AmountFraction 0),
      ("1", Just $ AmountFraction 100000),
      ("0.12345", Just $ AmountFraction 12345),
      ("0.123456", Nothing),
      ("2", Nothing)
    ]

testAmountFractionExamples :: Expectation
testAmountFractionExamples = mapM_ testEx amountFractionExamples
  where
    testEx (s, e) = AE.decode s `shouldBe` e

tests :: Spec
tests = describe "Amount fraction" $ do
    specify "Amount fraction examples" testAmountFractionExamples
    specify "Amount fraction to-from JSON" $ withMaxSuccess 10000 testAmountFractionToFromJSON
