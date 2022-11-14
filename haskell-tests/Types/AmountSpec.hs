{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}

module Types.AmountSpec where

import Control.Monad
import qualified Data.Aeson as AE
import Test.Hspec
import Test.QuickCheck as QC

import Concordium.Types

import Generators (genAmount)

checkAmountString :: Amount -> Property
checkAmountString s =
    let ma = amountFromString (amountToString s)
    in  case ma of
            Just a -> a === s
            Nothing -> QC.property False

testAmountString :: Property
testAmountString = forAll genAmount checkAmountString

amountExamples :: [(String, Maybe Amount)]
amountExamples =
    [ ("0", Just 0),
      ("-2", Nothing),
      ("0.00000", Just 0),
      ("0.1", Just 100_000),
      ("1", Just 1_000_000),
      ("0.123456", Just 123_456),
      ("000002", Just 2_000_000),
      ("18446744073709.551615", Just 18446744073709551615),
      ("018446744073709.551615", Just 18446744073709551615),
      ("18446744073709.551616", Nothing),
      ("018446744073709.551616", Nothing),
      ("18446744173709.551615", Nothing),
      ("18446744073709551615", Nothing),
      ("5.", Nothing),
      (".5", Nothing),
      ("0.", Nothing),
      ("0 ", Nothing),
      (" 1", Nothing),
      ("2,3", Nothing),
      ("1.3.4", Nothing),
      ("1..02", Nothing),
      ("1.2345678", Nothing),
      ("1.2345670", Nothing)
    ]

testAmountFromStringExamples :: Expectation
testAmountFromStringExamples = mapM_ testEx amountExamples
  where
    testEx (s, e) =
        let p = amountFromString s
        in  unless (p == e) $
                expectationFailure $
                    "Parsing " ++ show s ++ " expected " ++ show e ++ " but got " ++ show p

testAmountToAndFromJson :: Spec
testAmountToAndFromJson = describe "Amount to and from JSON" $ do
    specify "Can decode valid format" $ AE.decode "\"1234\"" `shouldBe` Just Amount{_amount = 1234}
    specify "Cannot decode invalid format" $ AE.decode "\"1.\"" `shouldBe` (Nothing :: Maybe Amount)
    specify "Cannot decode invalid type" $ AE.decode "12.34" `shouldBe` (Nothing :: Maybe Amount)
    specify "Cannot decode overflowing value" $ AE.decode "\"123123145131252352352312415\"" `shouldBe` (Nothing :: Maybe Amount)
    specify "Can encode amount" $ AE.encode Amount{_amount = 1234567890} `shouldBe` "\"1234567890\""

tests :: Spec
tests = do
    specify "Amount string parsing" $ withMaxSuccess 10000 $ testAmountString
    specify "Amount parsing examples" testAmountFromStringExamples
    testAmountToAndFromJson
