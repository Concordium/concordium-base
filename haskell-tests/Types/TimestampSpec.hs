{-# LANGUAGE OverloadedStrings #-}

-- | Basic JSON serialization and deserialization tests for 'Timestamp'.
module Types.TimestampSpec where

import Control.Monad
import qualified Data.Aeson as AE
import qualified Data.ByteString.Lazy as LBS
import Test.Hspec
import Test.QuickCheck

import Concordium.Common.Time

import Generators

testEncodeDecode :: Property
testEncodeDecode = forAll genTimestamp $ \ts -> AE.decode (AE.encode ts) === Just ts

decodeExamples :: [(LBS.ByteString, Maybe Timestamp)]
decodeExamples =
    [ ("0", Just $ Timestamp 0),
      ("1", Just $ Timestamp 1),
      ("1.0", Just $ Timestamp 1),
      ("-2", Nothing),
      ("-2e5", Nothing),
      ("\"10\"", Just $ Timestamp 10),
      ("\"1.0\"", Nothing),
      ("\"2024-12-07T15:00:00.726Z\"", Just $ Timestamp 1733583600726),
      ("\"2024-12-07T15:00:00.726+00:00\"", Just $ Timestamp 1733583600726),
      ("\"2024-12-07T15:00:00.726+01:00\"", Just $ Timestamp 1733580000726),
      ("\"2024-12-07T15:00:00.726-01:00\"", Just $ Timestamp 1733587200726)
    ]

testExamples :: Expectation
testExamples = mapM_ testEx decodeExamples
  where
    testEx (s, e) =
        let p = AE.decode s
        in  unless (p == e) $
                expectationFailure $
                    "Parsing " ++ show s ++ " expected " ++ show e ++ " but got " ++ show p

tests :: Spec
tests = describe "Timestamp" $ parallel $ do
    specify "Timestamp JSON serialization" $ withMaxSuccess 1000 $ testEncodeDecode
    specify "Timestamp JSON examples" $ testExamples
