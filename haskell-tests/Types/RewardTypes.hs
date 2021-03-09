{-# LANGUAGE OverloadedStrings #-}
module Types.RewardTypes where

import qualified Data.ByteString.Lazy as LBS
import qualified Data.Aeson as AE
import Test.Hspec
import Test.QuickCheck as QC

import Concordium.Types

genRewardFraction :: Gen RewardFraction
genRewardFraction = makeRewardFraction <$> arbitrary `suchThat` (<= 100000)

testRewardFractionToFromJSON :: Property
testRewardFractionToFromJSON = forAll genRewardFraction check
    where
        check f = AE.decode (AE.encode f) === Just f

rewardFractionExamples :: [(LBS.ByteString, Maybe RewardFraction)]
rewardFractionExamples = [
    ("0", Just $ RewardFraction 0),
    ("1", Just $ RewardFraction 100000),
    ("0.12345", Just $ RewardFraction 12345),
    ("0.123456", Nothing),
    ("2", Nothing)
    ]

testRewardFractionExamples :: Expectation
testRewardFractionExamples = mapM_ testEx rewardFractionExamples
    where
        testEx (s, e) = AE.decode s `shouldBe` e

tests :: Spec
tests = describe "Reward fraction" $ do
    specify "Reward fraction examples" testRewardFractionExamples
    specify "Reward fraction to-from JSON" $ withMaxSuccess 10000 testRewardFractionToFromJSON
