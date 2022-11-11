{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-deprecations #-}

module Types.AccountEncryptedAmountSpec where

import qualified Data.Aeson as AE
import qualified Data.Serialize as S
import Test.Hspec
import Test.QuickCheck as QC

import Generators

testBinarySerialization :: Property
testBinarySerialization = forAll genAccountEncryptedAmount $ \acc ->
    let bs = S.encode acc
    in  Right acc === S.decode bs

testJSONSerialization :: Property
testJSONSerialization = forAll genAccountEncryptedAmount $ \acc ->
    let bs = AE.encode acc
    in  Right acc === AE.eitherDecode bs

tests :: Spec
tests = parallel $ do
    specify "AccountEncryptedAmount binary serialization" $ withMaxSuccess 1000 $ testBinarySerialization
    specify "AccountEncryptedAmount JSON serialization" $ withMaxSuccess 1000 $ testJSONSerialization
