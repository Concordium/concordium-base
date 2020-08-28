module Main where

import qualified Types.PayloadSerializationSpec
import qualified Types.TransactionSerializationSpec
import qualified Types.AmountSpec

import Test.Hspec

main :: IO ()
main = hspec $ parallel $ do
         Types.PayloadSerializationSpec.tests
         Types.TransactionSerializationSpec.tests
         Types.AmountSpec.tests
