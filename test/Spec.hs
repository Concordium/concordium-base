module Main where

import qualified Types.PayloadSerializationSpec(tests)
import qualified Types.TransactionSerializationSpec(tests)

import Test.Hspec

main :: IO ()
main = hspec $ parallel $ do
         Types.PayloadSerializationSpec.tests
         Types.TransactionSerializationSpec.tests
