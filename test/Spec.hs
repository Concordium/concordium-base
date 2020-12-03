module Main where

import qualified Types.PayloadSerializationSpec
import qualified Types.TransactionSerializationSpec
import qualified Types.AmountSpec
import qualified Types.UpdatesSpec
import qualified Types.AccountEncryptedAmountSpec
import qualified Types.RewardTypes
import Test.Hspec

main :: IO ()
main = hspec $ parallel $ do
         Types.PayloadSerializationSpec.tests
         Types.TransactionSerializationSpec.tests
         Types.AmountSpec.tests
         Types.UpdatesSpec.tests
         Types.AccountEncryptedAmountSpec.tests
         Types.RewardTypes.tests
