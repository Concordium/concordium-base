module Types.AmountSpec where

import Test.Hspec
import Test.QuickCheck as QC

import Types.CoreAllGen
import Concordium.Types

checkAmountString :: Amount -> Property
checkAmountString s = let ma = amountFromString (amountToString s)
                      in case ma of
                        Just a -> a === s
                        Nothing -> QC.property False

testAmountString :: Property
testAmountString = forAll genAmount checkAmountString

tests :: Spec
tests = parallel $ do
  specify "Amount string parsing" $ withMaxSuccess 10000 $ testAmountString
