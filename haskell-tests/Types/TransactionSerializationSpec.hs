module Types.TransactionSerializationSpec where


import Test.Hspec
import Test.QuickCheck as QC

import Data.Serialize

import qualified Data.ByteString as  BS

import Types.TransactionGen
import Types.CoreAllGen
import Concordium.Types
import Concordium.Types.Transactions

groupIntoSize :: (Show a, Integral a) => a -> String
groupIntoSize s = 
  let kb = s
      nd = if kb > 0 then truncate (logBase 10 (fromIntegral kb) :: Double) else 0 :: Int
  in if nd == 0 then show kb ++ "B"
     else let lb = 10^nd :: Integer
              ub = 10^(nd+1) :: Integer
          in show lb ++ " -- " ++ show ub ++ "B"

checkTransaction :: BareTransaction -> Property
checkTransaction tx = let bs = encode tx
              in  case decode bs of
                    Left err -> counterexample err False
                    Right tx' -> QC.label (groupIntoSize (BS.length bs)) $ tx === tx'

testTransaction :: Int -> Property
testTransaction size = forAll (resize size genBareTransaction) checkTransaction

dummyTime :: TransactionTime
dummyTime = 37

-- |Check V0 serialization of block items.
checkBlockItem :: BlockItem -> Property
checkBlockItem bi = 
    case runGet (getBlockItemV0 (wmdArrivalTime bi)) bs of
      Left err -> counterexample err False
      Right bi' -> QC.label (groupIntoSize (BS.length bs)) $ bi === bi'
  where
    bs = encode $ wmdData bi

testBlockItem :: Property
testBlockItem = forAll genBlockItem checkBlockItem

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
  specify "Transaction serialization with size = 100." $ withMaxSuccess 10000 $ testTransaction 100
  specify "Transaction serialization with size = 1000." $ withMaxSuccess 10000 $ testTransaction 1000
  specify "BlockItem serialization." $ withMaxSuccess 10000 $ testBlockItem
