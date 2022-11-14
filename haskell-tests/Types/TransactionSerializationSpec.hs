module Types.TransactionSerializationSpec where

import Test.Hspec
import Test.QuickCheck as QC

import Data.Serialize

import qualified Data.ByteString as BS

import Concordium.Types
import Concordium.Types.Transactions
import Generators

groupIntoSize :: (Show a, Integral a) => a -> String
groupIntoSize s =
    let kb = s
        nd = if kb > 0 then truncate (logBase 10 (fromIntegral kb) :: Double) else 0 :: Int
    in  if nd == 0
            then show kb ++ "B"
            else
                let lb = 10 ^ nd :: Integer
                    ub = 10 ^ (nd + 1) :: Integer
                in  show lb ++ " -- " ++ show ub ++ "B"

-- |Check that a transaction can be serialized and deserialized.
checkTransaction :: AccountTransaction -> Property
checkTransaction tx =
    let bs = encode tx
    in  case decode bs of
            Left err -> counterexample err False
            Right tx' -> QC.label (groupIntoSize (BS.length bs)) $ tx === tx'

testTransaction :: Int -> Property
testTransaction size = forAll (resize size genAccountTransaction) checkTransaction

dummyTime :: TransactionTime
dummyTime = 37

-- |Check V0 serialization of block items.
checkBlockItem :: SProtocolVersion pv -> BlockItem -> Property
checkBlockItem spv bi =
    case runGet (getBlockItemV0 spv (wmdArrivalTime bi)) bs of
        Left err -> counterexample err False
        Right bi' -> QC.label (groupIntoSize (BS.length bs)) $ bi === bi'
  where
    bs = runPut . putBareBlockItemV0 $ wmdData bi

testBlockItem :: SProtocolVersion pv -> Property
testBlockItem spv = forAll genBlockItem $ checkBlockItem spv
tests :: Spec
tests = parallel $ do
    specify "Transaction serialization with size = 100." $ withMaxSuccess 1000 $ testTransaction 100
    specify "Transaction serialization with size = 1000." $ withMaxSuccess 1000 $ testTransaction 1000
    specify "BlockItem serialization in P1." $ withMaxSuccess 1000 $ testBlockItem SP1
    specify "BlockItem serialization in P2." $ withMaxSuccess 1000 $ testBlockItem SP2
    specify "BlockItem serialization in P3." $ withMaxSuccess 1000 $ testBlockItem SP3
    specify "BlockItem serialization in P4." $ withMaxSuccess 1000 $ testBlockItem SP4
