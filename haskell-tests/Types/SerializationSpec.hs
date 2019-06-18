{-# LANGUAGE OverloadedStrings #-}
module Types.SerializationSpec where

import Test.Hspec

import Test.QuickCheck as QC

import Types.CoreAllGen

import Concordium.Types.Acorn.Core
import Concordium.Types

import qualified Data.Serialize.Put as P
import qualified Data.Serialize.Get as G

import Data.Aeson as AE

import Data.ByteString.Lazy as BS    
import Data.Int

import Types.CoreAllGen(genCAddress)


groupIntoSize :: Int64 -> [Char]
groupIntoSize s =
  let kb = s `div` 1000
      nd = if kb > 0 then truncate (logBase 10 (fromIntegral kb)) else 0
  in if nd == 0 then show kb ++ "kB"
     else let lb = 10^nd
              ub = 10^(nd+1)
          in show lb ++ " -- " ++ show ub ++ "kB"

-- check that getExpr is left inverse of putExpr
checkExpr :: Expr ModuleName -> Property
checkExpr e = let bs = P.runPutLazy (putExpr e)
              in  case G.runGetLazy getExpr bs of
                    Left err -> counterexample err False
                    Right e' -> label (groupIntoSize (BS.length bs)) $ e === e'

-- check that getModule is left inverse of putModule
checkModule :: Module -> Property
checkModule e = let bs = P.runPutLazy (putModule e)
                in  case G.runGetLazy getModule bs of
                      Left err -> counterexample err False
                      Right e' -> label (groupIntoSize (BS.length bs)) $ e === e'


testExpr :: Int -> Spec
testExpr size = do
  specify ("Expression serialization with size " ++ show size ++ ":") $
    forAll (resize size $ genExpr) checkExpr

testModule :: Int -> Spec
testModule size = do
  specify ("Module serialization with size " ++ show size ++ ":") $
    forAll (resize size $ genModule) checkModule

checkContractAddress :: ContractAddress -> Property
checkContractAddress c =
  let bs = AE.encode c
  in case AE.eitherDecode bs :: Either String ContractAddress of
       Left err -> counterexample err False
       Right c' -> c === c'

testContractAddress :: Spec
testContractAddress = do
  specify "Contract address serialization" $
    forAll genCAddress checkContractAddress
