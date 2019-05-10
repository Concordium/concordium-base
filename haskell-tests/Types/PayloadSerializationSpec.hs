module Types.PayloadSerializationSpec where

import Test.Hspec
import Test.Hspec.QuickCheck

import Test.QuickCheck

import qualified Data.Serialize.Put as P
import qualified Data.Serialize.Get as G
import Data.ByteString.Lazy as BSL
import Data.ByteString as BS
import System.Random

import qualified Concordium.ID.AccountHolder as AH
import Concordium.Crypto.SignatureScheme(KeyPair, SchemeId(Ed25519), verifyKey)
import Concordium.Crypto.Ed25519Signature(randomKeyPair)
import Concordium.Types.Execution
import Concordium.Types(Amount(..), Address(..))

import qualified Data.Serialize as S

import Types.CoreAllGen

genPayload :: Gen Payload
genPayload = oneof [genDeployModule, genInit, genUpdate, genTransfer, genAccount]
  where 
        genAccount = CreateAccount . AH.createAccount . verifyKey . fst . randomKeyPair . mkStdGen <$> arbitrary

        genDeployModule = DeployModule <$> genModule

        genInit = do
          amnt <- Amount <$> arbitrary
          mref <- genModuleRef
          name <- genTyName
          param <- genExpr
          let paramSize = BS.length (S.encode param)
          return $ InitContract amnt mref name param paramSize

        genUpdate = do
          amnt <- Amount <$> arbitrary
          cref <- genCAddress
          msg <- genExpr
          let msgSize = BS.length (S.encode msg)
          return $ Update amnt cref msg msgSize

        genTransfer = do
          a <- oneof [AddressContract <$> genCAddress, AddressAccount <$> genAddress]
          amnt <- Amount <$> arbitrary
          return $ Transfer a amnt

groupIntoSize s =
  let kb = s `div` 1000
      nd = if kb > 0 then truncate (logBase 10 (fromIntegral kb)) else 0
  in if nd == 0 then show kb ++ "kB"
     else let lb = 10^nd
              ub = 10^(nd+1)
          in show lb ++ " -- " ++ show ub ++ "kB"

checkPayload :: Payload -> Property
checkPayload e = let bs = S.encodeLazy e
               in  case S.decodeLazy bs of
                     Left err -> counterexample err False
                     Right e' -> label (groupIntoSize (BSL.length bs)) $ e === e'

tests :: Spec
tests = describe "Payload serialization tests" $ do
           test 25
           test 50
 where test size = modifyMaxSuccess (const 10000) $
                   specify ("Payload serialization with size = " ++ show size ++ ":") $
                   forAll (resize size $ genPayload) checkPayload
