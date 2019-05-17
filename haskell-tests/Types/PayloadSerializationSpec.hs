{-# LANGUAGE RecordWildCards #-}
module Types.PayloadSerializationSpec where

import Test.Hspec
import Test.Hspec.QuickCheck

import Test.QuickCheck

import qualified Data.Serialize.Put as P
import qualified Data.Serialize.Get as G
import Data.ByteString.Lazy as BSL
import Data.ByteString as BS
import System.Random

import qualified Concordium.ID.Account as AH
import Concordium.Crypto.SignatureScheme(KeyPair, VerifyKey(..), SchemeId(Ed25519), verifyKey)
import Concordium.Crypto.Ed25519Signature(randomKeyPair)
import Concordium.Types.Execution
import Concordium.Types(Amount(..), Address(..))
import Concordium.ID.Types
import Concordium.ID.Attributes

import qualified Data.Serialize as S

import Types.CoreAllGen

import Control.Monad

genCredentialDeploymentInformation :: Gen CredentialDeploymentInformation
genCredentialDeploymentInformation = do
  cdi_verifKey <- VerifyKey . BS.pack <$> vector 37
  cdi_sigScheme <- elements [Ed25519]
  cdi_regId <- RegIdCred . BS.pack <$> vector credentialRegistrationIDSize
  cdi_arData <- do l <- choose (0, 10)
                   replicateM l $ do arId <- AR_ID . BS.pack <$> vector 73
                                     secretShare <- Share . BS.pack <$> vector 37
                                     return (arId, secretShare)
  cdi_ipId <- IP_ID . BS.pack <$> vector 53
  cdi_policy <- elements [AtomicBD AgeOver18]
  cdi_auxData <- BS.pack <$> (vector =<< choose (0, 1000))
  cdi_proof <- choose (10, 1000) >>= \s -> Proof . BS.pack <$> vector s
  return CDI{..}

genPayload :: Gen Payload
genPayload = oneof [genDeployModule, genInit, genUpdate, genTransfer, genAccount, genCredential]
  where 
        genAccount = CreateAccount . AH.createAccount . verifyKey . fst . randomKeyPair . mkStdGen <$> arbitrary

        genCredential = DeployCredential <$> genCredentialDeploymentInformation

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
           test 25 5000
           test 50 500
 where test size num = modifyMaxSuccess (const num) $
                       specify ("Payload serialization with size = " ++ show size ++ ":") $
                       forAll (resize size $ genPayload) checkPayload
