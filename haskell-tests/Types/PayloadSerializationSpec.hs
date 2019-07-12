{-# LANGUAGE RecordWildCards #-}
module Types.PayloadSerializationSpec where

import Test.Hspec
import Test.Hspec.QuickCheck

import Test.QuickCheck

import Data.ByteString.Lazy as BSL
import Data.ByteString as BS

import Concordium.Types
import Concordium.Crypto.SignatureScheme(VerifyKey(..), SchemeId(Ed25519))
import Concordium.Types.Execution
import Concordium.Types(Amount(..), Address(..))
import Concordium.ID.Types
import qualified Concordium.Crypto.VRF as VRF
import Data.FixedByteString as FBS

import qualified Data.Serialize as S

import Types.CoreAllGen

import Control.Monad

import Data.Int

genCredentialDeploymentInformation :: Gen CredentialDeploymentInformation
genCredentialDeploymentInformation = do
  cdvVerifyKey <- VerifyKey . BS.pack <$> vector 37
  cdvSigScheme <- elements [Ed25519]
  cdvRegId <- RegIdCred . FBS.pack <$> vector (FBS.fixedLength (undefined :: RegIdSize))
  cdvIpId <- IP_ID . BS.pack <$> vector 53
  cdvArData <- do
    ardName <- ARName . BS.pack <$> (vector =<< choose (0,1000))
    ardIdCredPubEnc <- AREnc . BS.pack <$> (vector =<< choose(30,80))
    return AnonymityRevocationData{..}
  cdvPolicy <- do
    l <- choose (0,1000)
    pAttributeListVariant <- arbitrary
    pExpiry <- arbitrary
    pItems <- replicateM l genPolicyItem
    return Policy{..}
  cdiProofs <- do l <- choose (0, 10000)
                  Proofs . BS.pack <$> vector l
  let cdiValues = CredentialDeploymentValues{..}
  return CredentialDeploymentInformation{..}

genPolicyItem :: Gen PolicyItem
genPolicyItem = do
  piIndex <- arbitrary
  piValue <- AttributeValue . FBS.pack <$> vector (FBS.fixedLength (undefined :: AttributeSize))
  return PolicyItem{..}

genPayload :: Gen Payload
genPayload = oneof [genDeployModule,
                    genInit,
                    genUpdate,
                    genTransfer,
                    genCredential,
                    genEncryption,
                    genAddBaker,
                    genRemoveBaker,
                    genUpdateBakerAccount,
                    genUpdateBakerSignKey,
                    genDelegateStake,
                    genUndelegateStake
                    ]
  where 
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

        -- NB: if the encryption key is going to be fixed length this needs to change
        genEncryption = do
          l <- choose (30,50)
          DeployEncryptionKey . EncKeyAcc . BS.pack <$> vector l

        genAddBaker = do
          abElectionVerifyKey <- VRF.publicKey <$> arbitrary
          abSignatureVerifyKey <- VerifyKey . BS.pack <$> (vector =<< choose (30,80))
          abAccount <- genAddress
          abProof <- genProof
          return AddBaker{..}

        genProof = choose (50,200) >>= vector >>= return . BS.pack

        genRemoveBaker = do
          rbId <- genBakerId
          rbProof <- genProof
          return RemoveBaker{..}

        genUpdateBakerAccount = do
          ubaId <- genBakerId
          ubaAddress <- genAddress
          ubaProof <- genProof
          return UpdateBakerAccount{..}

        genUpdateBakerSignKey = do
          ubsId <- genBakerId
          ubsKey <- VerifyKey . BS.pack <$> (vector =<< choose (30,80))
          ubsProof <- genProof
          return UpdateBakerSignKey{..}

        genBakerId = BakerId <$> arbitrary

        genDelegateStake = DelegateStake <$> genBakerId

        genUndelegateStake = return UndelegateStake


groupIntoSize :: Int64 -> [Char]
groupIntoSize s =
  let kb = s `div` 1000
      nd = if kb > 0 then truncate (logBase 10 (fromIntegral kb :: Double)) else 0 :: Int
  in if nd == 0 then show kb ++ "kB"
     else let lb = 10^nd :: Int
              ub = 10^(nd+1) :: Int
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
