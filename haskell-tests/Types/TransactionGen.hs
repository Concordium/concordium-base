{-# OPTIONS_GHC -Wno-deprecations #-}
module Types.TransactionGen where

import Test.QuickCheck

import Concordium.Types.ProtocolVersion
import Concordium.Types.Transactions
import Concordium.Crypto.SignatureScheme
import Concordium.Crypto.FFIDataTypes
import Data.Time.Clock

import Concordium.Common.Time
import Concordium.Types
import Concordium.Constants
import Concordium.ID.Types
import Concordium.ID.DummyData

import Control.Monad
import qualified Data.Map.Strict as Map
import qualified Data.FixedByteString as FBS
import qualified Data.ByteString.Short as BSS
import System.IO.Unsafe (unsafePerformIO)
import qualified Data.Vector as Vec

import Types.PayloadSerializationSpec

schemes :: [SchemeId]
schemes = [Ed25519]

verifyKeys :: Vec.Vector VerifyKey
verifyKeys = unsafePerformIO $ Vec.replicateM 200 (correspondingVerifyKey <$> newKeyPair Ed25519)
{-# NOINLINE verifyKeys #-}

genVerifyKey :: Gen VerifyKey
genVerifyKey = do
  i <- choose (0, Vec.length verifyKeys - 1)
  return $ verifyKeys Vec.! i

genSchemeId :: Gen SchemeId
genSchemeId = elements schemes

genAccountAddress :: Gen AccountAddress
genAccountAddress = AccountAddress . FBS.pack <$> vector accountAddressSize

genTransactionHeader :: Gen TransactionHeader
genTransactionHeader = do
  thSender <- genAccountAddress
  thPayloadSize <- PayloadSize <$> choose (0, maxPayloadSize SP4)
  thNonce <- Nonce <$> arbitrary
  thEnergyAmount <- Energy <$> arbitrary
  thExpiry <- TransactionTime <$> arbitrary
  return $ TransactionHeader{..}

genAccountTransaction :: Gen AccountTransaction
genAccountTransaction = do
  atrHeader <- genTransactionHeader
  atrPayload <- EncodedPayload . BSS.pack <$> vector (fromIntegral (thPayloadSize atrHeader))
  numCredentials <- choose (1,255)
  allKeys <- replicateM numCredentials $ do
    numKeys <- choose (1, 255)
    credentialSignatures <- replicateM numKeys $ do
      idx <- KeyIndex <$> arbitrary
      sLen <- choose (50,70)
      sig <- Signature . BSS.pack <$> vector sLen
      return (idx, sig)
    (, Map.fromList credentialSignatures) . CredentialIndex <$> arbitrary

  let atrSignature = TransactionSignature (Map.fromList allKeys)
  return $! makeAccountTransaction atrSignature atrHeader atrPayload

baseTime :: UTCTime
baseTime = read "2019-09-23 13:27:13.257285424 UTC"

genTransaction :: Gen Transaction
genTransaction = do
  wmdData <- genAccountTransaction
  wmdArrivalTime <- TransactionTime <$> arbitrary
  return $ addMetadata NormalTransaction wmdArrivalTime wmdData

genInitialCredentialDeploymentInformation :: Gen InitialCredentialDeploymentInfo
genInitialCredentialDeploymentInformation = do
  icdvAccount <- genCredentialPublicKeys
  icdvRegId <- RegIdCred . generateGroupElementFromSeed globalContext <$> arbitrary
  icdvIpId <- IP_ID <$> arbitrary
  icdvPolicy <- do
    let ym = YearMonth <$> choose (1000,9999) <*> choose (1,12)
    pValidTo <- ym
    pCreatedAt <- ym
    let pItems = Map.empty
    return Policy{..}
  let icdiValues = InitialCredentialDeploymentValues{..}
  icdiSig <- IpCdiSignature . BSS.pack <$> vector 64
  return InitialCredentialDeploymentInfo{..}

genAccountCredentialWithProofs :: Gen AccountCredentialWithProofs
genAccountCredentialWithProofs =
  oneof [NormalACWP <$> genCredentialDeploymentInformation,
         InitialACWP <$> genInitialCredentialDeploymentInformation]

genCredentialDeploymentWithMeta :: Gen CredentialDeploymentWithMeta
genCredentialDeploymentWithMeta = do
  credential <- genAccountCredentialWithProofs
  messageExpiry <- TransactionTime <$> arbitrary
  wmdArrivalTime <- TransactionTime <$> arbitrary
  return $ addMetadata CredentialDeployment wmdArrivalTime AccountCreation{..}

genBlockItem :: Gen BlockItem
genBlockItem = oneof [
  normalTransaction <$> genTransaction,
  credentialDeployment <$> genCredentialDeploymentWithMeta]
