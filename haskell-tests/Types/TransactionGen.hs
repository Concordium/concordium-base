{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -Wno-deprecations #-}
module Types.TransactionGen where

import Test.QuickCheck

import Concordium.Types.Transactions
import Concordium.Crypto.SignatureScheme
import Concordium.Crypto.FFIDataTypes
import Data.Time.Clock

import Concordium.Types
import Concordium.ID.Types
import Concordium.ID.DummyData

import Control.Monad
import qualified Data.Map.Strict as Map
import qualified Data.FixedByteString as FBS
import qualified Data.ByteString.Short as BSS
import System.IO.Unsafe (unsafePerformIO)
import qualified Data.Vector as Vec

schemes :: [SchemeId]
schemes = [Ed25519]

-- |Simply generate a few 'ElgamalCipher' values for testing purposes.
elgamalCiphers :: Vec.Vector ElgamalCipher
elgamalCiphers = unsafePerformIO $ Vec.replicateM 200 generateElgamalCipher
{-# NOINLINE elgamalCiphers #-}

genElgamalCipher :: Gen ElgamalCipher
genElgamalCipher = do
  i <- choose (0, Vec.length elgamalCiphers - 1)
  return $ elgamalCiphers Vec.! i

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
  thPayloadSize <- PayloadSize . fromIntegral <$> sized (\n -> choose (n, 10*(n+1)))
  thNonce <- Nonce <$> arbitrary
  thEnergyAmount <- Energy <$> arbitrary
  thExpiry <- TransactionTime <$> arbitrary
  return $ TransactionHeader{..}

genAccountTransaction :: Gen AccountTransaction
genAccountTransaction = do
  atrHeader <- genTransactionHeader
  atrPayload <- EncodedPayload . BSS.pack <$> vector (fromIntegral (thPayloadSize atrHeader))
  numKeys <- choose (1, 255)
  atrSignature <- TransactionSignature . Map.fromList <$> replicateM numKeys (do
    idx <- KeyIndex <$> arbitrary
    sLen <- choose (50,70)
    sig <- Signature . BSS.pack <$> vector sLen
    return (idx, sig))
  return $! makeAccountTransaction atrSignature atrHeader atrPayload

baseTime :: UTCTime
baseTime = read "2019-09-23 13:27:13.257285424 UTC"

genTransaction :: Gen Transaction
genTransaction = do
  wmdData <- genAccountTransaction
  wmdArrivalTime <- TransactionTime <$> arbitrary
  return $ addMetadata NormalTransaction wmdArrivalTime wmdData

genCredentialDeploymentInformation :: Gen CredentialDeploymentInformation
genCredentialDeploymentInformation = do
  let arbitraryNew = do
        nacc <- choose (1,255)
        keys <- replicateM nacc genVerifyKey
        threshold <- choose (1, nacc)
        return $ NewAccount keys (SignatureThreshold $ fromIntegral threshold)
  cdvAccount <- arbitraryNew
  cdvRegId <- RegIdCred . generateGroupElementFromSeed globalContext <$> arbitrary
  cdvIpId <- IP_ID <$> arbitrary
  cdvArData <- Map.fromList <$> listOf (do
    ardName <- do
      n <- arbitrary
      if n == 0 then return (ArIdentity 1) else return (ArIdentity n)
    ardIdCredPubShare <- AREnc <$> genElgamalCipher
    return (ardName, ChainArData{..}))
  cdvThreshold <- Threshold <$> choose (1, max 1 (fromIntegral (length cdvArData)))
  cdvPolicy <- do
    let ym = YearMonth <$> choose (1000,9999) <*> choose (1,12)
    pValidTo <- ym
    pCreatedAt <- ym
    let pItems = Map.empty
    return Policy{..}
  cdiProofs <- do l <- choose (0, 10000)
                  Proofs . BSS.pack <$> vector l
  let cdiValues = CredentialDeploymentValues{..}
  return CredentialDeploymentInformation{..}

genInitialCredentialDeploymentInformation :: Gen InitialCredentialDeploymentInfo
genInitialCredentialDeploymentInformation = do
  icdvAccount <- do
        nacc <- choose (1,255)
        keys <- replicateM nacc genVerifyKey
        threshold <- choose (1, nacc)
        return $ InitialCredentialAccount keys (SignatureThreshold $ fromIntegral threshold)
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
  wmdData <- genAccountCredentialWithProofs
  wmdArrivalTime <- TransactionTime <$> arbitrary
  return $ addMetadata CredentialDeployment wmdArrivalTime wmdData

genBlockItem :: Gen BlockItem
genBlockItem = oneof [
  normalTransaction <$> genTransaction,
  credentialDeployment <$> genCredentialDeploymentWithMeta]
