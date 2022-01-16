{-# OPTIONS_GHC -Wno-deprecations #-}
module Types.PayloadSerializationSpec where

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck.Monadic
import Test.QuickCheck

import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as BSS
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import qualified Data.Serialize as S
import qualified Data.Text as Text
import qualified Data.Vector as Vec
import Data.Int
import System.Random
import Control.Monad
import System.IO.Unsafe

import qualified Concordium.Crypto.BlockSignature as BlockSig
import qualified Concordium.Crypto.BlsSignature as Bls
import Concordium.Crypto.SignatureScheme
import Concordium.ID.Types
import Concordium.ID.DummyData
import Concordium.Common.Time
import qualified Concordium.Crypto.VRF as VRF
import Concordium.Crypto.EncryptedTransfers
import Concordium.Crypto.FFIDataTypes
import qualified Data.FixedByteString as FBS
import qualified Concordium.Crypto.SHA256 as SHA256

import Concordium.Types.Execution
import Concordium.Types
import Concordium.Wasm

import Concordium.Crypto.Proofs
import Concordium.Crypto.DummyData

genAttributeValue :: Gen AttributeValue
genAttributeValue = AttributeValue . BSS.pack <$> (vector =<< choose (0,31))

genDlogProof :: Gen Dlog25519Proof
genDlogProof = fst . randomProof . mkStdGen <$> resize 100000 arbitrary

genAccountOwnershipProof :: Gen AccountOwnershipProof
genAccountOwnershipProof = do
  n <- choose (1, 255)
  AccountOwnershipProof <$> replicateM n (do
     keyIndex <- KeyIndex <$> arbitrary
     proof <- genDlogProof
     return (keyIndex, proof))

genAggregationVerifyKeyAndProof :: Gen (BakerAggregationVerifyKey, BakerAggregationProof)
genAggregationVerifyKeyAndProof = do
  c <- arbitrary
  sk <- secretBlsKeyGen
  -- FIXME: The use of unsafePeformIO here is wrong, but I'm in a hurry.
  -- The randomness is used to get the zero-knowledge property
  -- We need to expose a deterministic "prove" function from rust that takes a seed.
  return (Bls.derivePublicKey sk, unsafePerformIO $ Bls.proveKnowledgeOfSK (BS.pack c) sk)

genAddress :: Gen AccountAddress
genAddress = AccountAddress . FBS.fromByteString . BS.pack <$> (vector accountAddressSize)

genCAddress :: Gen ContractAddress
genCAddress = ContractAddress <$> (ContractIndex <$> arbitrary) <*> (ContractSubindex <$> arbitrary)

genModuleRef :: Gen ModuleRef
genModuleRef = ModuleRef . SHA256.hash . BS.pack <$> vector 32

-- These generators name contracts as numbers to make sure the names are valid.
genInitName :: Gen InitName
genInitName =
  InitName . Text.pack . ("init_" ++) . show <$> (arbitrary :: Gen Word)

genReceiveName :: Gen ReceiveName
genReceiveName = do
  contract <- show <$> (arbitrary :: Gen Word)
  receive <- show <$> (arbitrary :: Gen Word)
  return . ReceiveName . Text.pack $ receive ++ "." ++ contract

genParameter :: Gen Parameter
genParameter = do
  n <- choose (0,1000)
  Parameter . BSS.pack <$> vector n

genPayload :: Gen Payload
genPayload = oneof [genDeployModule,
                    genInit,
                    genUpdate,
                    genTransfer,
                    genCredentialUpdate,
                    genAddBaker,
                    genRemoveBaker,
                    genUpdateBakerStake,
                    genUpdateBakerRestakeEarnings,
                    genUpdateBakerKeys,
                    genUpdateCredentialKeys,
                    genTransferToEncrypted,
                    genRegisterData
                    ]
  where
        genCredentialUpdate = do
          maxNumCredentials <- choose (0,255)
          indices <- Set.fromList . map CredentialIndex <$> replicateM maxNumCredentials (choose (0, 255))
          -- the actual number of key indices. Duplicate key indices might have been generated.
          let numCredentials = Set.size indices
          credentials <- replicateM numCredentials genCredentialDeploymentInformation
          ucNewThreshold <- AccountThreshold <$> choose (1, 255) -- since we are only updating there is no requirement that the threshold is less than the amount of credentials
          toRemoveLen <- choose (0, 30)
          ucRemoveCredIds <- replicateM toRemoveLen genCredentialId
          return UpdateCredentials{ucNewCredInfos = Map.fromList (zip (Set.toList indices) credentials),..}

        genByteString = do
          n <- choose (0,1000)
          BS.pack <$> vector n

        genDeployModule = oneof [DeployModule <$> (WasmModuleV0 . WasmModuleV . ModuleSource <$> genByteString),
                                 DeployModule <$> (WasmModuleV1 . WasmModuleV . ModuleSource <$> genByteString)]

        genInit = do
          icAmount <- Amount <$> arbitrary
          icModRef <- genModuleRef
          icInitName <- genInitName
          icParam <- genParameter
          return InitContract{..}

        genUpdate = do
          uAmount <- Amount <$> arbitrary
          uAddress <- genCAddress
          uMessage <- genParameter
          uReceiveName <- genReceiveName
          return Update{..}

        genTransfer = do
          a <- genAddress
          amnt <- Amount <$> arbitrary
          return $ Transfer a amnt

        genAddBaker = do
          abElectionVerifyKey <- VRF.publicKey <$> arbitrary
          abSignatureVerifyKey <- BlockSig.verifyKey <$> genBlockKeyPair
          (abAggregationVerifyKey, abProofAggregation) <- genAggregationVerifyKeyAndProof
          abProofSig <- genDlogProof
          abProofElection <- genDlogProof
          abBakingStake <- arbitrary
          abRestakeEarnings <- arbitrary
          return AddBaker{..}

        genRemoveBaker = return RemoveBaker

        genUpdateBakerStake =
          UpdateBakerStake <$> arbitrary
        
        genUpdateBakerRestakeEarnings =
          UpdateBakerRestakeEarnings <$> arbitrary

        genUpdateBakerKeys = do
          ubkElectionVerifyKey <- VRF.publicKey <$> arbitrary
          ubkSignatureVerifyKey <- BlockSig.verifyKey <$> genBlockKeyPair
          (ubkAggregationVerifyKey, ubkProofAggregation) <- genAggregationVerifyKeyAndProof
          ubkProofSig <- genDlogProof
          ubkProofElection <- genDlogProof
          return UpdateBakerKeys{..}


        genUpdateCredentialKeys = do
          uckKeys <- genCredentialPublicKeys
          uckCredId <- genCredentialId
          return UpdateCredentialKeys{..}

        genTransferToEncrypted =
           TransferToEncrypted . Amount <$> arbitrary

        genRegisterData = do
          n <- chooseInt (0, maxRegisteredDataSize)
          rdData <- RegisteredData . BSS.pack <$> vectorOf n arbitrary
          return RegisterData{..}

genCredentialId :: Gen CredentialRegistrationID
genCredentialId = RegIdCred . generateGroupElementFromSeed globalContext <$> arbitrary

genSignThreshold :: Gen SignatureThreshold
genSignThreshold = SignatureThreshold <$> choose (1,255)

-- |Simply generate a few 'ElgamalCipher' values for testing purposes.
elgamalCiphers :: Vec.Vector ElgamalCipher
elgamalCiphers = unsafePerformIO $ Vec.replicateM 200 generateElgamalCipher
{-# NOINLINE elgamalCiphers #-}

genElgamalCipher :: Gen ElgamalCipher
genElgamalCipher = do
  i <- choose (0, Vec.length elgamalCiphers - 1)
  return $ elgamalCiphers Vec.! i

-- generate an increasing list of key indices, at least 1
genIndices :: Gen [KeyIndex]
genIndices = do
  maxLen <- choose (1::Int, 255)
  let go is _ 0 = return is
      go is nextIdx n = do
        nextIndex <- choose (nextIdx, 255)
        if nextIndex == 255 then
          return (KeyIndex nextIndex:is)
        else go (KeyIndex nextIndex:is) (nextIndex+1) (n-1)
  reverse <$> go [] 0 maxLen

genAccountKeysMap :: Gen (Map.Map KeyIndex VerifyKey)
genAccountKeysMap = do
  indexList <- genIndices
  mapList <- forM indexList $ \idx -> do
    kp <- genSigSchemeKeyPair
    return (idx, correspondingVerifyKey kp)
  return $ Map.fromList mapList

genCredentialPublicKeys :: Gen CredentialPublicKeys
genCredentialPublicKeys = do
  credKeys <- genAccountKeysMap
  credThreshold <- genSignThreshold
  return CredentialPublicKeys{..}

genCredentialDeploymentInformation :: Gen CredentialDeploymentInformation
genCredentialDeploymentInformation = do
  cdvPublicKeys <- genCredentialPublicKeys
  cdvCredId <- RegIdCred . generateGroupElementFromSeed globalContext <$> arbitrary
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


testSerializeEncryptedTransfer :: Property
testSerializeEncryptedTransfer = property $ \gen gen1 seed1 seed2 -> forAll genAddress $ \addr -> monadicIO $ do
  let public = AccountEncryptionKey . deriveElgamalPublicKey globalContext . generateGroupElementFromSeed globalContext $ seed1
  let private = generateElgamalSecretKeyFromSeed globalContext seed2
  let agg = makeAggregatedDecryptedAmount (encryptAmountZeroRandomness globalContext gen) gen (EncryptedAmountAggIndex gen1)
  let amount = gen `div` 2
  Just eatd <- run (makeEncryptedAmountTransferData globalContext (_elgamalPublicKey public) private agg amount)
  return (checkPayload (EncryptedAmountTransfer addr eatd))

testSecToPubTransfer :: Property
testSecToPubTransfer = property $ \gen gen1 seed1 -> monadicIO $ do
  let private = generateElgamalSecretKeyFromSeed globalContext seed1
  let agg = makeAggregatedDecryptedAmount (encryptAmountZeroRandomness globalContext gen) gen (EncryptedAmountAggIndex gen1)
  let amount = gen `div` 2
  Just eatd <- run (makeSecToPubAmountTransferData globalContext private agg amount)
  return (checkPayload (TransferToPublic eatd))


groupIntoSize :: Int64 -> [Char]
groupIntoSize s =
  let kb = s `div` 1000
      nd = if kb > 0 then truncate (logBase 10 (fromIntegral kb :: Double)) else 0 :: Int
  in if nd == 0 then show kb ++ "kB"
     else let lb = 10^nd :: Int
              ub = 10^(nd+1) :: Int
          in show lb ++ " -- " ++ show ub ++ "kB"

checkPayload :: Payload -> Property
checkPayload e = let bs = S.runPut $ putPayload e
                 in case S.runGet (getPayload SP1 (fromIntegral (BS.length bs))) bs of
                      Left err -> counterexample err False
                      Right e' -> label (groupIntoSize (fromIntegral (BS.length bs))) $ e === e'

tests :: Spec
tests = do
  describe "Payload serialization tests" $ do
    test 25 1000
    test 50 500
  describe "Encrypted transfer payloads" $ do
    specify "Encrypted transfer" $ testSerializeEncryptedTransfer
    specify "Transfer to public" $ testSecToPubTransfer
 where test size num =
         modifyMaxSuccess (const num) $
           specify ("Payload serialization with size = " ++ show size ++ ":") $
           forAll (resize size $ genPayload) checkPayload
