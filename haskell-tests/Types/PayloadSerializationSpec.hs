{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -Wno-deprecations #-}
module Types.PayloadSerializationSpec where

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck.Monadic
import Test.QuickCheck

import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as BSS
import qualified Data.Map as Map
import qualified Data.Set as Set
import qualified Data.Serialize as S
import qualified Data.Text as Text
import Data.Int
import System.Random
import Control.Monad

import qualified Concordium.Crypto.BlockSignature as BlockSig
import qualified Concordium.Crypto.BlsSignature as Bls
import Concordium.Crypto.SignatureScheme
import Concordium.ID.Types
import Concordium.ID.DummyData
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

-- genCredentialDeploymentInformation :: Gen CredentialDeploymentInformation
-- genCredentialDeploymentInformation = do
--   cdvVerifyKey <- VerifyKey . BS.pack <$> vector 37
--   cdvSigScheme <- elements [Ed25519]
--   cdvRegId <- RegIdCred . FBS.pack <$> vector (FBS.fixedLength (undefined :: RegIdSize))
--   cdvIpId <- IP_ID . BS.pack <$> vector 53
--   cdvArData <- do
--     ardName <- ArIdentity . BS.pack <$> (vector =<< choose (0,1000))
--     ardIdCredPubEnc <- AREnc . BS.pack <$> (vector =<< choose(30,80))
--     return AnonymityRevocationData{..}
--   cdvPolicy <- do
--     l <- choose (0,1000)
--     pAttributeListVariant <- arbitrary
--     pExpiry <- arbitrary
--     pItems <- replicateM l genPolicyItem
--     return Policy{..}
--   cdiProofs <- do l <- choose (0, 10000)
--                   Proofs . BS.pack <$> vector l
--   let cdiValues = CredentialDeploymentValues{..}
--   return CredentialDeploymentInformation{..}

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
  return (Bls.derivePublicKey sk, Bls.proveKnowledgeOfSK (BS.pack c) sk)

genAddress :: Gen AccountAddress
genAddress = AccountAddress . FBS.fromByteString . BS.pack <$> (vector accountAddressSize)

genCAddress :: Gen ContractAddress
genCAddress = ContractAddress <$> (ContractIndex <$> arbitrary) <*> (ContractSubindex <$> arbitrary)

genModuleRef :: Gen ModuleRef
genModuleRef = ModuleRef . SHA256.hash . BS.pack <$> vector 32

genPayload :: Gen Payload
genPayload = oneof [genDeployModule,
                    genInit,
                    genUpdate,
                    genTransfer,
--                  genCredential,
                    genAddBaker,
                    genRemoveBaker,
                    genUpdateBakerAccount,
                    genUpdateBakerSignKey,
                    genDelegateStake,
                    genUndelegateStake,
                    genUpdateAccountKeys,
                    genAddAccountKeys,
                    genRemoveAccountKeys,
                    genTransferToEncrypted
                    ]
  where
--        genCredential = DeployCredential <$> genCredentialDeploymentInformation

        genByteString = do
          n <- choose (0,1000)
          BS.pack <$> vector n

        -- These generators name contracts as numbers to make sure the names are valid.
        genInitName :: Gen InitName
        genInitName =
          InitName . Text.pack . ("init_" ++) . show <$> (arbitrary :: Gen Word)

        genReceiveName :: Gen ReceiveName
        genReceiveName = do
          contract <- show <$> (arbitrary :: Gen Word)
          receive <- show <$> (arbitrary :: Gen Word)
          return . ReceiveName . Text.pack $ receive ++ "." ++ contract

        genParameter = do
          n <- choose (0,1000)
          Parameter . BSS.pack <$> vector n

        genDeployModule = DeployModule <$> (WasmModule 0 <$> genByteString)

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
          abAccount <- genAddress
          abProofSig <- genDlogProof
          abProofElection <- genDlogProof
          abProofAccount <- genAccountOwnershipProof
          return AddBaker{..}

        genRemoveBaker = do
          rbId <- genBakerId
          return RemoveBaker{..}

        genUpdateBakerAccount = do
          ubaId <- genBakerId
          ubaAddress <- genAddress
          ubaProof <- genAccountOwnershipProof
          return UpdateBakerAccount{..}

        genUpdateBakerSignKey = do
          ubsId <- genBakerId
          ubsKey <- BlockSig.verifyKey <$> genBlockKeyPair
          ubsProof <- genDlogProof
          return UpdateBakerSignKey{..}

        genBakerId = BakerId <$> arbitrary

        genDelegateStake = DelegateStake <$> genBakerId

        genUndelegateStake = return UndelegateStake

        -- generate an increasing list of key indices.
        genIndices = do
          maxLen <- choose (0::Int, 255)
          let go is _ 0 = return is
              go is nextIdx n = do
                nextIndex <- choose (nextIdx, 255)
                if nextIndex == 255 then
                  return (KeyIndex nextIndex:is)
                else go (KeyIndex nextIndex:is) (nextIndex+1) (n-1)
          reverse <$> go [] 0 maxLen

        genAccountKeysMap = do
          indexList <- genIndices
          mapList <- forM indexList (\idx -> do
            kp <- genSigSchemeKeyPair
            return (idx, correspondingVerifyKey kp))
          return $ Map.fromList mapList

        genSignThreshold = oneof [
            (Just . SignatureThreshold <$> choose (1,255)),
            (return Nothing)
          ]

        genUpdateAccountKeys = do
          uakKeys <- genAccountKeysMap
          return UpdateAccountKeys{..}

        genAddAccountKeys = do
          aakThreshold <- genSignThreshold
          aakKeys <- genAccountKeysMap
          return AddAccountKeys{..}

        genRemoveAccountKeys = do
          indices <- genIndices
          rakThreshold <- genSignThreshold
          let rakIndices = Set.fromList indices
          return RemoveAccountKeys{..}

        genTransferToEncrypted =
           TransferToEncrypted . Amount <$> arbitrary

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
                 in case S.runGet (getPayload (fromIntegral (BS.length bs))) bs of
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
