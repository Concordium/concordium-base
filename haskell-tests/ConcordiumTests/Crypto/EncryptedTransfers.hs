{-# LANGUAGE ScopedTypeVariables #-}
module ConcordiumTests.Crypto.EncryptedTransfers where

import Concordium.Crypto.EncryptedTransfers
import Concordium.ID.Parameters
import Concordium.ID.Types
import Concordium.Crypto.FFIDataTypes

import qualified Data.ByteString as BS
import Data.Serialize
import Test.QuickCheck.Monadic
import Test.QuickCheck
import Test.Hspec
import Foreign.Ptr

testSerializeDet :: (Serialize a, Eq a, Show a, Arbitrary gen, Show gen) => (gen ->  a) -> Property
testSerializeDet f = property $ \g ->
        let val = f g
        in Right val === runGet get (runPut $ put val)

testSerializeEncryptedAmount :: Property
testSerializeEncryptedAmount = testSerializeDet (encryptAmount globalContext)

testMakeAggregatedEncryptedAmount :: Property
testMakeAggregatedEncryptedAmount = property $ \gen -> monadicIO $ do
  let agg = makeAggregatedDecryptedAmount (encryptAmount globalContext gen) gen (EncryptedAmountAggIndex gen)
  res <- run (withAggregatedDecryptedAmount agg $ return)
  return (res =/= nullPtr)

testSerializeEncryptedAmountTransferData :: Property
testSerializeEncryptedAmountTransferData = property $ \gen seed1 seed2 -> monadicIO $ do
  let public = generateElgamalSecondFromSeed seed1
  let private = generateElgamalSecondSecretFromSeed seed2
  let agg = makeAggregatedDecryptedAmount (encryptAmount globalContext gen) gen (EncryptedAmountAggIndex gen)
  let amount = gen `div` 2
  Just eatd@EncryptedAmountTransferData{..} <- run (makeEncryptedAmountTransferData globalContext public private agg amount)
  let bytes = runPut (put eatdRemainingAmount <> put eatdTransferAmount <> put eatdIndex <> putEncryptedAmountTransferProof eatdProof)
  let len = BS.length (runPut (putEncryptedAmountTransferProof eatdProof))
  let getEncrypted = do
        _eatdRemainingAmount <- get
        _eatdTransferAmount <- get
        _eatdIndex <- get
        _eatdProof <- getEncryptedAmountTransferProof (fromIntegral len)
        return EncryptedAmountTransferData{
          eatdRemainingAmount = _eatdRemainingAmount,
          eatdTransferAmount = _eatdTransferAmount,
          eatdIndex = _eatdIndex,
          eatdProof = _eatdProof
          }
  return (Right eatd === runGet getEncrypted bytes)

testTransferProofVerify :: Property
testTransferProofVerify = property $ \gen seed1 seed2 -> monadicIO $ do
  let public = generateElgamalSecondFromSeed seed1
  let receiverPK = AccountEncryptionKey (RegIdCred public)
  let private = generateElgamalSecondSecretFromSeed seed2
  let senderPK = AccountEncryptionKey (RegIdCred (deriveElgamalSecondPublic private))
  let inputAmount = encryptAmount globalContext gen
  let agg = makeAggregatedDecryptedAmount inputAmount gen (EncryptedAmountAggIndex gen)
  let amount = gen `div` 2
  Just eatd <- run (makeEncryptedAmountTransferData globalContext public private agg amount)
  return $ verifyEncryptedTransferProof globalContext receiverPK senderPK inputAmount eatd

testSecToPubTransferProofVerify :: Property
testSecToPubTransferProofVerify = property $ \gen seed1-> monadicIO $ do
  let private = generateElgamalSecondSecretFromSeed  seed1
  let receiverPK = AccountEncryptionKey (RegIdCred (deriveElgamalSecondPublic private))
  let inputAmount = encryptAmount globalContext gen
  let agg = makeAggregatedDecryptedAmount inputAmount gen (EncryptedAmountAggIndex gen)
  let amount = gen `div` 2
  Just eatd <- run (makeSecToPubAmountTransferData globalContext private agg amount)
  return $ verifySecretToPublicTransferProof globalContext receiverPK inputAmount eatd

tests :: Spec
tests = describe "Concordium.Crypto.EncryptedTransfers" $ do
  describe "serialization" $ do
    it "encrypted amount" testSerializeEncryptedAmount
    it "serialize encrypted amount transfer data" testSerializeEncryptedAmountTransferData
  describe "Make encrypted transfer." $ do
    it "make aggregated encrypted amount" testMakeAggregatedEncryptedAmount
  describe "Test proof verification." $ do
    it "encrypted transfer proof verify" testTransferProofVerify
    it "sec to pub transfer proof verify" testSecToPubTransferProofVerify
