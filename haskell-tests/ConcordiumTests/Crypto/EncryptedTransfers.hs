{-# LANGUAGE ScopedTypeVariables #-}

module ConcordiumTests.Crypto.EncryptedTransfers where

import Concordium.Common.Amount
import Concordium.Crypto.EncryptedTransfers
import Concordium.Crypto.FFIDataTypes
import Concordium.ID.DummyData
import Concordium.ID.Types

import qualified Data.ByteString as BS
import Data.Serialize
import Data.Word
import Foreign.Ptr
import Test.Hspec
import Test.QuickCheck
import Test.QuickCheck.Monadic

testSerializeDet :: (Serialize a, Eq a, Show a, Arbitrary gen, Show gen) => (gen -> a) -> Property
testSerializeDet f = property $ \g ->
    let val = f g
    in  Right val === runGet get (runPut $ put val)

testSerializeEncryptedAmount :: Property
testSerializeEncryptedAmount = testSerializeDet (encryptAmountZeroRandomness globalContext)

testMakeAggregatedEncryptedAmount :: Property
testMakeAggregatedEncryptedAmount = property $ \gen gen1 -> monadicIO $ do
    let agg = makeAggregatedDecryptedAmount (encryptAmountZeroRandomness globalContext gen) gen (EncryptedAmountAggIndex gen1)
    res <- run (withAggregatedDecryptedAmount agg $ return)
    return (res =/= nullPtr)

testSerializeEncryptedAmountTransferData :: Property
testSerializeEncryptedAmountTransferData = property $ \gen gen1 seed1 seed2 -> monadicIO $ do
    let public = accEncKeyFromSeed seed1
    let private = generateElgamalSecretKeyFromSeed globalContext seed2
    let agg = makeAggregatedDecryptedAmount (encryptAmountZeroRandomness globalContext gen) gen (EncryptedAmountAggIndex gen1)
    let amount = gen `div` 2
    Just eatd@EncryptedAmountTransferData{..} <- run (makeEncryptedAmountTransferData globalContext (_elgamalPublicKey public) private agg amount)
    let bytes = runPut (put eatdRemainingAmount <> put eatdTransferAmount <> put eatdIndex <> putEncryptedAmountTransferProof eatdProof)
    let len = BS.length (runPut (putEncryptedAmountTransferProof eatdProof))
    let getEncrypted = do
            _eatdRemainingAmount <- get
            _eatdTransferAmount <- get
            _eatdIndex <- get
            _eatdProof <- getEncryptedAmountTransferProof (fromIntegral len)
            return
                EncryptedAmountTransferData
                    { eatdRemainingAmount = _eatdRemainingAmount,
                      eatdTransferAmount = _eatdTransferAmount,
                      eatdIndex = _eatdIndex,
                      eatdProof = _eatdProof
                    }
    return (Right eatd === runGet getEncrypted bytes)

accEncKeyFromSeed :: Word64 -> AccountEncryptionKey
accEncKeyFromSeed = AccountEncryptionKey . deriveElgamalPublicKey globalContext . generateGroupElementFromSeed globalContext

testTransferProofVerify :: Property
testTransferProofVerify = property $ \gen gen1 seed1 seed2 -> monadicIO $ do
    let receiverPK = accEncKeyFromSeed seed1
    let private = generateElgamalSecretKeyFromSeed globalContext seed2
    let senderPK = accEncKeyFromSeed seed2
    let inputAmount = encryptAmountZeroRandomness globalContext gen
    let agg = makeAggregatedDecryptedAmount inputAmount gen (EncryptedAmountAggIndex gen1)
    let amount = gen `div` 2
    Just eatd <- run (makeEncryptedAmountTransferData globalContext (_elgamalPublicKey receiverPK) private agg amount)
    return $ verifyEncryptedTransferProof globalContext receiverPK senderPK inputAmount eatd

testSecToPubTransferProofVerify :: Property
testSecToPubTransferProofVerify = property $ \gen gen1 seed1 -> monadicIO $ do
    let private = generateElgamalSecretKeyFromSeed globalContext seed1
    let receiverPK = accEncKeyFromSeed seed1
    let inputAmount = encryptAmountZeroRandomness globalContext gen
    let agg = makeAggregatedDecryptedAmount inputAmount gen (EncryptedAmountAggIndex gen1)
    let amount = gen `div` 2
    Just eatd <- run (makeSecToPubAmountTransferData globalContext private agg amount)
    return $ verifySecretToPublicTransferProof globalContext receiverPK inputAmount eatd

testEncryptDecrypt :: Property
testEncryptDecrypt =
    let table = computeTable globalContext (2 ^ (16 :: Int))
    in  property $ \gen amnt -> monadicIO $ do
            let private = generateElgamalSecretKeyFromSeed globalContext gen
            let pk = _elgamalPublicKey . accEncKeyFromSeed $ gen
            encAmnt <- run (encryptAmount globalContext pk (Amount amnt))
            return (Amount amnt === decryptAmount table private encAmnt)

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
    describe "Test decryption." $ do
        it "encrypt + decrypt is identity" testEncryptDecrypt
