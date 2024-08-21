{-# OPTIONS_GHC -Wno-deprecations #-}

module Types.PayloadSerializationSpec where

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck
import Test.QuickCheck.Monadic

import Control.Monad
import qualified Data.Bits as Bit
import qualified Data.ByteString as BS
import Data.Either (isLeft)
import Data.Int
import Data.Maybe (isNothing)
import qualified Data.Serialize as S
import Data.Word

import Concordium.Crypto.EncryptedTransfers
import Concordium.Crypto.FFIDataTypes
import Concordium.ID.DummyData
import Concordium.ID.Types

import Concordium.Types
import Concordium.Types.Execution
import qualified Concordium.Wasm as Wasm

import Generators

-- | Check if a payload is supported by the given protocol version.
isPayloadSupported :: ProtocolVersion -> Payload -> Bool
isPayloadSupported pv DeployModule{..} =
    -- At P3 and earlier, only version 0 modules are supported.
    pv > P3 || Wasm.wasmVersion dmMod == Wasm.V0
isPayloadSupported _ InitContract{} = True
isPayloadSupported _ Update{} = True
isPayloadSupported _ Transfer{} = True
isPayloadSupported pv AddBaker{} = pv <= P3
isPayloadSupported pv RemoveBaker{} = pv <= P3
isPayloadSupported pv UpdateBakerStake{} = pv <= P3
isPayloadSupported pv UpdateBakerRestakeEarnings{} = pv <= P3
isPayloadSupported pv UpdateBakerKeys{} = pv <= P3
isPayloadSupported _ UpdateCredentialKeys{} = True
isPayloadSupported pv EncryptedAmountTransfer{} = pv <= P6
isPayloadSupported pv TransferToEncrypted{} = pv <= P6
isPayloadSupported _ TransferToPublic{} = True
isPayloadSupported _ TransferWithSchedule{} = True
isPayloadSupported _ UpdateCredentials{} = True
isPayloadSupported _ RegisterData{} = True
isPayloadSupported pv TransferWithMemo{} = pv > P1
isPayloadSupported pv EncryptedAmountTransferWithMemo{} = pv > P1 && pv <= P6
isPayloadSupported pv TransferWithScheduleAndMemo{} = pv > P1
isPayloadSupported pv ConfigureBaker{..}
    | isNothing cbSuspend = pv > P3
    | otherwise = pv > P7
isPayloadSupported pv ConfigureDelegation{} = pv > P3

testSerializeEncryptedTransfer :: SProtocolVersion pv -> Property
testSerializeEncryptedTransfer spv =
    property $ \gen gen1 seed1 seed2 -> forAll genAccountAddress $ \addr -> monadicIO $ do
        let public = AccountEncryptionKey . deriveElgamalPublicKey globalContext . generateGroupElementFromSeed globalContext $ seed1
        let private = generateElgamalSecretKeyFromSeed globalContext seed2
        let agg = makeAggregatedDecryptedAmount (encryptAmountZeroRandomness globalContext gen) gen (EncryptedAmountAggIndex gen1)
        let amount = gen `div` 2
        Just eatd <- run (makeEncryptedAmountTransferData globalContext (_elgamalPublicKey public) private agg amount)
        return (checkPayload spv (EncryptedAmountTransfer addr eatd))

testSerializeEncryptedTransferWithMemo :: SProtocolVersion pv -> Property
testSerializeEncryptedTransferWithMemo spv =
    property $ \gen gen1 seed1 seed2 -> forAll genAccountAddress $ \addr ->
        forAll genMemo $ \memo -> monadicIO $ do
            let public = AccountEncryptionKey . deriveElgamalPublicKey globalContext . generateGroupElementFromSeed globalContext $ seed1
            let private = generateElgamalSecretKeyFromSeed globalContext seed2
            let agg = makeAggregatedDecryptedAmount (encryptAmountZeroRandomness globalContext gen) gen (EncryptedAmountAggIndex gen1)
            let amount = gen `div` 2
            Just eatd <- run (makeEncryptedAmountTransferData globalContext (_elgamalPublicKey public) private agg amount)
            return (checkPayload spv (EncryptedAmountTransferWithMemo addr memo eatd))

testSecToPubTransfer :: SProtocolVersion pv -> Property
testSecToPubTransfer spv = property $ \gen gen1 seed1 -> monadicIO $ do
    let private = generateElgamalSecretKeyFromSeed globalContext seed1
    let agg = makeAggregatedDecryptedAmount (encryptAmountZeroRandomness globalContext gen) gen (EncryptedAmountAggIndex gen1)
    let amount = gen `div` 2
    Just eatd <- run (makeSecToPubAmountTransferData globalContext private agg amount)
    return (checkPayload spv (TransferToPublic eatd))

groupIntoSize :: Int64 -> [Char]
groupIntoSize s =
    let kb = s `div` 1000
        nd = if kb > 0 then truncate (logBase 10 (fromIntegral kb :: Double)) else 0 :: Int
    in  if nd == 0
            then show kb ++ "kB"
            else
                let lb = 10 ^ nd :: Int
                    ub = 10 ^ (nd + 1) :: Int
                in  show lb ++ " -- " ++ show ub ++ "kB"

checkPayload :: SProtocolVersion pv -> Payload -> Property
checkPayload spv e =
    let bs = S.runPut $ putPayload e
    in  label (groupIntoSize (fromIntegral (BS.length bs))) $ case S.runGet (getPayload spv (fromIntegral (BS.length bs))) bs of
            Left err -> counterexample err (not supported)
            Right e'
                | supported -> e === e'
                | otherwise -> counterexample "Payload is not supported, but was decoded" False
  where
    supported = isPayloadSupported (demoteProtocolVersion spv) e

-- Modify the bitmap portion of a payload. Assumes that the input bytestring
-- is at least 24 bits long.
modifyPayloadBitmap :: (Word16 -> Word16) -> BS.ByteString -> BS.ByteString
modifyPayloadBitmap f bs =
    let res = S.runGetState ((,) <$> S.getWord8 <*> S.getWord16be) bs 0
        ((header, bitmap), rest) = case res of
            Right v -> v
            -- This happens only when bs is 23 bits or less.
            Left _ -> error "res should be Right"
    in  S.runPut (S.putWord8 header <> S.putWord16be (f bitmap)) `BS.append` rest

-- | 'genPayloadWithInvalidBitmap' @sizeOfBitmap@ @payload@ will update the @payload@ by setting
-- invalid bits in the high end of the 16 bit bitmap. The bitmap is assumed to be located at index
-- '1' of the payload. The @sizeOfBitmap@ is the number of allowed bits in the bitmap. The remaining
-- (higher) bits are modified to invalidate the payload's bitmap.
genPayloadWithInvalidBitmap :: Int -> BS.ByteString -> Gen BS.ByteString
genPayloadWithInvalidBitmap sizeOfBitmap payload = do
    let invalidBitmask = Bit.shiftL maxBound sizeOfBitmap
    invalidBits <- suchThat (fmap (invalidBitmask Bit..&.) arbitrary) (/= 0)
    return (modifyPayloadBitmap (invalidBits Bit..|.) payload)

genInvalidPayloadConfigureBaker :: ProtocolVersion -> Gen BS.ByteString
genInvalidPayloadConfigureBaker pv =
    oneof $ invalidBitmap : [invalidSuspendFlag | pv < P8]
  where
    invalidBitmap = do
        bs <- S.runPut . putPayload <$> genPayloadConfigureBaker pv
        genPayloadWithInvalidBitmap 10 bs
    invalidSuspendFlag = do
        p <- genPayloadConfigureBaker pv
        b <- arbitrary
        -- we test against a correct and incorrect bitmask for the suspend flag.
        doSetSuspendBit <- arbitrary
        -- set the suspend flag and the corresponding bit in the bitmask
        return $
            modifyPayloadBitmap (if doSetSuspendBit then setSuspendBit else id) $
                S.runPut $
                    putPayload $
                        p{cbSuspend = Just b}
    suspendBitmask = Bit.shiftL 1 9
    setSuspendBit bm = suspendBitmask Bit..|. bm

genInvalidPayloadConfigureDelegation :: Gen BS.ByteString
genInvalidPayloadConfigureDelegation = do
    bs <- S.runPut . putPayload <$> genPayloadConfigureDelegation
    genPayloadWithInvalidBitmap 3 bs

genInvalidPayloadByteString :: ProtocolVersion -> Gen BS.ByteString
genInvalidPayloadByteString pv =
    oneof [genInvalidPayloadConfigureBaker pv, genInvalidPayloadConfigureDelegation]

-- | Generate a bytestring representing a valid payload, but with additional bytes appended to it.
genPaddedPayloadByteString :: ProtocolVersion -> Gen BS.ByteString
genPaddedPayloadByteString pv = do
    payload <- genPayload pv
    padding <- BS.pack <$> sized (\n -> vectorOf (n + 1) arbitrary)
    return . S.runPut $ do
        putPayload payload
        S.putByteString padding

checkInvalidPayloadByteString :: SProtocolVersion pv -> BS.ByteString -> Property
checkInvalidPayloadByteString spv bs =
    property $ isLeft $ S.runGet (getPayload spv (fromIntegral (BS.length bs))) bs

tests :: Spec
tests = do
    describe "Payload serialization tests" $ do
        test SP1 25 1000
        test SP2 50 500
        test SP3 50 500
        test SP4 25 1000
        test SP4 50 500
        test SP5 25 1000
        test SP5 50 500
        test SP6 25 1000
        test SP6 50 500
        test SP7 25 1000
        test SP7 50 500
        test SP8 50 500
    describe "Negative payload serialization tests" $ do
        negativeTest SP4 20 200
        negativeTest SP6 20 200
        negativeTest SP7 20 200
        negativeTest SP8 20 200
        negativeTestPadded SP6 20 200
        negativeTestPadded SP7 20 200
        negativeTestPadded SP8 20 200
    describe "Encrypted transfer payloads P6" $ do
        specify "Encrypted transfer" $ testSerializeEncryptedTransfer SP6
        specify "Encrypted transfer with memo" $ testSerializeEncryptedTransferWithMemo SP6
        specify "Transfer to public" $ testSecToPubTransfer SP6
    describe "Encrypted transfer payloads P7" $ do
        specify "Encrypted transfer" $ testSerializeEncryptedTransfer SP7
        specify "Encrypted transfer with memo" $ testSerializeEncryptedTransferWithMemo SP7
        specify "Transfer to public" $ testSecToPubTransfer SP7
    describe "Encrypted transfer payloads P8" $ do
        specify "Encrypted transfer" $ testSerializeEncryptedTransfer SP8
        specify "Encrypted transfer with memo" $ testSerializeEncryptedTransferWithMemo SP8
        specify "Transfer to public" $ testSecToPubTransfer SP8
    describe "Unsafe payload serialization tests" $ do
        forM_ [P1, P2, P3, P4, P5, P6, P7, P8] $ \pv -> do
            case promoteProtocolVersion pv of
                (SomeProtocolVersion spv) -> testUnsafe spv 25 1000
  where
    test spv size num =
        modifyMaxSuccess (const num)
            $ specify
                ( "Payload serialization ("
                    ++ show (demoteProtocolVersion spv)
                    ++ ") with size = "
                    ++ show size
                    ++ ":"
                )
            $ forAll (resize size $ genPayload (demoteProtocolVersion spv)) (checkPayload spv)
    negativeTest spv size num =
        modifyMaxSuccess (const num)
            $ specify
                ( "Negative payload serialization ("
                    ++ show (demoteProtocolVersion spv)
                    ++ ") with size = "
                    ++ show size
                    ++ ":"
                )
            $ forAll (resize size $ genInvalidPayloadByteString (demoteProtocolVersion spv)) (checkInvalidPayloadByteString spv)
    negativeTestPadded spv size num =
        modifyMaxSuccess (const num)
            $ specify
                ( "Negative payload serialization with padding ("
                    ++ show (demoteProtocolVersion spv)
                    ++ ") with size = "
                    ++ show size
                    ++ ":"
                )
            $ forAll (resize size $ genPaddedPayloadByteString (demoteProtocolVersion spv)) (checkInvalidPayloadByteString spv)
    testUnsafe spv size num =
        modifyMaxSuccess (const num)
            $ specify
                ( "Payload deserialization including invalid types ("
                    ++ show (demoteProtocolVersion spv)
                    ++ ") with size = "
                    ++ show size
                    ++ ":"
                )
            $ forAll
                (resize size genPayloadUnsafe)
                (checkPayloadLabelled spv)
    checkPayloadLabelled spv payload =
        label lbl $ checkPayload spv payload
      where
        lbl
            | isPayloadSupported (demoteProtocolVersion spv) payload = "supported"
            | otherwise = "unsupported"
