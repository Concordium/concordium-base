{-# OPTIONS_GHC -Wno-deprecations #-}

module Types.PayloadSerializationSpec where

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck
import Test.QuickCheck.Monadic

import qualified Data.Bits as Bit
import qualified Data.ByteString as BS
import Data.Either (isLeft)
import Data.Int
import qualified Data.Serialize as S
import Data.Word

import Concordium.Crypto.EncryptedTransfers
import Concordium.Crypto.FFIDataTypes
import Concordium.ID.DummyData
import Concordium.ID.Types

import Concordium.Types
import Concordium.Types.Execution

import Generators

testSerializeEncryptedTransfer :: Property
testSerializeEncryptedTransfer =
    property $ \gen gen1 seed1 seed2 -> forAll genAccountAddress $ \addr -> monadicIO $ do
        let public = AccountEncryptionKey . deriveElgamalPublicKey globalContext . generateGroupElementFromSeed globalContext $ seed1
        let private = generateElgamalSecretKeyFromSeed globalContext seed2
        let agg = makeAggregatedDecryptedAmount (encryptAmountZeroRandomness globalContext gen) gen (EncryptedAmountAggIndex gen1)
        let amount = gen `div` 2
        Just eatd <- run (makeEncryptedAmountTransferData globalContext (_elgamalPublicKey public) private agg amount)
        return (checkPayload SP1 (EncryptedAmountTransfer addr eatd))

testSecToPubTransfer :: Property
testSecToPubTransfer = property $ \gen gen1 seed1 -> monadicIO $ do
    let private = generateElgamalSecretKeyFromSeed globalContext seed1
    let agg = makeAggregatedDecryptedAmount (encryptAmountZeroRandomness globalContext gen) gen (EncryptedAmountAggIndex gen1)
    let amount = gen `div` 2
    Just eatd <- run (makeSecToPubAmountTransferData globalContext private agg amount)
    return (checkPayload SP1 (TransferToPublic eatd))

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
    in  case S.runGet (getPayload spv (fromIntegral (BS.length bs))) bs of
            Left err -> counterexample err False
            Right e' -> label (groupIntoSize (fromIntegral (BS.length bs))) $ e === e'

modifyPayloadBitmap :: (Word16 -> Word16) -> BS.ByteString -> BS.ByteString
modifyPayloadBitmap f bs =
    let Right ((header, bitmap), rest) = S.runGetState ((,) <$> S.getWord8 <*> S.getWord16be) bs 0
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

genInvalidPayloadConfigureBaker :: Gen BS.ByteString
genInvalidPayloadConfigureBaker = do
    bs <- S.runPut . putPayload <$> genPayloadConfigureBaker
    genPayloadWithInvalidBitmap 10 bs

genInvalidPayloadConfigureDelegation :: Gen BS.ByteString
genInvalidPayloadConfigureDelegation = do
    bs <- S.runPut . putPayload <$> genPayloadConfigureDelegation
    genPayloadWithInvalidBitmap 3 bs

genInvalidPayloadByteString :: Gen BS.ByteString
genInvalidPayloadByteString =
    oneof [genInvalidPayloadConfigureBaker, genInvalidPayloadConfigureDelegation]

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
    describe "Negative payload serialization tests" $
        negativeTest SP4 20 200
    describe "Encrypted transfer payloads" $ do
        specify "Encrypted transfer" $ testSerializeEncryptedTransfer
        specify "Transfer to public" $ testSecToPubTransfer
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
            $ forAll (resize size genInvalidPayloadByteString) (checkInvalidPayloadByteString spv)
