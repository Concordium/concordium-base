{-# OPTIONS_GHC -Wno-deprecations #-}
module Types.PayloadSerializationSpec where

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck.Monadic
import Test.QuickCheck

import qualified Data.ByteString as BS
import qualified Data.Serialize as S
import Data.Int

import Concordium.ID.Types
import Concordium.ID.DummyData
import Concordium.Crypto.EncryptedTransfers
import Concordium.Crypto.FFIDataTypes

import Concordium.Types.Execution
import Concordium.Types

import Types.Generators

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
  in if nd == 0 then show kb ++ "kB"
     else let lb = 10^nd :: Int
              ub = 10^(nd+1) :: Int
          in show lb ++ " -- " ++ show ub ++ "kB"

checkPayload :: SProtocolVersion pv -> Payload -> Property
checkPayload spv e = let bs = S.runPut $ putPayload e
                 in case S.runGet (getPayload spv (fromIntegral (BS.length bs))) bs of
                      Left err -> counterexample err False
                      Right e' -> label (groupIntoSize (fromIntegral (BS.length bs))) $ e === e'

tests :: Spec
tests = do
  describe "Payload serialization tests" $ do
    test SP3 25 1000
    test SP3 50 500
    test SP4 25 1000
    test SP4 50 500
  describe "Encrypted transfer payloads" $ do
    specify "Encrypted transfer" $ testSerializeEncryptedTransfer
    specify "Transfer to public" $ testSecToPubTransfer
 where test spv size num =
         modifyMaxSuccess (const num) $
           specify ("Payload serialization (" ++ show (demoteProtocolVersion spv) 
              ++ ") with size = " ++ show size ++ ":") $
                forAll (resize size $ genPayload (demoteProtocolVersion spv)) (checkPayload spv)
