module Types.TransactionSerializationSpec where

import Test.Hspec
import Test.QuickCheck as QC

import qualified Data.ByteString as BS
import Data.Monoid (getSum)
import Data.Serialize

import Concordium.Types
import Concordium.Types.Transactions
import Generators

groupIntoSize :: (Show a, Integral a) => a -> String
groupIntoSize s =
    let kb = s
        nd = if kb > 0 then truncate (logBase 10 (fromIntegral kb) :: Double) else 0 :: Int
    in  if nd == 0
            then show kb ++ "B"
            else
                let lb = 10 ^ nd :: Integer
                    ub = 10 ^ (nd + 1) :: Integer
                in  show lb ++ " -- " ++ show ub ++ "B"

-- | Check that a transaction can be serialized and deserialized.
checkTransaction :: (Eq a, Show a, Serialize a) => a -> Property
checkTransaction tx =
    let bs = encode tx
    in  case decode bs of
            Left err -> counterexample err False
            Right tx' -> QC.label (groupIntoSize (BS.length bs)) $ tx === tx'

testAccountTransaction :: Property
testAccountTransaction = forAll genAccountTransaction checkTransaction

testAccountTransactionV1 :: Property
testAccountTransactionV1 = forAll genAccountTransactionV1 checkTransaction

dummyTime :: TransactionTime
dummyTime = 37

-- | Check V0 serialization of block items.
checkBlockItem :: SProtocolVersion pv -> BlockItem -> Property
checkBlockItem spv bi =
    case runGet (getBlockItemV0 spv (wmdArrivalTime bi)) bs of
        Left err -> counterexample err False
        Right bi' -> QC.label (groupIntoSize (BS.length bs)) $ bi === bi'
  where
    bs = runPut . putBareBlockItemV0 $ wmdData bi

testBlockItem :: SProtocolVersion pv -> Property
testBlockItem spv = forAll genBlockItem $ checkBlockItem spv

checkBlockItemExtendedTransaction :: SProtocolVersion pv -> BlockItem -> Property
checkBlockItemExtendedTransaction spv bi =
    case runGet (getBlockItemV0 spv (wmdArrivalTime bi)) bs of
        Left err ->
            if (pv < 10)
                then property True
                else counterexample err False
        Right bi' ->
            if (pv >= 10)
                then checkBlockItem spv bi'
                else counterexample "Expected deserialization to fail but it succeeded" False
  where
    bs = runPut . putBareBlockItemV0 $ wmdData bi
    pv = protocolVersionToWord64 $ demoteProtocolVersion spv

testBlockItemExtendedTransaction :: SProtocolVersion pv -> Property
testBlockItemExtendedTransaction spv = forAll genBlockItemTransactionExt $ checkBlockItemExtendedTransaction spv

-- | Test that 'transactionHeaderSize' reflects the size of serialized 'TransactionHeader's.
testAccountTransactionHeaderSize :: Property
testAccountTransactionHeaderSize = forAll genTransactionHeader $ \th ->
    fromIntegral (BS.length (encode th)) === transactionHeaderSize

-- | Test that 'getTransactionHeaderPayloadSize' reflects the size of serialized header + payloads.
testGetTransactionHeaderPayloadSize :: Property
testGetTransactionHeaderPayloadSize = forAll genAccountTransaction $ \AccountTransaction{..} ->
    fromIntegral (BS.length (runPut $ put atrHeader >> putEncodedPayload atrPayload))
        === getTransactionHeaderPayloadSize atrHeader

-- | Test that 'transactionHeaderV1Size' reflects the size of serialized 'TransactionHeaderV1's.
testAccountTransactionHeaderV1Size :: Property
testAccountTransactionHeaderV1Size = forAll genTransactionHeaderV1 $ \th ->
    QC.label ("size: " ++ show (transactionHeaderV1Size th)) $
        fromIntegral (BS.length (encode th)) === transactionHeaderV1Size th

-- | Test that 'getTransactionV1HeaderPayloadSize' reflects the size of serialized
--  V1 header + payloads.
testGetTransactionV1HeaderPayloadSize :: Property
testGetTransactionV1HeaderPayloadSize = forAll genAccountTransactionV1 $ \AccountTransactionV1{..} ->
    fromIntegral (BS.length (runPut $ put atrv1Header <> putEncodedPayload atrv1Payload))
        === getTransactionV1HeaderPayloadSize atrv1Header

-- | Test 'transactionBaseCost' for 'AccountTransaction's.
testTransactionBaseCostAccountTransaction :: Property
testTransactionBaseCostAccountTransaction = forAll genAccountTransaction $ \atr@AccountTransaction{..} ->
    fromIntegral (transactionBaseCost atr)
        === getTransactionHeaderPayloadSize atrHeader
            + 100 * getSum (foldMap (foldMap (const 1)) $ tsSignatures atrSignature)

-- | Test 'transactionBaseCost' for 'AccountTransactionV1's.
testTransactionBaseCostAccountTransactionV1 :: Property
testTransactionBaseCostAccountTransactionV1 = forAll genAccountTransactionV1 $ \atr@AccountTransactionV1{..} ->
    fromIntegral (transactionBaseCost atr)
        === getTransactionV1HeaderPayloadSize atrv1Header
            + 100
                * getSum
                    ( (foldMap (foldMap (const 1)) $ tsSignatures (tsv1Sender atrv1Signature))
                        + (foldMap (foldMap (foldMap (const 1)) . tsSignatures) $ tsv1Sponsor atrv1Signature)
                    )

tests :: Spec
tests = parallel $ do
    specify "Transaction serialization." $ withMaxSuccess 1000 testAccountTransaction
    specify "TransactionV1 serialization." $ withMaxSuccess 1000 testAccountTransactionV1

    specify "BlockItem serialization in P1." $ withMaxSuccess 100 $ testBlockItem SP1
    specify "BlockItem serialization in P2." $ withMaxSuccess 100 $ testBlockItem SP2
    specify "BlockItem serialization in P3." $ withMaxSuccess 100 $ testBlockItem SP3
    specify "BlockItem serialization in P4." $ withMaxSuccess 100 $ testBlockItem SP4
    specify "BlockItem serialization in P5." $ withMaxSuccess 100 $ testBlockItem SP5
    specify "BlockItem serialization in P6." $ withMaxSuccess 100 $ testBlockItem SP6
    specify "BlockItem serialization in P7." $ withMaxSuccess 100 $ testBlockItem SP7
    specify "BlockItem serialization in P8." $ withMaxSuccess 100 $ testBlockItem SP8
    specify "BlockItem serialization in P9." $ withMaxSuccess 100 $ testBlockItem SP9

    specify "BlockItem ExtendedTransaction serialization in P1." $ withMaxSuccess 100 $ testBlockItemExtendedTransaction SP1
    specify "BlockItem ExtendedTransaction serialization in P2." $ withMaxSuccess 100 $ testBlockItemExtendedTransaction SP2
    specify "BlockItem ExtendedTransaction serialization in P3." $ withMaxSuccess 100 $ testBlockItemExtendedTransaction SP3
    specify "BlockItem ExtendedTransaction serialization in P4." $ withMaxSuccess 100 $ testBlockItemExtendedTransaction SP4
    specify "BlockItem ExtendedTransaction serialization in P5." $ withMaxSuccess 100 $ testBlockItemExtendedTransaction SP5
    specify "BlockItem ExtendedTransaction serialization in P6." $ withMaxSuccess 100 $ testBlockItemExtendedTransaction SP6
    specify "BlockItem ExtendedTransaction serialization in P7." $ withMaxSuccess 100 $ testBlockItemExtendedTransaction SP7
    specify "BlockItem ExtendedTransaction serialization in P8." $ withMaxSuccess 100 $ testBlockItemExtendedTransaction SP8
    specify "BlockItem ExtendedTransaction serialization in P9." $ withMaxSuccess 100 $ testBlockItemExtendedTransaction SP9

    specify "TransactionHeader serialization matches transactionHeaderSize." $ testAccountTransactionHeaderSize
    specify "TransactionHeader + payload serialization matches getTransactionHeaderPayloadSize" $ testGetTransactionHeaderPayloadSize
    specify "TransactionHeaderV1 serialization matches transactionHeaderV1Size." $ testAccountTransactionHeaderV1Size
    specify "TransactionHeaderV1 + payload serialization matches getTransactionV1HeaderPayloadSize" $ testGetTransactionV1HeaderPayloadSize

    specify "transactionBaseCost for AccountTransaction. " $ testTransactionBaseCostAccountTransaction
    specify "transactionBaseCost for AccountTransactionV1. " $ testTransactionBaseCostAccountTransactionV1
