{-# OPTIONS_GHC -fno-warn-orphans #-}

module Types.TransactionSummarySpec where

import qualified Data.ByteString.Short as SBS
import Data.Serialize
import qualified Data.Aeson as AE
import Test.Hspec
import Test.QuickCheck

import qualified Concordium.Crypto.BlockSignature as BlockSig
import Concordium.Crypto.DummyData
import Concordium.Crypto.EncryptedTransfers
import Concordium.Crypto.SHA256 (Hash (Hash))
import qualified Concordium.Crypto.VRF as VRF
import Concordium.ID.Types (AccountThreshold (..), CredentialType (..))
import Concordium.Types
import Concordium.Types.Execution
import qualified Concordium.Wasm as Wasm
import qualified Data.FixedByteString as FBS

import Types.AmountSpec (genAmount)
import Types.PayloadSerializationSpec hiding (genAddress)
import Types.TransactionGen (genAccountAddress)
import Types.UpdatesSpec (genUpdatePayload)

transactionTypes :: [TransactionType]
transactionTypes =
    [ TTDeployModule,
      TTInitContract,
      TTUpdate,
      TTTransfer,
      TTAddBaker,
      TTRemoveBaker,
      TTUpdateBakerStake,
      TTUpdateBakerRestakeEarnings,
      TTUpdateBakerKeys,
      TTUpdateCredentialKeys,
      TTEncryptedAmountTransfer,
      TTTransferToEncrypted,
      TTTransferToPublic,
      TTTransferWithSchedule,
      TTUpdateCredentials,
      TTRegisterData,
      TTTransferWithMemo,
      TTEncryptedAmountTransferWithMemo,
      TTTransferWithScheduleAndMemo
    ]

instance Arbitrary TransactionType where
    arbitrary = elements transactionTypes

testTransactionTypesSerialIdentity :: Expectation
testTransactionTypesSerialIdentity = mapM_ testEncDec transactionTypes
  where
    testEncDec tt = decode (encode tt) `shouldBe` Right tt

genEncryptedAmount :: Gen EncryptedAmount
genEncryptedAmount = EncryptedAmount <$> genElgamalCipher <*> genElgamalCipher

genContractEvent :: Gen Wasm.ContractEvent
genContractEvent = Wasm.ContractEvent . SBS.pack <$> arbitrary

genAddress :: Gen Address
genAddress = oneof [AddressAccount <$> genAccountAddress, AddressContract <$> genCAddress]

genTransactionTime :: Gen TransactionTime
genTransactionTime = TransactionTime <$> arbitrary

genTimestamp :: Gen Timestamp
genTimestamp = Timestamp <$> arbitrary

genRegisteredData :: Gen RegisteredData
genRegisteredData = do
    len <- choose (0, maxRegisteredDataSize)
    RegisteredData . SBS.pack <$> vector len

genMemo :: Gen Memo
genMemo = do
    len <- choose (0, maxMemoSize)
    Memo . SBS.pack <$> vector len

genBakerId :: Gen BakerId
genBakerId = BakerId . AccountIndex <$> arbitrary

instance Arbitrary Event where
    arbitrary =
        oneof
            [ ModuleDeployed <$> genModuleRef,
              ContractInitialized <$> genModuleRef <*> genCAddress <*> genAmount <*> genInitName <*> genWasmVersion <*> listOf genContractEvent,
              Updated <$> genCAddress <*> genAddress <*> genAmount <*> genParameter <*> genReceiveName <*> genWasmVersion <*> listOf genContractEvent,
              Transferred <$> genAddress <*> genAmount <*> genAddress,
              AccountCreated <$> genAccountAddress,
              CredentialDeployed <$> genCredentialId <*> genAccountAddress,
              genBakerAdded,
              BakerRemoved <$> genBakerId <*> genAccountAddress,
              BakerStakeIncreased <$> genBakerId <*> genAccountAddress <*> genAmount,
              BakerStakeDecreased <$> genBakerId <*> genAccountAddress <*> genAmount,
              BakerSetRestakeEarnings <$> genBakerId <*> genAccountAddress <*> arbitrary,
              genBakerKeysUpdated,
              CredentialKeysUpdated <$> genCredentialId,
              NewEncryptedAmount <$> genAccountAddress <*> (EncryptedAmountIndex <$> arbitrary) <*> genEncryptedAmount,
              EncryptedAmountsRemoved <$> genAccountAddress <*> genEncryptedAmount <*> genEncryptedAmount <*> (EncryptedAmountAggIndex <$> arbitrary),
              AmountAddedByDecryption <$> genAccountAddress <*> genAmount,
              EncryptedSelfAmountAdded <$> genAccountAddress <*> genEncryptedAmount <*> genAmount,
              UpdateEnqueued <$> genTransactionTime <*> genUpdatePayload,
              genTransferredWithSchedule,
              genCredentialsUpdated,
              DataRegistered <$> genRegisteredData,
              TransferMemo <$> genMemo,
              Interrupted <$> genCAddress <*> listOf genContractEvent,
              Resumed <$> genCAddress <*> arbitrary
            ]
      where
        genWasmVersion = elements [Wasm.V0, Wasm.V1]
        genBakerAdded = do
            ebaBakerId <- genBakerId
            ebaAccount <- genAccountAddress
            ebaSignKey <- BlockSig.verifyKey <$> genBlockKeyPair
            ebaElectionKey <- VRF.publicKey <$> arbitrary
            (ebaAggregationKey, _) <- genAggregationVerifyKeyAndProof
            ebaStake <- arbitrary
            ebaRestakeEarnings <- arbitrary
            return BakerAdded{..}
        genBakerKeysUpdated = do
            ebkuBakerId <- genBakerId
            ebkuAccount <- genAccountAddress
            ebkuSignKey <- BlockSig.verifyKey <$> genBlockKeyPair
            ebkuElectionKey <- VRF.publicKey <$> arbitrary
            (ebkuAggregationKey, _) <- genAggregationVerifyKeyAndProof
            return BakerKeysUpdated{..}
        genTransferredWithSchedule = do
            etwsFrom <- genAccountAddress
            etwsTo <- genAccountAddress
            etwsAmount <- listOf ((,) <$> genTimestamp <*> genAmount)
            return TransferredWithSchedule{..}
        genCredentialsUpdated = do
            cuAccount <- genAccountAddress
            cuNewCredIds <- listOf genCredentialId
            cuRemovedCredIds <- listOf genCredentialId
            cuNewThreshold <- AccountThreshold <$> choose (1, maxBound)
            return CredentialsUpdated{..}

-- |Test that decoding is the inverse of encoding for 'Event's.
testEventSerializationIdentity :: Event -> Property
testEventSerializationIdentity e = decode (encode e) === Right e

-- |Test that decoding is the inverse of encoding for 'Event's.
testEventJSONSerializationIdentity :: Event -> Property
testEventJSONSerializationIdentity e = AE.eitherDecode (AE.encode e) === Right e

instance Arbitrary RejectReason where
    arbitrary =
        oneof
            [ return ModuleNotWF,
              ModuleHashAlreadyExists <$> genModuleRef,
              InvalidAccountReference <$> genAccountAddress,
              InvalidInitMethod <$> genModuleRef <*> genInitName,
              InvalidReceiveMethod <$> genModuleRef <*> genReceiveName,
              InvalidModuleReference <$> genModuleRef,
              InvalidContractAddress <$> genCAddress,
              return RuntimeFailure,
              AmountTooLarge <$> genAddress <*> genAmount,
              return SerializationFailure,
              return OutOfEnergy,
              RejectedInit <$> arbitrary,
              RejectedReceive <$> arbitrary <*> genCAddress <*> genReceiveName <*> genParameter,
              NonExistentRewardAccount <$> genAccountAddress,
              return InvalidProof,
              AlreadyABaker <$> genBakerId,
              NotABaker <$> genAccountAddress,
              return InsufficientBalanceForBakerStake,
              return StakeUnderMinimumThresholdForBaking,
              return BakerInCooldown,
              DuplicateAggregationKey . fst <$> genAggregationVerifyKeyAndProof,
              return NonExistentCredentialID,
              return KeyIndexAlreadyInUse,
              return InvalidAccountThreshold,
              return InvalidCredentialKeySignThreshold,
              return InvalidEncryptedAmountTransferProof,
              return InvalidTransferToPublicProof,
              EncryptedAmountSelfTransfer <$> genAccountAddress,
              return InvalidIndexOnEncryptedTransfer,
              return ZeroScheduledAmount,
              return NonIncreasingSchedule,
              return FirstScheduledReleaseExpired,
              ScheduledSelfTransfer <$> genAccountAddress,
              return InvalidCredentials,
              DuplicateCredIDs <$> listOf genCredentialId,
              NonExistentCredIDs <$> listOf genCredentialId,
              return RemoveFirstCredential,
              return CredentialHolderDidNotSign,
              return NotAllowedMultipleCredentials,
              return NotAllowedToReceiveEncrypted,
              return NotAllowedToHandleEncrypted
            ]

-- |Test that decoding is the inverse of encoding for 'RejectReason's.
testRejectReasonSerializationIdentity :: RejectReason -> Property
testRejectReasonSerializationIdentity e = decode (encode e) === Right e

instance Arbitrary ValidResult where
    arbitrary =
        oneof
            [ TxSuccess <$> arbitrary,
              TxReject <$> arbitrary
            ]

-- |Test that decoding is the inverse of encoding for 'ValidResult's.
testValidResultSerializationIdentity :: ValidResult -> Property
testValidResultSerializationIdentity e = decode (encode e) === Right e

instance Arbitrary TransactionSummary where
    arbitrary = do
        tsSender <- oneof [return Nothing, Just <$> genAccountAddress]
        tsHash <- TransactionHashV0 . Hash . FBS.pack <$> vector 32
        tsCost <- genAmount
        tsEnergyCost <- Energy <$> arbitrary
        tsType <-
            oneof
                [ TSTAccountTransaction <$> arbitrary,
                  TSTCredentialDeploymentTransaction <$> elements [Initial, Normal],
                  TSTUpdateTransaction <$> arbitraryBoundedEnum
                ]
        tsResult <- arbitrary
        tsIndex <- TransactionIndex <$> arbitrary
        return TransactionSummary{..}

-- |Test that decoding is the inverse of encoding for 'TransactionSummary's.
testTransactionSummarySerializationIdentity :: TransactionSummary -> Property
testTransactionSummarySerializationIdentity e = decode (encode e) === Right e

tests :: Spec
tests = describe "Transaction summaries" $ do
    specify "TransactionType: serialize then deserialize is identity" testTransactionTypesSerialIdentity
    specify "Event: serialize then deserialize is identity" $ withMaxSuccess 10000 testEventSerializationIdentity
    specify "Event: JSON serialize then deserialize is identity" $ withMaxSuccess 10000 testEventJSONSerializationIdentity
    specify "RejectReason: serialize then deserialize is identity" $ withMaxSuccess 10000 testRejectReasonSerializationIdentity
    specify "ValidResult: serialize then deserialize is identity" $ withMaxSuccess 1000 testValidResultSerializationIdentity
    specify "TransactionSummary: serialize then deserialize is identity" $ withMaxSuccess 1000 testTransactionSummarySerializationIdentity
