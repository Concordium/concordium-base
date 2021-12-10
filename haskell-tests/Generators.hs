{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Generators where

import Test.QuickCheck

import Control.Monad
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as BSS
import Data.Word
import Data.Ratio
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TE
import Data.Time.Clock
import qualified Data.Vector as Vec
import qualified Data.Sequence as Seq
import System.IO.Unsafe
import System.Random

import Concordium.Common.Time
import Concordium.Constants
import qualified Concordium.Crypto.BlockSignature as BlockSig
import qualified Concordium.Crypto.BlsSignature as Bls
import Concordium.Crypto.DummyData
import Concordium.Crypto.EncryptedTransfers
import Concordium.Crypto.FFIDataTypes
import Concordium.Crypto.Proofs
import qualified Concordium.Crypto.SHA256 as SHA256
import Concordium.Crypto.SignatureScheme
import qualified Concordium.Crypto.VRF as VRF
import Concordium.ID.DummyData
import Concordium.ID.Types
import Concordium.Types
import Concordium.Types.Execution
import Concordium.Types.Transactions
import Concordium.Types.Updates
import Concordium.Types.Parameters
import Concordium.Genesis.Parameters
import qualified Concordium.Wasm as Wasm
import qualified Data.FixedByteString as FBS

genAmount :: Gen Amount
genAmount = Amount <$> arbitrary

genAttributeValue :: Gen AttributeValue
genAttributeValue = AttributeValue . BSS.pack <$> (vector =<< choose (0, 31))

genDlogProof :: Gen Dlog25519Proof
genDlogProof = fst . randomProof . mkStdGen <$> resize 100000 arbitrary

genAccountOwnershipProof :: Gen AccountOwnershipProof
genAccountOwnershipProof = do
    n <- choose (1, 255)
    AccountOwnershipProof
        <$> replicateM
            n
            ( do
                keyIndex <- KeyIndex <$> arbitrary
                proof <- genDlogProof
                return (keyIndex, proof)
            )

genAggregationVerifyKeyAndProof :: Gen (BakerAggregationVerifyKey, BakerAggregationProof)
genAggregationVerifyKeyAndProof = do
    c <- arbitrary
    sk <- secretBlsKeyGen
    -- FIXME: The use of unsafePerformIO here is wrong, but I'm in a hurry.
    -- The randomness is used to get the zero-knowledge property
    -- We need to expose a deterministic "prove" function from rust that takes a seed.
    return (Bls.derivePublicKey sk, unsafePerformIO $ Bls.proveKnowledgeOfSK (BS.pack c) sk)

genAccountAddress :: Gen AccountAddress
genAccountAddress = AccountAddress . FBS.pack <$> vector accountAddressSize

genAccountAliases :: AccountAddress -> Gen AccountAddress
genAccountAliases (AccountAddress addr) = do
  suffix <- vector 3
  return $ AccountAddress . FBS.pack $ (take accountAddressPrefixSize (FBS.unpack addr) ++ suffix)

genCAddress :: Gen ContractAddress
genCAddress = ContractAddress <$> (ContractIndex <$> arbitrary) <*> (ContractSubindex <$> arbitrary)

genModuleRef :: Gen ModuleRef
genModuleRef = ModuleRef . SHA256.hash . BS.pack <$> vector 32

-- These generators name contracts as numbers to make sure the names are valid.
genInitName :: Gen Wasm.InitName
genInitName =
    Wasm.InitName . Text.pack . ("init_" ++) . show <$> (arbitrary :: Gen Word)

genReceiveName :: Gen Wasm.ReceiveName
genReceiveName = do
    contract <- show <$> (arbitrary :: Gen Word)
    receive <- show <$> (arbitrary :: Gen Word)
    return . Wasm.ReceiveName . Text.pack $ receive ++ "." ++ contract

genParameter :: Gen Wasm.Parameter
genParameter = do
    n <- choose (0, 1000)
    Wasm.Parameter . BSS.pack <$> vector n

genUrlText :: Gen UrlText
genUrlText =
    UrlText
        <$> suchThat
            (Text.pack <$> scale (min (fromIntegral maxUrlTextLength)) (listOf arbitrary))
            ((<= fromIntegral maxUrlTextLength) . BS.length . TE.encodeUtf8)

genRewardFraction :: Gen RewardFraction
genRewardFraction = makeRewardFraction <$> arbitrary `suchThat` (<= 100000)

genInclusiveRangeOfRewardFraction :: Gen (InclusiveRange RewardFraction)
genInclusiveRangeOfRewardFraction = do
    (irMin, irMax) <- ((,) <$> genRewardFraction <*> genRewardFraction)
                        `suchThat` (\(i0, i1) -> i0 <= i1)
    return InclusiveRange{..}

genPayload :: ProtocolVersion -> Gen Payload
genPayload pv =
    oneof $
        [ genPayloadDeployModule,
          genPayloadInitContract,
          genPayloadUpdate,
          genPayloadTransfer,
          genPayloadUpdateCredentials,
          genPayloadUpdateCredentialKeys,
          genPayloadTransferToEncrypted,
          genPayloadRegisterData
        ]
            ++ if pv < P4
                then
                    [ genPayloadAddBaker,
                      genPayloadRemoveBaker,
                      genPayloadUpdateBakerStake,
                      genPayloadUpdateBakerRestateEarnings,
                      genPayloadUpdateBakerKeys
                    ]
                else
                    [ genPayloadConfigureBaker,
                      genPayloadConfigureDelegation
                    ]

genPayloadUpdateCredentials :: Gen Payload
genPayloadUpdateCredentials = do
    maxNumCredentials <- choose (0, 255)
    indices <- Set.fromList . map CredentialIndex <$> replicateM maxNumCredentials (choose (0, 255))
    -- the actual number of key indices. Duplicate key indices might have been generated.
    let numCredentials = Set.size indices
    credentials <- replicateM numCredentials genCredentialDeploymentInformation
    ucNewThreshold <- AccountThreshold <$> choose (1, 255) -- since we are only updating there is no requirement that the threshold is less than the amount of credentials
    toRemoveLen <- choose (0, 30)
    ucRemoveCredIds <- replicateM toRemoveLen genCredentialId
    return UpdateCredentials{ucNewCredInfos = Map.fromList (zip (Set.toList indices) credentials), ..}

genByteString :: Gen BS.ByteString
genByteString = do
    n <- choose (0, 1000)
    BS.pack <$> vector n

genPayloadDeployModule :: Gen Payload
genPayloadDeployModule = DeployModule <$> (Wasm.WasmModule 0 . Wasm.ModuleSource <$> genByteString)

genPayloadInitContract :: Gen Payload
genPayloadInitContract = do
    icAmount <- Amount <$> arbitrary
    icModRef <- genModuleRef
    icInitName <- genInitName
    icParam <- genParameter
    return InitContract{..}

genPayloadUpdate :: Gen Payload
genPayloadUpdate = do
    uAmount <- Amount <$> arbitrary
    uAddress <- genCAddress
    uMessage <- genParameter
    uReceiveName <- genReceiveName
    return Update{..}

genPayloadTransfer :: Gen Payload
genPayloadTransfer = do
    a <- genAccountAddress
    amnt <- Amount <$> arbitrary
    return $ Transfer a amnt

genPayloadAddBaker :: Gen Payload
genPayloadAddBaker = do
    abElectionVerifyKey <- VRF.publicKey <$> arbitrary
    abSignatureVerifyKey <- BlockSig.verifyKey <$> genBlockKeyPair
    (abAggregationVerifyKey, abProofAggregation) <- genAggregationVerifyKeyAndProof
    abProofSig <- genDlogProof
    abProofElection <- genDlogProof
    abBakingStake <- arbitrary
    abRestakeEarnings <- arbitrary
    return AddBaker{..}

genPayloadRemoveBaker :: Gen Payload
genPayloadRemoveBaker = return RemoveBaker

genPayloadUpdateBakerStake :: Gen Payload
genPayloadUpdateBakerStake = UpdateBakerStake <$> arbitrary

genPayloadUpdateBakerRestateEarnings :: Gen Payload
genPayloadUpdateBakerRestateEarnings = UpdateBakerRestakeEarnings <$> arbitrary

genPayloadUpdateBakerKeys :: Gen Payload
genPayloadUpdateBakerKeys = do
    ubkElectionVerifyKey <- VRF.publicKey <$> arbitrary
    ubkSignatureVerifyKey <- BlockSig.verifyKey <$> genBlockKeyPair
    (ubkAggregationVerifyKey, ubkProofAggregation) <- genAggregationVerifyKeyAndProof
    ubkProofSig <- genDlogProof
    ubkProofElection <- genDlogProof
    return UpdateBakerKeys{..}

genPayloadUpdateCredentialKeys :: Gen Payload
genPayloadUpdateCredentialKeys = do
    uckKeys <- genCredentialPublicKeys
    uckCredId <- genCredentialId
    return UpdateCredentialKeys{..}

genPayloadTransferToEncrypted :: Gen Payload
genPayloadTransferToEncrypted = TransferToEncrypted . Amount <$> arbitrary

genPayloadRegisterData :: Gen Payload
genPayloadRegisterData = do
    n <- chooseInt (0, maxRegisteredDataSize)
    rdData <- RegisteredData . BSS.pack <$> vectorOf n arbitrary
    return RegisterData{..}

genPayloadConfigureBaker :: Gen Payload
genPayloadConfigureBaker = do
    cbCapital <- arbitrary
    cbRestakeEarnings <- arbitrary
    cbOpenForDelegation <- liftArbitrary $ elements [OpenForAll, ClosedForNew, ClosedForAll]
    cbSignatureVerifyKey <-
        liftArbitrary $
            (,) <$> (BlockSig.verifyKey <$> genBlockKeyPair) <*> genDlogProof
    cbElectionVerifyKey <-
        liftArbitrary $
            (,) <$> (VRF.publicKey <$> arbitrary) <*> genDlogProof
    cbAggregationVerifyKey <- liftArbitrary genAggregationVerifyKeyAndProof
    cbMetadataURL <- liftArbitrary genUrlText
    cbTransactionFeeCommission <- liftArbitrary genRewardFraction
    cbBakingRewardCommission <- liftArbitrary genRewardFraction
    cbFinalizationRewardCommission <- liftArbitrary genRewardFraction
    return ConfigureBaker{..}

genPayloadConfigureDelegation :: Gen Payload
genPayloadConfigureDelegation = do
    cdCapital <- arbitrary
    cdRestakeEarnings <- arbitrary
    cdDelegationTarget <-
        liftArbitrary $
            oneof [return DelegateToLPool, DelegateToBaker . BakerId . AccountIndex <$> arbitrary]
    return ConfigureDelegation{..}

genCredentialId :: Gen CredentialRegistrationID
genCredentialId = RegIdCred . generateGroupElementFromSeed globalContext <$> arbitrary

genSignThreshold :: Gen SignatureThreshold
genSignThreshold = SignatureThreshold <$> choose (1, 255)

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
    maxLen <- choose (1 :: Int, 255)
    let go is _ 0 = return is
        go is nextIdx n = do
            nextIndex <- choose (nextIdx, 255)
            if nextIndex == 255
                then return (KeyIndex nextIndex : is)
                else go (KeyIndex nextIndex : is) (nextIndex + 1) (n -1)
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

genPolicy :: Gen Policy
genPolicy = do
    let ym = YearMonth <$> choose (1000, 9999) <*> choose (1, 12)
    pValidTo <- ym
    pCreatedAt <- ym
    let pItems = Map.empty
    return Policy{..}

genCredentialDeploymentInformation :: Gen CredentialDeploymentInformation
genCredentialDeploymentInformation = do
    cdvPublicKeys <- genCredentialPublicKeys
    cdvCredId <- RegIdCred . generateGroupElementFromSeed globalContext <$> arbitrary
    cdvIpId <- IP_ID <$> arbitrary
    cdvArData <-
        Map.fromList
            <$> listOf
                ( do
                    ardName <- do
                        n <- arbitrary
                        if n == 0 then return (ArIdentity 1) else return (ArIdentity n)
                    ardIdCredPubShare <- AREnc <$> genElgamalCipher
                    return (ardName, ChainArData{..})
                )
    cdvThreshold <- Threshold <$> choose (1, max 1 (fromIntegral (length cdvArData)))
    cdvPolicy <- genPolicy
    cdiProofs <- do
        l <- choose (0, 10000)
        Proofs . BSS.pack <$> vector l
    let cdiValues = CredentialDeploymentValues{..}
    return CredentialDeploymentInformation{..}

genCommissionRates :: Gen CommissionRates
genCommissionRates =
    CommissionRates <$> genRewardFraction <*> genRewardFraction <*> genRewardFraction

genCommissionRanges :: Gen CommissionRanges
genCommissionRanges =
    CommissionRanges <$> genInclusiveRangeOfRewardFraction
                     <*> genInclusiveRangeOfRewardFraction
                     <*> genInclusiveRangeOfRewardFraction

genChainParametersV0 :: Gen (ChainParameters' 'ChainParametersV0)
genChainParametersV0 = do
    _cpElectionDifficulty <- genElectionDifficulty
    _cpExchangeRates <- genExchangeRates
    _cpCooldownParameters <- genCooldownParametersV0
    _cpTimeParameters <- genTimeParametersV0
    _cpAccountCreationLimit <- arbitrary
    _cpRewardParameters <- genRewardParameters
    _cpFoundationAccount <- AccountIndex <$> arbitrary
    _cpPoolParameters <- genPoolParametersV0
    return ChainParameters{..}

genChainParametersV1 :: Gen (ChainParameters' 'ChainParametersV1)
genChainParametersV1 = do
    _cpElectionDifficulty <- genElectionDifficulty
    _cpExchangeRates <- genExchangeRates
    _cpCooldownParameters <- genCooldownParametersV1
    _cpTimeParameters <- genTimeParametersV1
    _cpAccountCreationLimit <- arbitrary
    _cpRewardParameters <- genRewardParameters
    _cpFoundationAccount <- AccountIndex <$> arbitrary
    _cpPoolParameters <- genPoolParametersV1
    return ChainParameters{..}

genGenesisChainParametersV0 :: Gen (GenesisChainParameters' 'ChainParametersV0)
genGenesisChainParametersV0 = do
    gcpElectionDifficulty <- genElectionDifficulty
    gcpExchangeRates <- genExchangeRates
    gcpCooldownParameters <- genCooldownParametersV0
    gcpTimeParameters <- genTimeParametersV0
    gcpAccountCreationLimit <- arbitrary
    gcpRewardParameters <- genRewardParameters
    gcpFoundationAccount <- genAccountAddress
    gcpPoolParameters <- genPoolParametersV0
    return GenesisChainParameters{..}

genGenesisChainParametersV1 :: Gen (GenesisChainParameters' 'ChainParametersV1)
genGenesisChainParametersV1 = do
    gcpElectionDifficulty <- genElectionDifficulty
    gcpExchangeRates <- genExchangeRates
    gcpCooldownParameters <- genCooldownParametersV1
    gcpTimeParameters <- genTimeParametersV1
    gcpAccountCreationLimit <- arbitrary
    gcpRewardParameters <- genRewardParameters
    gcpFoundationAccount <- genAccountAddress
    gcpPoolParameters <- genPoolParametersV1
    return GenesisChainParameters{..}

genCooldownParametersV0 :: Gen (CooldownParameters 'ChainParametersV0)
genCooldownParametersV0 = CooldownParametersV0 <$> arbitrary

genCooldownParametersV1 :: Gen (CooldownParameters 'ChainParametersV1)
genCooldownParametersV1 =
    CooldownParametersV1 <$> (RewardPeriod <$> arbitrary) <*> (RewardPeriod <$> arbitrary)

genTimeParametersV0 :: Gen (TimeParameters 'ChainParametersV0)
genTimeParametersV0 = return TimeParametersV0

genTimeParametersV1 :: Gen (TimeParameters 'ChainParametersV1)
genTimeParametersV1 = TimeParametersV1 <$> (RewardPeriodLength <$> arbitrary)

genPoolParametersV0 :: Gen (PoolParameters 'ChainParametersV0)
genPoolParametersV0 = PoolParametersV0 <$> arbitrary

genPoolParametersV1 :: Gen (PoolParameters 'ChainParametersV1)
genPoolParametersV1 = do
    _ppLPoolCommissions <- genCommissionRates
    _ppCommissionBounds <- genCommissionRanges
    _ppMinimumEquityCapital <- genAmount
    _ppMinimumFinalizationCapital <- genRewardFraction
    _ppCapitalBound <- genRewardFraction
    _ppLeverageBound <- genLeverageFactor
    return PoolParametersV1{..}

genRewardParameters :: Gen RewardParameters
genRewardParameters = do
    _rpMintDistribution <- genMintDistribution
    _rpTransactionFeeDistribution <- genTransactionFeeDistribution
    _rpGASRewards <- genGASRewards
    return RewardParameters{..}

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
      TTTransferWithScheduleAndMemo,
      TTConfigureBaker,
      TTConfigureDelegation
    ]

instance Arbitrary TransactionType where
    arbitrary = elements transactionTypes

genEncryptedAmount :: Gen EncryptedAmount
genEncryptedAmount = EncryptedAmount <$> genElgamalCipher <*> genElgamalCipher

genAccountEncryptedAmount :: Gen AccountEncryptedAmount
genAccountEncryptedAmount = do
  _selfAmount <- genEncryptedAmount
  _startIndex <- EncryptedAmountAggIndex <$> arbitrary
  len <- choose (0,100)
  _incomingEncryptedAmounts <- Seq.replicateM len genEncryptedAmount
  numAgg <- arbitrary
  aggAmount <- genEncryptedAmount
  if numAgg == Just 1 || numAgg == Just 0 then
    return AccountEncryptedAmount{_aggregatedAmount = Nothing,..}
  else
    return AccountEncryptedAmount{_aggregatedAmount = (aggAmount,) <$> numAgg,..}

genContractEvent :: Gen Wasm.ContractEvent
genContractEvent = Wasm.ContractEvent . BSS.pack <$> arbitrary

genAddress :: Gen Address
genAddress = oneof [AddressAccount <$> genAccountAddress, AddressContract <$> genCAddress]

genTransactionTime :: Gen TransactionTime
genTransactionTime = TransactionTime <$> arbitrary

genTimestamp :: Gen Timestamp
genTimestamp = Timestamp <$> arbitrary

genRegisteredData :: Gen RegisteredData
genRegisteredData = do
    len <- choose (0, maxRegisteredDataSize)
    RegisteredData . BSS.pack <$> vector len

genMemo :: Gen Memo
genMemo = do
    len <- choose (0, maxMemoSize)
    Memo . BSS.pack <$> vector len

genBakerId :: Gen BakerId
genBakerId = BakerId . AccountIndex <$> arbitrary

genEvent :: IsProtocolVersion pv => SProtocolVersion pv -> Gen Event
genEvent spv =
        oneof
            ([ ModuleDeployed <$> genModuleRef,
              ContractInitialized <$> genModuleRef <*> genCAddress <*> genAmount <*> genInitName <*> listOf genContractEvent,
              Updated <$> genCAddress <*> genAddress <*> genAmount <*> genParameter <*> genReceiveName <*> listOf genContractEvent,
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
              UpdateEnqueued <$> genTransactionTime <*> genUpdatePayload (chainParametersVersionFor spv),
              genTransferredWithSchedule,
              genCredentialsUpdated,
              DataRegistered <$> genRegisteredData
            ] ++ maybeMemo)
      where
        maybeMemo = if supportMemo then [TransferMemo <$> genMemo] else []
        supportMemo = case spv of
                SP1 -> False
                SP2 -> True
                SP3 -> True
                SP4 -> True
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

genValidResult :: IsProtocolVersion pv => SProtocolVersion pv -> Gen ValidResult
genValidResult spv =
        oneof
            [ TxSuccess <$> (liftArbitrary $ genEvent spv),
              TxReject <$> arbitrary
            ]

genTransactionSummary :: IsProtocolVersion pv => SProtocolVersion pv -> Gen TransactionSummary
genTransactionSummary spv = do
        tsSender <- oneof [return Nothing, Just <$> genAccountAddress]
        tsHash <- TransactionHashV0 . SHA256.Hash . FBS.pack <$> vector 32
        tsCost <- genAmount
        tsEnergyCost <- Energy <$> arbitrary
        tsType <-
            oneof
                [ TSTAccountTransaction <$> arbitrary,
                  TSTCredentialDeploymentTransaction <$> elements [Initial, Normal],
                  TSTUpdateTransaction <$> arbitraryBoundedEnum
                ]
        tsResult <- genValidResult spv
        tsIndex <- TransactionIndex <$> arbitrary
        return TransactionSummary{..}

schemes :: [SchemeId]
schemes = [Ed25519]

verifyKeys :: Vec.Vector VerifyKey
verifyKeys = unsafePerformIO $ Vec.replicateM 200 (correspondingVerifyKey <$> newKeyPair Ed25519)
{-# NOINLINE verifyKeys #-}

genVerifyKey :: Gen VerifyKey
genVerifyKey = do
    i <- choose (0, Vec.length verifyKeys - 1)
    return $ verifyKeys Vec.! i

genSchemeId :: Gen SchemeId
genSchemeId = elements schemes

genTransactionHeader :: Gen TransactionHeader
genTransactionHeader = do
    thSender <- genAccountAddress
    thPayloadSize <- PayloadSize <$> choose (0, maxPayloadSize)
    thNonce <- Nonce <$> arbitrary
    thEnergyAmount <- Energy <$> arbitrary
    thExpiry <- TransactionTime <$> arbitrary
    return $ TransactionHeader{..}

genAccountTransaction :: Gen AccountTransaction
genAccountTransaction = do
    atrHeader <- genTransactionHeader
    atrPayload <- EncodedPayload . BSS.pack <$> vector (fromIntegral (thPayloadSize atrHeader))
    numCredentials <- choose (1, 255)
    allKeys <- replicateM numCredentials $ do
        numKeys <- choose (1, 255)
        credentialSignatures <- replicateM numKeys $ do
            idx <- KeyIndex <$> arbitrary
            sLen <- choose (50, 70)
            sig <- Signature . BSS.pack <$> vector sLen
            return (idx, sig)
        (,Map.fromList credentialSignatures) . CredentialIndex <$> arbitrary

    let atrSignature = TransactionSignature (Map.fromList allKeys)
    return $! makeAccountTransaction atrSignature atrHeader atrPayload

baseTime :: UTCTime
baseTime = read "2019-09-23 13:27:13.257285424 UTC"

genTransaction :: Gen Transaction
genTransaction = do
    wmdData <- genAccountTransaction
    wmdArrivalTime <- TransactionTime <$> arbitrary
    return $ addMetadata NormalTransaction wmdArrivalTime wmdData

genInitialCredentialDeploymentInformation :: Gen InitialCredentialDeploymentInfo
genInitialCredentialDeploymentInformation = do
    icdvAccount <- genCredentialPublicKeys
    icdvRegId <- RegIdCred . generateGroupElementFromSeed globalContext <$> arbitrary
    icdvIpId <- IP_ID <$> arbitrary
    icdvPolicy <- genPolicy
    let icdiValues = InitialCredentialDeploymentValues{..}
    icdiSig <- IpCdiSignature . BSS.pack <$> vector 64
    return InitialCredentialDeploymentInfo{..}

genAccountCredentialWithProofs :: Gen AccountCredentialWithProofs
genAccountCredentialWithProofs =
    oneof
        [ NormalACWP <$> genCredentialDeploymentInformation,
          InitialACWP <$> genInitialCredentialDeploymentInformation
        ]

genCredentialDeploymentWithMeta :: Gen CredentialDeploymentWithMeta
genCredentialDeploymentWithMeta = do
    credential <- genAccountCredentialWithProofs
    messageExpiry <- TransactionTime <$> arbitrary
    wmdArrivalTime <- TransactionTime <$> arbitrary
    return $ addMetadata CredentialDeployment wmdArrivalTime AccountCreation{..}

genBlockItem :: Gen BlockItem
genBlockItem =
    oneof
        [ normalTransaction <$> genTransaction,
          credentialDeployment <$> genCredentialDeploymentWithMeta
        ]

genElectionDifficulty :: Gen ElectionDifficulty
genElectionDifficulty = makeElectionDifficulty <$> arbitrary `suchThat` (< 100000)

genAuthorizations :: IsChainParametersVersion cpv => Gen (Authorizations cpv)
genAuthorizations = do
    size <- getSize
    nKeys <- choose (1, min 65535 (1 + size))
    asKeys <- Vec.fromList . fmap correspondingVerifyKey <$> vectorOf nKeys genSigSchemeKeyPair
    let genAccessStructure = do
            asnKeys <- choose (1, nKeys)
            accessPublicKeys <- Set.fromList . take asnKeys <$> shuffle [0 .. fromIntegral nKeys - 1]
            accessThreshold <- UpdateKeysThreshold <$> choose (1, fromIntegral asnKeys)
            return AccessStructure{..}
    asEmergency <- genAccessStructure
    asProtocol <- genAccessStructure
    asParamElectionDifficulty <- genAccessStructure
    asParamEuroPerEnergy <- genAccessStructure
    asParamMicroGTUPerEuro <- genAccessStructure
    asParamFoundationAccount <- genAccessStructure
    asParamMintDistribution <- genAccessStructure
    asParamTransactionFeeDistribution <- genAccessStructure
    asParamGASRewards <- genAccessStructure
    asBakerStakeThreshold <- genAccessStructure
    asAddAnonymityRevoker <- genAccessStructure
    asAddIdentityProvider <- genAccessStructure
    asCooldownParameters <- justForCPV1A genAccessStructure
    asTimeParameters <- justForCPV1A genAccessStructure
    return Authorizations{..}

genProtocolUpdate :: Gen ProtocolUpdate
genProtocolUpdate = do
    puMessage <- Text.pack <$> arbitrary
    puSpecificationURL <- Text.pack <$> arbitrary
    puSpecificationHash <- SHA256.hash . BS.pack <$> arbitrary
    puSpecificationAuxiliaryData <- BS.pack <$> arbitrary
    return ProtocolUpdate{..}

genMintRate :: Gen MintRate
genMintRate = do
    mrExponent <- arbitrary
    mrMantissa <- choose (0, fromIntegral (min (toInteger (maxBound :: Word32)) (10 ^ mrExponent)))
    return MintRate{..}

genRatioOfWord64 :: Gen (Ratio Word64)
genRatioOfWord64 = do
    num <- choose (1, maxBound)
    den <- choose (1, maxBound)
    return $ num % den

genLeverageFactor :: Gen LeverageFactor
genLeverageFactor = genRatioOfWord64

genExchangeRate :: Gen ExchangeRate
genExchangeRate = ExchangeRate <$> genLeverageFactor

genEnergyRate :: Gen EnergyRate
genEnergyRate = max <*> negate <$> arbitrary

genExchangeRates :: Gen ExchangeRates
genExchangeRates = makeExchangeRates <$> genExchangeRate <*> genExchangeRate

genMintDistribution :: Gen MintDistribution
genMintDistribution = do
    _mdMintPerSlot <- genMintRate
    bf <- choose (0, 100000)
    ff <- choose (0, 100000 - bf)
    let _mdBakingReward = makeRewardFraction bf
        _mdFinalizationReward = makeRewardFraction ff
    return MintDistribution{..}

genTransactionFeeDistribution :: Gen TransactionFeeDistribution
genTransactionFeeDistribution = do
    bf <- choose (0, 100000)
    gf <- choose (0, 100000 - bf)
    let _tfdBaker = makeRewardFraction bf
        _tfdGASAccount = makeRewardFraction gf
    return TransactionFeeDistribution{..}

genGASRewards :: Gen GASRewards
genGASRewards = do
    _gasBaker <- makeRewardFraction <$> choose (0, 100000)
    _gasFinalizationProof <- makeRewardFraction <$> choose (0, 100000)
    _gasAccountCreation <- makeRewardFraction <$> choose (0, 100000)
    _gasChainUpdate <- makeRewardFraction <$> choose (0, 100000)
    return GASRewards{..}

genHigherLevelKeys :: Gen (HigherLevelKeys a)
genHigherLevelKeys = do
    size <- getSize
    nKeys <- choose (1, min 65535 (1 + size))
    hlkKeys <- Vec.fromList . fmap correspondingVerifyKey <$> vectorOf nKeys genSigSchemeKeyPair
    hlkThreshold <- UpdateKeysThreshold <$> choose (1, fromIntegral nKeys)
    return HigherLevelKeys{..}

genRootUpdate :: IsChainParametersVersion cpv => SChainParametersVersion cpv -> Gen RootUpdate
genRootUpdate scpv =
    oneof
        [ RootKeysRootUpdate <$> genHigherLevelKeys,
          Level1KeysRootUpdate <$> genHigherLevelKeys,
          case scpv of
              SCPV0 -> Level2KeysRootUpdate <$> genAuthorizations
              SCPV1 -> Level2KeysRootUpdateV1 <$> genAuthorizations
        ]

genLevel1Update :: IsChainParametersVersion cpv => SChainParametersVersion cpv -> Gen Level1Update
genLevel1Update scpv =
    oneof
        [ Level1KeysLevel1Update <$> genHigherLevelKeys,
          case scpv of
              SCPV0 -> Level2KeysLevel1Update <$> genAuthorizations
              SCPV1 -> Level2KeysLevel1UpdateV1 <$> genAuthorizations
        ]

genLevel2UpdatePayload :: SChainParametersVersion cpv -> Gen UpdatePayload
genLevel2UpdatePayload scpv =
    case scpv of
        SCPV0 -> 
            oneof
                [ ProtocolUpdatePayload <$> genProtocolUpdate,
                ElectionDifficultyUpdatePayload <$> genElectionDifficulty,
                EuroPerEnergyUpdatePayload <$> genExchangeRate,
                MicroGTUPerEuroUpdatePayload <$> genExchangeRate,
                FoundationAccountUpdatePayload <$> genAccountAddress,
                MintDistributionUpdatePayload <$> genMintDistribution,
                TransactionFeeDistributionUpdatePayload <$> genTransactionFeeDistribution,
                GASRewardsUpdatePayload <$> genGASRewards,
                BakerStakeThresholdUpdatePayload <$> genPoolParametersV0
                ]
        SCPV1 -> 
            oneof
                [ ProtocolUpdatePayload <$> genProtocolUpdate,
                ElectionDifficultyUpdatePayload <$> genElectionDifficulty,
                EuroPerEnergyUpdatePayload <$> genExchangeRate,
                MicroGTUPerEuroUpdatePayload <$> genExchangeRate,
                FoundationAccountUpdatePayload <$> genAccountAddress,
                MintDistributionUpdatePayload <$> genMintDistribution,
                TransactionFeeDistributionUpdatePayload <$> genTransactionFeeDistribution,
                GASRewardsUpdatePayload <$> genGASRewards,
                CooldownParametersCPV1UpdatePayload <$> genCooldownParametersV1,
                PoolParametersCPV1UpdatePayload <$> genPoolParametersV1,
                TimeParametersCPV1UpdatePayload <$> genTimeParametersV1
                ]

genUpdatePayload :: IsChainParametersVersion cpv => SChainParametersVersion cpv -> Gen UpdatePayload
genUpdatePayload scpv = 
    oneof [ genLevel2UpdatePayload scpv,
            RootUpdatePayload <$> genRootUpdate scpv,
            Level1UpdatePayload <$> genLevel1Update scpv
          ]

genRawUpdateInstruction :: IsChainParametersVersion cpv => SChainParametersVersion cpv -> Gen RawUpdateInstruction
genRawUpdateInstruction scpv = do
    ruiSeqNumber <- Nonce <$> arbitrary
    ruiEffectiveTime <- oneof [return 0, TransactionTime <$> arbitrary]
    ruiTimeout <- TransactionTime <$> arbitrary
    ruiPayload <- genUpdatePayload scpv
    return RawUpdateInstruction{..}

genLevel2RawUpdateInstruction :: SChainParametersVersion cpv -> Gen RawUpdateInstruction
genLevel2RawUpdateInstruction scpv = do
    ruiSeqNumber <- Nonce <$> arbitrary
    ruiEffectiveTime <- oneof [return 0, TransactionTime <$> arbitrary]
    ruiTimeout <- TransactionTime <$> arbitrary
    ruiPayload <- genLevel2UpdatePayload scpv
    return RawUpdateInstruction{..}

-- |Generate an 'Authorizations' structure and the list of key pairs.
-- The threshold for each access structure is specified.
genAuthorizationsAndKeys ::
    forall cpv.
    IsChainParametersVersion cpv =>
    -- |Threshold for each access structure
    UpdateKeysThreshold ->
    Gen (Authorizations cpv, [KeyPair])
genAuthorizationsAndKeys thr = do
    let nKeys = case chainParametersVersion @cpv of
            SCPV0 -> fromIntegral thr * 12
            SCPV1 -> fromIntegral thr * 14
    kps <- vectorOf nKeys genSigSchemeKeyPair
    let asKeys = Vec.fromList $ correspondingVerifyKey <$> kps
    let genAccessStructure = do
            asnKeys <- choose (fromIntegral thr, nKeys)
            accessPublicKeys <- Set.fromList . take asnKeys <$> shuffle [0 .. fromIntegral nKeys - 1]
            return AccessStructure{accessThreshold = thr, ..}
    asEmergency <- genAccessStructure
    asProtocol <- genAccessStructure
    asParamElectionDifficulty <- genAccessStructure
    asParamEuroPerEnergy <- genAccessStructure
    asParamMicroGTUPerEuro <- genAccessStructure
    asParamFoundationAccount <- genAccessStructure
    asParamMintDistribution <- genAccessStructure
    asParamTransactionFeeDistribution <- genAccessStructure
    asParamGASRewards <- genAccessStructure
    asBakerStakeThreshold <- genAccessStructure
    asAddAnonymityRevoker <- genAccessStructure
    asAddIdentityProvider <- genAccessStructure
    asCooldownParameters <- justForCPV1A genAccessStructure
    asTimeParameters <- justForCPV1A genAccessStructure
    return (Authorizations{..}, kps)

genLevel1Keys ::
    UpdateKeysThreshold ->
    Gen (HigherLevelKeys Level1KeysKind, [KeyPair])
genLevel1Keys thr = do
    kps <- vectorOf (fromIntegral thr * 2) genSigSchemeKeyPair
    let hlkKeys = Vec.fromList $ correspondingVerifyKey <$> kps
    return (HigherLevelKeys{hlkThreshold = thr, ..}, kps)

genRootKeys ::
    UpdateKeysThreshold ->
    Gen (HigherLevelKeys RootKeysKind, [KeyPair])
genRootKeys thr = do
    kps <- vectorOf (fromIntegral thr * 2) genSigSchemeKeyPair
    let hlkKeys = Vec.fromList $ correspondingVerifyKey <$> kps
    return (HigherLevelKeys{hlkThreshold = thr, ..}, kps)

genKeyCollection :: IsChainParametersVersion cpv => UpdateKeysThreshold -> Gen (UpdateKeysCollection cpv, [KeyPair], [KeyPair], [KeyPair])
genKeyCollection thr = do
    (rootKeys, a) <- genRootKeys thr
    (level1Keys, b) <- genLevel1Keys thr
    (level2Keys, c) <- genAuthorizationsAndKeys thr
    return (UpdateKeysCollection{..}, a, b, c)
