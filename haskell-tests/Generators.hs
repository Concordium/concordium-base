{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

-- | This module implements QuickCheck generators for types that are commonly used in tests.
module Generators where

import Test.QuickCheck hiding ((.&.))

import Control.Monad
import Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as BSS
import Data.Char
import qualified Data.Map.Strict as Map
import Data.Ratio
import qualified Data.Sequence as Seq
import qualified Data.Set as Set
import Data.Singletons
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TE
import qualified Data.Vector as Vec
import Data.Word
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
import Concordium.Genesis.Parameters
import Concordium.ID.DummyData
import Concordium.ID.Types
import Concordium.Types
import Concordium.Types.Conditionally
import Concordium.Types.Execution
import Concordium.Types.Parameters
import Concordium.Types.Tokens
import Concordium.Types.Transactions
import Concordium.Types.Updates
import qualified Concordium.Wasm as Wasm
import qualified Data.FixedByteString as FBS

genAmount :: Gen Amount
genAmount = Amount <$> arbitrary

genAttributeValue :: Gen AttributeValue
genAttributeValue = AttributeValue <$> (genShortByteStringLen =<< chooseInt (0, 31))

genDlogProof :: Gen Dlog25519Proof
genDlogProof = fst . randomProof . mkStdGen <$> resize 100000 arbitrary

genAccountOwnershipProof :: Gen AccountOwnershipProof
genAccountOwnershipProof = do
    n <- chooseInt (1, 255)
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

genTokenHolder :: Gen TokenHolder
genTokenHolder = HolderAccount <$> genAccountAddress

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
    n <- chooseInt (0, 1000)
    Wasm.Parameter <$> genShortByteStringLen n

-- | Generate a 'UrlText' that is a UTF-8 encoded string of no more than 'maxUrlTextLength' bytes.
genUrlText :: Gen UrlText
genUrlText =
    UrlText
        <$> suchThat
            (Text.pack <$> scale (min (fromIntegral maxUrlTextLength)) (listOf arbitrary))
            ((<= fromIntegral maxUrlTextLength) . BS.length . TE.encodeUtf8)

-- | Generate an 'AmountFraction' in the range [0,1].
genAmountFraction :: Gen AmountFraction
genAmountFraction = makeAmountFraction <$> chooseBoundedIntegral (0, 100000)

-- | Generate a 'CapitalBound', in the range (0,1]. (0 is not a valid 'CapitalBound'.)
genCapitalBound :: Gen CapitalBound
genCapitalBound = CapitalBound . makeAmountFraction <$> chooseBoundedIntegral (1, 100000)

genInclusiveRangeOfAmountFraction :: Gen (InclusiveRange AmountFraction)
genInclusiveRangeOfAmountFraction = do
    i0 <- genAmountFraction
    i1 <- genAmountFraction
    let (irMin, irMax) = if i0 <= i1 then (i0, i1) else (i1, i0)
    return InclusiveRange{..}

-- | Generate payloads that are valid for the given protocol version.
--  This includes all payload types except encrypted transfers (with and without memo) and
--  transfer to public.
genPayload :: ProtocolVersion -> Gen Payload
genPayload pv =
    oneof $
        [ genPayloadDeployModule pv,
          genPayloadInitContract,
          genPayloadUpdate,
          genPayloadTransfer,
          genPayloadUpdateCredentials,
          genPayloadUpdateCredentialKeys,
          genPayloadRegisterData,
          genPayloadTransferWithSchedule
        ]
            ++ [genPayloadTransferToEncrypted | pv < P7]
            ++ (if pv >= P2 then [genTransferWithMemo, genTransferWithScheduleAndMemo] else [])
            ++ if pv < P4
                then
                    [ genPayloadAddBaker,
                      genPayloadRemoveBaker,
                      genPayloadUpdateBakerStake,
                      genPayloadUpdateBakerRestateEarnings,
                      genPayloadUpdateBakerKeys
                    ]
                else
                    [ genPayloadConfigureBaker pv,
                      genPayloadConfigureDelegation
                    ]
                        ++ [genPayloadToken | pv >= P9]

-- | Generate payloads that are valid for some protocol version, but may not be valid for all.
genPayloadUnsafe :: Gen Payload
genPayloadUnsafe =
    oneof $
        [ -- All module version are supported at P4.
          genPayloadDeployModule P4,
          genPayloadInitContract,
          genPayloadUpdate,
          genPayloadTransfer,
          genPayloadUpdateCredentials,
          genPayloadUpdateCredentialKeys,
          genPayloadRegisterData,
          genPayloadTransferWithSchedule,
          genPayloadTransferToEncrypted,
          genTransferWithMemo,
          genTransferWithScheduleAndMemo,
          genPayloadAddBaker,
          genPayloadRemoveBaker,
          genPayloadUpdateBakerStake,
          genPayloadUpdateBakerRestateEarnings,
          genPayloadUpdateBakerKeys,
          genPayloadConfigureDelegation
        ]
            ++ [genPayloadConfigureBaker pv | pv <- [P4, P5, P6, P7, P8]]

genPayloadUpdateCredentials :: Gen Payload
genPayloadUpdateCredentials = do
    maxNumCredentials <- chooseInt (0, 255)
    indices <- Set.fromList . map CredentialIndex <$> replicateM maxNumCredentials (chooseBoundedIntegral (0, 255))
    -- the actual number of key indices. Duplicate key indices might have been generated.
    let numCredentials = Set.size indices
    credentials <- replicateM numCredentials genCredentialDeploymentInformation
    ucNewThreshold <- AccountThreshold <$> chooseBoundedIntegral (1, 255) -- since we are only updating there is no requirement that the threshold is less than the amount of credentials
    toRemoveLen <- chooseInt (0, 30)
    ucRemoveCredIds <- replicateM toRemoveLen genCredentialId
    return UpdateCredentials{ucNewCredInfos = Map.fromList (zip (Set.toList indices) credentials), ..}

genByteString :: Gen BS.ByteString
genByteString = do
    n <- chooseInt (0, 1000)
    gen <- mkStdGen <$> chooseBoundedIntegral (minBound, maxBound)
    return $ fst $ BS.unfoldrN n (Just . genWord8) gen

genPayloadDeployModule :: ProtocolVersion -> Gen Payload
genPayloadDeployModule pv =
    let genV0 = DeployModule . Wasm.WasmModuleV0 . Wasm.WasmModuleV . Wasm.ModuleSource <$> Generators.genByteString
        genV1 = DeployModule . Wasm.WasmModuleV1 . Wasm.WasmModuleV . Wasm.ModuleSource <$> Generators.genByteString
    in  if pv <= P3 -- protocol versions <= 3 only allow version 0 Wasm modules.
            then genV0
            else oneof [genV0, genV1]

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
    rdData <- RegisteredData <$> genShortByteStringLen n
    return RegisterData{..}

genPayloadConfigureBaker :: ProtocolVersion -> Gen Payload
genPayloadConfigureBaker pv = do
    cbCapital <- arbitrary
    cbRestakeEarnings <- arbitrary
    cbOpenForDelegation <- liftArbitrary $ elements [OpenForAll, ClosedForNew, ClosedForAll]
    cbKeysWithProofs <- liftArbitrary $ do
        sigPair <- (,) <$> (BlockSig.verifyKey <$> genBlockKeyPair) <*> genDlogProof
        elecPair <- (,) <$> (VRF.publicKey <$> arbitrary) <*> genDlogProof
        aggPair <- genAggregationVerifyKeyAndProof
        return
            BakerKeysWithProofs
                { bkwpElectionVerifyKey = fst elecPair,
                  bkwpProofElection = snd elecPair,
                  bkwpSignatureVerifyKey = fst sigPair,
                  bkwpProofSig = snd sigPair,
                  bkwpAggregationVerifyKey = fst aggPair,
                  bkwpProofAggregation = snd aggPair
                }
    cbMetadataURL <- liftArbitrary genUrlText
    cbTransactionFeeCommission <- liftArbitrary genAmountFraction
    cbBakingRewardCommission <- liftArbitrary genAmountFraction
    cbFinalizationRewardCommission <- liftArbitrary genAmountFraction
    cbSuspend <-
        if supportsValidatorSuspension (accountVersionFor pv)
            then arbitrary
            else return Nothing
    return ConfigureBaker{..}

genPayloadTransferWithSchedule :: Gen Payload
genPayloadTransferWithSchedule = do
    twsTo <- genAccountAddress
    len <- chooseBoundedIntegral (0, 255)
    twsSchedule :: [(Timestamp, Amount)] <- vectorOf len $ do
        ts <- genTimestamp
        amnt <- Amount <$> arbitrary
        return (ts, amnt)
    return $ TransferWithSchedule{..}

genTransferWithMemo :: Gen Payload
genTransferWithMemo = do
    twmToAddress <- genAccountAddress
    twmMemo <- genMemo
    twmAmount <- Amount <$> arbitrary
    return TransferWithMemo{..}

genTransferWithScheduleAndMemo :: Gen Payload
genTransferWithScheduleAndMemo = do
    twswmTo <- genAccountAddress
    twswmMemo <- genMemo
    len <- chooseBoundedIntegral (0, 255)
    twswmSchedule :: [(Timestamp, Amount)] <- vectorOf len $ do
        ts <- genTimestamp
        amnt <- Amount <$> arbitrary
        return (ts, amnt)
    return TransferWithScheduleAndMemo{..}

genDelegationTarget :: Gen DelegationTarget
genDelegationTarget =
    oneof [return DelegatePassive, DelegateToBaker . BakerId . AccountIndex <$> arbitrary]

genPayloadConfigureDelegation :: Gen Payload
genPayloadConfigureDelegation = do
    cdCapital <- arbitrary
    cdRestakeEarnings <- arbitrary
    cdDelegationTarget <- liftArbitrary $ genDelegationTarget
    return ConfigureDelegation{..}

-- | Generate token transaction payloads.
genPayloadToken :: Gen Payload
genPayloadToken = do
    tuTokenId <- genTokenId
    tuOperations <- genTokenParameter
    return TokenUpdate{..}

genCredentialId :: Gen CredentialRegistrationID
genCredentialId = RegIdCred . generateGroupElementFromSeed globalContext <$> arbitrary

genSignThreshold :: Gen SignatureThreshold
genSignThreshold = SignatureThreshold <$> chooseBoundedIntegral (1, 255)

-- | Simply generate a few 'ElgamalCipher' values for testing purposes.
elgamalCiphers :: Vec.Vector ElgamalCipher
elgamalCiphers = unsafePerformIO $ Vec.replicateM 200 generateElgamalCipher
{-# NOINLINE elgamalCiphers #-}

genElgamalCipher :: Gen ElgamalCipher
genElgamalCipher = do
    i <- chooseInt (0, Vec.length elgamalCiphers - 1)
    return $ elgamalCiphers Vec.! i

-- generate an increasing list of key indices, at least 1
genIndices :: Gen [KeyIndex]
genIndices = do
    maxLen <- chooseInt (1 :: Int, 255)
    let go is _ 0 = return is
        go is nextIdx n = do
            nextIndex <- chooseBoundedIntegral (nextIdx, 255)
            if nextIndex == 255
                then return (KeyIndex nextIndex : is)
                else go (KeyIndex nextIndex : is) (nextIndex + 1) (n - 1)
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
    let ym = YearMonth <$> chooseBoundedIntegral (1000, 9999) <*> chooseBoundedIntegral (1, 12)
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
    cdvThreshold <- Threshold <$> chooseBoundedIntegral (1, max 1 (fromIntegral (length cdvArData)))
    cdvPolicy <- genPolicy
    cdiProofs <- do
        l <- chooseBoundedIntegral (0, 10000)
        Proofs <$> genShortByteStringLen l
    let cdiValues = CredentialDeploymentValues{..}
    return CredentialDeploymentInformation{..}

genCommissionRates :: Gen CommissionRates
genCommissionRates =
    CommissionRates <$> genAmountFraction <*> genAmountFraction <*> genAmountFraction

genCommissionRanges :: Gen CommissionRanges
genCommissionRanges =
    CommissionRanges
        <$> genInclusiveRangeOfAmountFraction
        <*> genInclusiveRangeOfAmountFraction
        <*> genInclusiveRangeOfAmountFraction

genChainParametersV0 :: Gen (ChainParameters' 'ChainParametersV0)
genChainParametersV0 = do
    _cpConsensusParameters <- ConsensusParametersV0 <$> genElectionDifficulty
    _cpExchangeRates <- genExchangeRates
    _cpCooldownParameters <- genCooldownParametersV0
    let _cpTimeParameters = NoParam
    _cpAccountCreationLimit <- arbitrary
    _cpRewardParameters <- genRewardParameters
    _cpFoundationAccount <- AccountIndex <$> arbitrary
    _cpPoolParameters <- genPoolParametersV0
    let _cpFinalizationCommitteeParameters = NoParam
    let _cpValidatorScoreParameters = NoParam
    return ChainParameters{..}

genChainParametersV1 :: Gen (ChainParameters' 'ChainParametersV1)
genChainParametersV1 = do
    _cpConsensusParameters <- ConsensusParametersV0 <$> genElectionDifficulty
    _cpExchangeRates <- genExchangeRates
    _cpCooldownParameters <- genCooldownParametersV1
    _cpTimeParameters <- SomeParam <$> genTimeParametersV1
    _cpAccountCreationLimit <- arbitrary
    _cpRewardParameters <- genRewardParameters
    _cpFoundationAccount <- AccountIndex <$> arbitrary
    _cpPoolParameters <- genPoolParametersV1
    let _cpFinalizationCommitteeParameters = NoParam
    let _cpValidatorScoreParameters = NoParam
    return ChainParameters{..}

genFinalizationCommitteeParameters :: Gen FinalizationCommitteeParameters
genFinalizationCommitteeParameters = do
    _fcpMinFinalizers <- chooseBoundedIntegral (20, 100)
    _fcpMaxFinalizers <- chooseBoundedIntegral (100, 800)
    _fcpFinalizerRelativeStakeThreshold <- arbitrary
    return FinalizationCommitteeParameters{..}

genConsensusParametersV1 ::
    Gen (ConsensusParameters' 'ConsensusParametersVersion1)
genConsensusParametersV1 = do
    _cpTimeoutParameters <- genTimeoutParameters
    _cpMinBlockTime <- genDuration
    _cpBlockEnergyLimit <- Energy <$> arbitrary
    _cpFinalizationCommitteeParameters <- genFinalizationCommitteeParameters
    return ConsensusParametersV1{..}

genChainParametersV2 :: Gen (ChainParameters' 'ChainParametersV2)
genChainParametersV2 = do
    _cpConsensusParameters <- genConsensusParametersV1
    _cpExchangeRates <- genExchangeRates
    _cpCooldownParameters <- genCooldownParametersV1
    _cpTimeParameters <- SomeParam <$> genTimeParametersV1
    _cpAccountCreationLimit <- arbitrary
    _cpRewardParameters <- genRewardParameters
    _cpFoundationAccount <- AccountIndex <$> arbitrary
    _cpPoolParameters <- genPoolParametersV1
    _cpFinalizationCommitteeParameters <- SomeParam <$> genFinalizationCommitteeParameters
    let _cpValidatorScoreParameters = NoParam
    return ChainParameters{..}

genValidatorScoreParameters :: Gen ValidatorScoreParameters
genValidatorScoreParameters = do
    _vspMaxMissedRounds <- arbitrary
    return ValidatorScoreParameters{..}

genChainParametersV3 :: Gen (ChainParameters' 'ChainParametersV3)
genChainParametersV3 = do
    _cpConsensusParameters <- genConsensusParametersV1
    _cpExchangeRates <- genExchangeRates
    _cpCooldownParameters <- genCooldownParametersV1
    _cpTimeParameters <- SomeParam <$> genTimeParametersV1
    _cpAccountCreationLimit <- arbitrary
    _cpRewardParameters <- genRewardParameters
    _cpFoundationAccount <- AccountIndex <$> arbitrary
    _cpPoolParameters <- genPoolParametersV1
    _cpFinalizationCommitteeParameters <- SomeParam <$> genFinalizationCommitteeParameters
    _cpValidatorScoreParameters <- SomeParam <$> genValidatorScoreParameters
    return ChainParameters{..}

genGenesisChainParametersV0 :: Gen (GenesisChainParameters' 'ChainParametersV0)
genGenesisChainParametersV0 = do
    gcpConsensusParameters <- ConsensusParametersV0 <$> genElectionDifficulty
    gcpExchangeRates <- genExchangeRates
    gcpCooldownParameters <- genCooldownParametersV0
    let gcpTimeParameters = NoParam
    gcpAccountCreationLimit <- arbitrary
    gcpRewardParameters <- genRewardParameters
    gcpFoundationAccount <- genAccountAddress
    gcpPoolParameters <- genPoolParametersV0
    let gcpFinalizationCommitteeParameters = NoParam
    let gcpValidatorScoreParameters = NoParam
    return GenesisChainParameters{..}

genGenesisChainParametersV1 :: Gen (GenesisChainParameters' 'ChainParametersV1)
genGenesisChainParametersV1 = do
    gcpConsensusParameters <- ConsensusParametersV0 <$> genElectionDifficulty
    gcpExchangeRates <- genExchangeRates
    gcpCooldownParameters <- genCooldownParametersV1
    gcpTimeParameters <- SomeParam <$> genTimeParametersV1
    gcpAccountCreationLimit <- arbitrary
    gcpRewardParameters <- genRewardParameters
    gcpFoundationAccount <- genAccountAddress
    gcpPoolParameters <- genPoolParametersV1
    let gcpFinalizationCommitteeParameters = NoParam
    let gcpValidatorScoreParameters = NoParam
    return GenesisChainParameters{..}

genGenesisChainParametersV2 :: Gen (GenesisChainParameters' 'ChainParametersV2)
genGenesisChainParametersV2 = do
    gcpConsensusParameters <- genConsensusParametersV1
    gcpExchangeRates <- genExchangeRates
    gcpCooldownParameters <- genCooldownParametersV1
    gcpTimeParameters <- SomeParam <$> genTimeParametersV1
    gcpAccountCreationLimit <- arbitrary
    gcpRewardParameters <- genRewardParameters
    gcpFoundationAccount <- genAccountAddress
    gcpPoolParameters <- genPoolParametersV1
    gcpFinalizationCommitteeParameters <- SomeParam <$> genFinalizationCommitteeParameters
    let gcpValidatorScoreParameters = NoParam
    return GenesisChainParameters{..}

genGenesisChainParametersV3 :: Gen (GenesisChainParameters' 'ChainParametersV3)
genGenesisChainParametersV3 = do
    gcpConsensusParameters <- genConsensusParametersV1
    gcpExchangeRates <- genExchangeRates
    gcpCooldownParameters <- genCooldownParametersV1
    gcpTimeParameters <- SomeParam <$> genTimeParametersV1
    gcpAccountCreationLimit <- arbitrary
    gcpRewardParameters <- genRewardParameters
    gcpFoundationAccount <- genAccountAddress
    gcpPoolParameters <- genPoolParametersV1
    gcpFinalizationCommitteeParameters <- SomeParam <$> genFinalizationCommitteeParameters
    gcpValidatorScoreParameters <- SomeParam <$> genValidatorScoreParameters
    return GenesisChainParameters{..}

genCooldownParametersV0 :: Gen (CooldownParameters' 'CooldownParametersVersion0)
genCooldownParametersV0 = CooldownParametersV0 <$> arbitrary

genCooldownParametersV1 :: Gen (CooldownParameters' 'CooldownParametersVersion1)
genCooldownParametersV1 =
    CooldownParametersV1 <$> (DurationSeconds <$> arbitrary) <*> (DurationSeconds <$> arbitrary)

genRewardPeriodLength :: Gen RewardPeriodLength
genRewardPeriodLength = RewardPeriodLength <$> chooseBoundedIntegral (1, maxBound) -- to make sure that reward period length is >= 1

genTimeParametersV1 :: Gen TimeParameters
genTimeParametersV1 = TimeParametersV1 <$> genRewardPeriodLength <*> genMintRate

genPoolParametersV0 :: Gen (PoolParameters' 'PoolParametersVersion0)
genPoolParametersV0 = PoolParametersV0 <$> arbitrary

genPoolParametersV1 :: Gen (PoolParameters' 'PoolParametersVersion1)
genPoolParametersV1 = do
    _ppPassiveCommissions <- genCommissionRates
    _ppCommissionBounds <- genCommissionRanges
    _ppMinimumEquityCapital <- genAmount
    _ppCapitalBound <- genCapitalBound
    _ppLeverageBound <- genLeverageFactor
    return PoolParametersV1{..}

genRewardParameters :: forall cpv. (IsChainParametersVersion cpv) => Gen (RewardParameters cpv)
genRewardParameters = withCPVConstraints (chainParametersVersion @cpv) $ do
    _rpMintDistribution <- genMintDistribution
    _rpTransactionFeeDistribution <- genTransactionFeeDistribution
    _rpGASRewards <- genGASRewards
    return RewardParameters{..}

genDuration :: Gen Duration
genDuration = Duration <$> arbitrary

-- | x > 1
genTimeoutIncrease :: Gen (Ratio Word64)
genTimeoutIncrease = do
    den <- chooseBoundedIntegral (1, maxBound - 1)
    num <- chooseBoundedIntegral (den + 1, maxBound)
    return $ num % den

-- | x > 0 || x < 1
genTimeoutDecrease :: Gen (Ratio Word64)
genTimeoutDecrease = do
    num <- chooseBoundedIntegral (1, maxBound)
    den <- chooseBoundedIntegral (num + 1, maxBound)
    return $ num % den

genTimeoutParameters :: Gen TimeoutParameters
genTimeoutParameters = do
    _tpTimeoutBase <- genDuration
    _tpTimeoutIncrease <- genTimeoutIncrease
    _tpTimeoutDecrease <- genTimeoutDecrease
    return TimeoutParameters{..}

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

instance Arbitrary OpenStatus where
    arbitrary = elements [OpenForAll, ClosedForNew, ClosedForAll]

genEncryptedAmount :: Gen EncryptedAmount
genEncryptedAmount = EncryptedAmount <$> genElgamalCipher <*> genElgamalCipher

genAccountEncryptedAmount :: Gen AccountEncryptedAmount
genAccountEncryptedAmount = do
    _selfAmount <- genEncryptedAmount
    _startIndex <- EncryptedAmountAggIndex <$> arbitrary
    len <- chooseInt (0, 100)
    _incomingEncryptedAmounts <- Seq.replicateM len genEncryptedAmount
    numAgg <- arbitrary
    aggAmount <- genEncryptedAmount
    if numAgg == Just 1 || numAgg == Just 0
        then return AccountEncryptedAmount{_aggregatedAmount = Nothing, ..}
        else return AccountEncryptedAmount{_aggregatedAmount = (aggAmount,) <$> numAgg, ..}

genContractEvent :: Gen Wasm.ContractEvent
genContractEvent = Wasm.ContractEvent <$> sized genShortByteStringLen

genAddress :: Gen Address
genAddress = oneof [AddressAccount <$> genAccountAddress, AddressContract <$> genCAddress]

genTransactionTime :: Gen TransactionTime
genTransactionTime = TransactionTime <$> arbitrary

genTimestamp :: Gen Timestamp
genTimestamp = Timestamp <$> arbitrary

genRegisteredData :: Gen RegisteredData
genRegisteredData = do
    len <- chooseBoundedIntegral (0, maxRegisteredDataSize)
    RegisteredData <$> genShortByteStringLen len

genMemo :: Gen Memo
genMemo = do
    len <- chooseBoundedIntegral (0, maxMemoSize)
    Memo <$> genShortByteStringLen len

genBakerId :: Gen BakerId
genBakerId = BakerId . AccountIndex <$> arbitrary

genDelegatorId :: Gen DelegatorId
genDelegatorId = DelegatorId . AccountIndex <$> arbitrary

genWasmVersion :: SProtocolVersion pv -> Gen Wasm.WasmVersion
genWasmVersion spv
    | supportsV1Contracts spv = elements [Wasm.V0, Wasm.V1]
    | otherwise = return Wasm.V0

genEvent :: (IsProtocolVersion pv) => SProtocolVersion pv -> Gen Event
genEvent spv =
    oneof
        ( [ ModuleDeployed <$> genModuleRef,
            ContractInitialized <$> genModuleRef <*> genCAddress <*> genAmount <*> genInitName <*> genWasmVersion spv <*> listOf genContractEvent <*> pure CFalse,
            Updated <$> genCAddress <*> genAddress <*> genAmount <*> genParameter <*> genReceiveName <*> genWasmVersion spv <*> listOf genContractEvent,
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
            UpdateEnqueued <$> genTransactionTime <*> genUpdatePayload spv,
            genTransferredWithSchedule,
            genCredentialsUpdated,
            DataRegistered <$> genRegisteredData
          ]
            ++ maybeMemo
            ++ maybeV1ContractEvents
            ++ maybeDelegationEvents
            ++ maybeUpgrade
            ++ maybeSuspendEvents
            ++ maybeTokenEvents
        )
  where
    maybeUpgrade = if supportsUpgradableContracts spv then [Upgraded <$> genCAddress <*> genModuleRef <*> genModuleRef] else []
    maybeMemo = if supportsMemo spv then [TransferMemo <$> genMemo] else []
    maybeV1ContractEvents =
        if supportsV1Contracts spv
            then
                [ Interrupted <$> genCAddress <*> listOf genContractEvent,
                  Resumed <$> genCAddress <*> arbitrary
                ]
            else []
    maybeDelegationEvents =
        if protocolSupportsDelegation spv
            then
                [ BakerSetOpenStatus <$> genBakerId <*> genAccountAddress <*> arbitrary,
                  BakerSetMetadataURL <$> genBakerId <*> genAccountAddress <*> genUrlText,
                  BakerSetTransactionFeeCommission <$> genBakerId <*> genAccountAddress <*> genAmountFraction,
                  BakerSetBakingRewardCommission <$> genBakerId <*> genAccountAddress <*> genAmountFraction,
                  BakerSetFinalizationRewardCommission <$> genBakerId <*> genAccountAddress <*> genAmountFraction,
                  DelegationStakeIncreased <$> genDelegatorId <*> genAccountAddress <*> genAmount,
                  DelegationStakeDecreased <$> genDelegatorId <*> genAccountAddress <*> genAmount,
                  DelegationSetRestakeEarnings <$> genDelegatorId <*> genAccountAddress <*> arbitrary,
                  DelegationSetDelegationTarget <$> genDelegatorId <*> genAccountAddress <*> genDelegationTarget,
                  DelegationAdded <$> genDelegatorId <*> genAccountAddress,
                  DelegationRemoved <$> genDelegatorId <*> genAccountAddress
                ]
            else []
    maybeSuspendEvents =
        if protocolSupportsSuspend spv
            then
                [ BakerSuspended <$> genBakerId <*> genAccountAddress,
                  BakerResumed <$> genBakerId <*> genAccountAddress
                ]
            else []
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
        cuNewThreshold <- AccountThreshold <$> chooseBoundedIntegral (1, maxBound)
        return CredentialsUpdated{..}
    maybeTokenEvents
        | protocolSupportsPLT spv =
            [ TokenModuleEvent <$> genTokenId <*> genTokenEventType <*> genTokenEventDetails,
              TokenTransfer
                <$> genTokenId
                <*> genTokenHolder
                <*> genTokenHolder
                <*> genTokenAmount
                <*> liftArbitrary genMemo,
              TokenMint <$> genTokenId <*> genTokenHolder <*> genTokenAmount,
              TokenBurn <$> genTokenId <*> genTokenHolder <*> genTokenAmount,
              TokenCreated <$> genCreatePLT
            ]
        | otherwise = []

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
              return NotAllowedToHandleEncrypted,
              return MissingBakerAddParameters,
              return FinalizationRewardCommissionNotInRange,
              return BakingRewardCommissionNotInRange,
              return TransactionFeeCommissionNotInRange,
              return AlreadyADelegator,
              return InsufficientBalanceForDelegationStake,
              return MissingDelegationAddParameters,
              return InsufficientDelegationStake,
              return DelegatorInCooldown,
              NotADelegator <$> genAccountAddress,
              DelegationTargetNotABaker <$> genBakerId,
              return StakeOverMaximumThresholdForPool,
              return PoolWouldBecomeOverDelegated,
              return PoolClosed
            ]

genValidResult :: (IsProtocolVersion pv) => SProtocolVersion pv -> Gen ValidResult
genValidResult spv =
    oneof
        [ TxSuccess <$> (liftArbitrary $ genEvent spv),
          TxReject <$> arbitrary
        ]

genTransactionSummary :: (IsProtocolVersion pv) => SProtocolVersion pv -> Gen TransactionSummary
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
    i <- chooseInt (0, Vec.length verifyKeys - 1)
    return $ verifyKeys Vec.! i

genSchemeId :: Gen SchemeId
genSchemeId = elements schemes

genTransactionHeader :: Gen TransactionHeader
genTransactionHeader = do
    thSender <- genAccountAddress
    thPayloadSize <- PayloadSize <$> chooseBoundedIntegral (0, maxPayloadSize SP4)
    thNonce <- Nonce <$> arbitrary
    thEnergyAmount <- Energy <$> arbitrary
    thExpiry <- TransactionTime <$> arbitrary
    return $ TransactionHeader{..}

genShortByteStringLen :: Int -> Gen BSS.ShortByteString
genShortByteStringLen len = do
    gen <- mkStdGen <$> chooseBoundedIntegral (minBound, maxBound)
    return $ fst $ BSS.unfoldrN len (Just . genWord8) gen

genShortByteString :: Gen BSS.ShortByteString
genShortByteString = sized $ \n -> do
    k <- chooseInt (0, n)
    genShortByteStringLen k

genAccountTransaction :: Gen AccountTransaction
genAccountTransaction = do
    atrHeader <- genTransactionHeader
    atrPayload <- EncodedPayload <$> genShortByteStringLen (fromIntegral (thPayloadSize atrHeader))
    numCredentials <- chooseBoundedIntegral (1, 255)
    allKeys <- replicateM numCredentials $ do
        numKeys <- chooseBoundedIntegral (1, 255)
        credentialSignatures <- replicateM numKeys $ do
            idx <- KeyIndex <$> arbitrary
            sLen <- chooseBoundedIntegral (50, 70)
            sig <- Signature <$> genShortByteStringLen sLen
            return (idx, sig)
        (,Map.fromList credentialSignatures) . CredentialIndex <$> arbitrary

    let atrSignature = TransactionSignature (Map.fromList allKeys)
    return $! makeAccountTransaction atrSignature atrHeader atrPayload

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
    icdiSig <- IpCdiSignature <$> genShortByteStringLen 64
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
genElectionDifficulty = makeElectionDifficulty <$> chooseBoundedIntegral (0, 99999)

genAuthorizations :: forall auv. (IsAuthorizationsVersion auv) => Gen (Authorizations auv)
genAuthorizations = do
    size <- getSize
    nKeys <- chooseBoundedIntegral (1, min 65535 (1 + size))
    asKeys <- Vec.fromList . fmap correspondingVerifyKey <$> vectorOf nKeys genSigSchemeKeyPair
    let genAccessStructure = do
            asnKeys <- chooseBoundedIntegral (1, nKeys)
            accessPublicKeys <- Set.fromList . take asnKeys <$> shuffle [0 .. fromIntegral nKeys - 1]
            accessThreshold <- UpdateKeysThreshold <$> chooseBoundedIntegral (1, fromIntegral asnKeys)
            return AccessStructure{..}
    asEmergency <- genAccessStructure
    asProtocol <- genAccessStructure
    asParamConsensusParameters <- genAccessStructure
    asParamEuroPerEnergy <- genAccessStructure
    asParamMicroGTUPerEuro <- genAccessStructure
    asParamFoundationAccount <- genAccessStructure
    asParamMintDistribution <- genAccessStructure
    asParamTransactionFeeDistribution <- genAccessStructure
    asParamGASRewards <- genAccessStructure
    asPoolParameters <- genAccessStructure
    asAddAnonymityRevoker <- genAccessStructure
    asAddIdentityProvider <- genAccessStructure
    asCooldownParameters <- conditionallyA (sSupportsCooldownParametersAccessStructure (sing @auv)) genAccessStructure
    asTimeParameters <- conditionallyA (sSupportsTimeParameters (sing @auv)) genAccessStructure
    asCreatePLT <- conditionallyA (sSupportsCreatePLT (sing @auv)) genAccessStructure
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
    mrMantissa <- chooseBoundedIntegral (0, fromIntegral (min (toInteger (maxBound :: Word32)) (10 ^ mrExponent)))
    return MintRate{..}

genRatioOfWord64 :: Gen (Ratio Word64)
genRatioOfWord64 = do
    num <- chooseBoundedIntegral (1, maxBound)
    den <- chooseBoundedIntegral (1, maxBound)
    return $ num % den

genLeverageFactor :: Gen LeverageFactor
genLeverageFactor =
    LeverageFactor <$> do
        den <- chooseBoundedIntegral (1, maxBound)
        num <- chooseBoundedIntegral (den, maxBound) -- to make sure that the leverage factor is >= 1
        return $ num % den

genExchangeRate :: Gen ExchangeRate
genExchangeRate = ExchangeRate <$> genRatioOfWord64

genEnergyRate :: Gen EnergyRate
genEnergyRate = max <*> negate <$> arbitrary

genExchangeRates :: Gen ExchangeRates
genExchangeRates = makeExchangeRates <$> genExchangeRate <*> genExchangeRate

genMintDistribution :: forall mdv. (IsMintDistributionVersion mdv) => Gen (MintDistribution mdv)
genMintDistribution = do
    _mdMintPerSlot <- conditionallyA (sSupportsMintPerSlot (sing @mdv)) genMintRate
    bf <- chooseBoundedIntegral (0, 100000)
    ff <- chooseBoundedIntegral (0, 100000 - bf)
    let _mdBakingReward = makeAmountFraction bf
        _mdFinalizationReward = makeAmountFraction ff
    return MintDistribution{..}

genTransactionFeeDistribution :: Gen TransactionFeeDistribution
genTransactionFeeDistribution = do
    bf <- chooseBoundedIntegral (0, 100000)
    gf <- chooseBoundedIntegral (0, 100000 - bf)
    let _tfdBaker = makeAmountFraction bf
        _tfdGASAccount = makeAmountFraction gf
    return TransactionFeeDistribution{..}

genGASRewards :: forall grv. (IsGASRewardsVersion grv) => Gen (GASRewards grv)
genGASRewards = do
    _gasBaker <- makeAmountFraction <$> chooseBoundedIntegral (0, 100000)
    _gasFinalizationProof <-
        conditionallyA (sSupportsGASFinalizationProof (sing @grv)) $
            makeAmountFraction <$> chooseBoundedIntegral (0, 100000)
    _gasAccountCreation <- makeAmountFraction <$> chooseBoundedIntegral (0, 100000)
    _gasChainUpdate <- makeAmountFraction <$> chooseBoundedIntegral (0, 100000)
    return GASRewards{..}

-- | Generate a token parameter consisting of up to 1000 arbitrary bytes.
genTokenParameter :: Gen TokenParameter
genTokenParameter = do
    n <- chooseBoundedIntegral (0, 1000)
    TokenParameter <$> genShortByteStringLen n

-- | Generate an reference to a token module (always 32 bytes).
genTokenModuleRef :: Gen TokenModuleRef
genTokenModuleRef = TokenModuleRef . SHA256.hash . BS.pack <$> vector 32

-- | Generate a valid UTF-8 character. The size argument is used to determine how many bytes in
--  size this can be (up to 4).
genUtf8Char :: Gen [Word8]
genUtf8Char = do
    sz <- getSize
    oneof $ [oneByte] ++ [twoByte | sz >= 2] ++ [threeByte | sz >= 3] ++ [fourByte | sz >= 4]
  where
    oneByte = do
        cp <- chooseBoundedIntegral (0x00, 0x7f)
        return [cp]
    twoByte = do
        (cp :: Word32) <- chooseBoundedIntegral (0x80, 0x07ff)
        return
            [ 0b11000000 .|. fromIntegral (cp `shiftR` 6),
              0b10000000 .|. (fromIntegral cp .&. 0b00111111)
            ]
    threeByte = do
        -- Surrogate codepoints are disallowed.
        (cp :: Word32) <-
            chooseBoundedIntegral (0x0800, 0xffff)
                `suchThat` (\x -> x < 0xd800 || x > 0xdfff)
        return
            [ 0b11100000 .|. (fromIntegral (cp `shiftR` 12)),
              0b10000000 .|. (0b00111111 .&. fromIntegral (cp `shiftR` 6)),
              0b10000000 .|. (0b00111111 .&. fromIntegral cp)
            ]
    fourByte = do
        (cp :: Word32) <- chooseBoundedIntegral (0x010000, 0x10ffff)
        return
            [ 0b11110000 .|. (fromIntegral (cp `shiftR` 18)),
              0b10000000 .|. (0b00111111 .&. fromIntegral (cp `shiftR` 12)),
              0b10000000 .|. (0b00111111 .&. fromIntegral (cp `shiftR` 6)),
              0b10000000 .|. (0b00111111 .&. fromIntegral cp)
            ]

-- | Generate a valid UTF-8 string of the specified length.
genUtf8String :: Int -> Gen [Word8]
genUtf8String len
    | len <= 0 = return []
    | otherwise = do
        c <- resize len genUtf8Char
        rest <- genUtf8String (len - length c)
        return (c ++ rest)

-- | Allowed token id characters
allowedChars :: [Word8]
allowedChars =
    map (fromIntegral . ord) $
        ['0' .. '9'] ++ ['a' .. 'z'] ++ ['A' .. 'Z'] ++ ".-%"

-- | Generate an allowed character
genAllowedChar :: Gen Word8
genAllowedChar = elements allowedChars

-- | Generate allowed characters of specific length
genAllowedChars :: Int -> Gen [Word8]
genAllowedChars len = vectorOf len genAllowedChar

-- | Generate an arbitrary 'TokenId', consisting of up to 255 bytes that is a valid UTF-8 string.
genTokenId :: Gen TokenId
genTokenId = do
    len <- chooseBoundedIntegral (1, 128)
    TokenId . BSS.pack <$> genAllowedChars len

genTokenEventType :: Gen TokenEventType
genTokenEventType = do
    len <- chooseBoundedIntegral (0, 255)
    TokenEventType . BSS.pack <$> genUtf8String len

-- | Generate an arbitrary 'TokenRawAmount'.
genTokenRawAmount :: Gen TokenRawAmount
genTokenRawAmount = TokenRawAmount <$> arbitrary

-- | Generate an arbitrary 'TokenAmount' across all representable values.
genTokenAmount :: Gen TokenAmount
genTokenAmount = TokenAmount <$> genTokenRawAmount <*> arbitrary

-- | Generate an arbitrary 'TokenEventDetails', consisting of up to 1000 bytes.
--  This is not guaranteed to be valid CBOR.
genTokenEventDetails :: Gen TokenEventDetails
genTokenEventDetails = do
    len <- chooseBoundedIntegral (0, 1000)
    TokenEventDetails . BSS.pack <$> genUtf8String len

-- | Generate an arbitrary 'CreatePLT' chain update, consisting of:
--   * Random token symbol up to 255 bytes valid UTF-8.
--   * Token module reference from arbitrary bytes.
--   * Random address as the governance account.
--   * Arbitrary decimals between 0 and 255.
--   * Generated token parameter up to 1000 bytes long.
genCreatePLT :: Gen CreatePLT
genCreatePLT = do
    _cpltTokenId <- genTokenId
    _cpltTokenModule <- genTokenModuleRef
    _cpltGovernanceAccount <- genAccountAddress
    _cpltDecimals <- chooseBoundedIntegral (0, 255)
    _cpltInitializationParameters <- genTokenParameter
    return CreatePLT{..}

genHigherLevelKeys :: Gen (HigherLevelKeys a)
genHigherLevelKeys = do
    size <- getSize
    nKeys <- chooseBoundedIntegral (1, min 65535 (1 + size))
    hlkKeys <- Vec.fromList . fmap correspondingVerifyKey <$> vectorOf nKeys genSigSchemeKeyPair
    hlkThreshold <- UpdateKeysThreshold <$> chooseBoundedIntegral (1, fromIntegral nKeys)
    return HigherLevelKeys{..}

genRootUpdate :: (IsAuthorizationsVersion auv) => SAuthorizationsVersion auv -> Gen RootUpdate
genRootUpdate sauv =
    oneof
        [ RootKeysRootUpdate <$> genHigherLevelKeys,
          Level1KeysRootUpdate <$> genHigherLevelKeys,
          case sauv of
            SAuthorizationsVersion0 -> Level2KeysRootUpdate <$> genAuthorizations
            SAuthorizationsVersion1 -> Level2KeysRootUpdateV1 <$> genAuthorizations
            SAuthorizationsVersion2 -> Level2KeysRootUpdateV2 <$> genAuthorizations
        ]

genLevel1Update :: (IsAuthorizationsVersion auv) => SAuthorizationsVersion auv -> Gen Level1Update
genLevel1Update sauv =
    oneof
        [ Level1KeysLevel1Update <$> genHigherLevelKeys,
          case sauv of
            SAuthorizationsVersion0 -> Level2KeysLevel1Update <$> genAuthorizations
            SAuthorizationsVersion1 -> Level2KeysLevel1UpdateV1 <$> genAuthorizations
            SAuthorizationsVersion2 -> Level2KeysLevel1UpdateV2 <$> genAuthorizations
        ]

genLevel2UpdatePayload :: SChainParametersVersion cpv -> Gen UpdatePayload
genLevel2UpdatePayload scpv =
    case scpv of
        SChainParametersV0 ->
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
        SChainParametersV1 ->
            oneof
                [ ProtocolUpdatePayload <$> genProtocolUpdate,
                  ElectionDifficultyUpdatePayload <$> genElectionDifficulty,
                  EuroPerEnergyUpdatePayload <$> genExchangeRate,
                  MicroGTUPerEuroUpdatePayload <$> genExchangeRate,
                  FoundationAccountUpdatePayload <$> genAccountAddress,
                  MintDistributionCPV1UpdatePayload <$> genMintDistribution,
                  TransactionFeeDistributionUpdatePayload <$> genTransactionFeeDistribution,
                  GASRewardsUpdatePayload <$> genGASRewards,
                  CooldownParametersCPV1UpdatePayload <$> genCooldownParametersV1,
                  PoolParametersCPV1UpdatePayload <$> genPoolParametersV1,
                  TimeParametersCPV1UpdatePayload <$> genTimeParametersV1
                ]
        SChainParametersV2 ->
            oneof
                [ ProtocolUpdatePayload <$> genProtocolUpdate,
                  EuroPerEnergyUpdatePayload <$> genExchangeRate,
                  MicroGTUPerEuroUpdatePayload <$> genExchangeRate,
                  FoundationAccountUpdatePayload <$> genAccountAddress,
                  MintDistributionCPV1UpdatePayload <$> genMintDistribution,
                  TransactionFeeDistributionUpdatePayload <$> genTransactionFeeDistribution,
                  CooldownParametersCPV1UpdatePayload <$> genCooldownParametersV1,
                  PoolParametersCPV1UpdatePayload <$> genPoolParametersV1,
                  TimeParametersCPV1UpdatePayload <$> genTimeParametersV1,
                  TimeoutParametersUpdatePayload <$> genTimeoutParameters,
                  MinBlockTimeUpdatePayload <$> genDuration,
                  BlockEnergyLimitUpdatePayload . Energy <$> arbitrary,
                  GASRewardsCPV2UpdatePayload <$> genGASRewards
                ]
        SChainParametersV3 ->
            oneof
                [ ProtocolUpdatePayload <$> genProtocolUpdate,
                  EuroPerEnergyUpdatePayload <$> genExchangeRate,
                  MicroGTUPerEuroUpdatePayload <$> genExchangeRate,
                  FoundationAccountUpdatePayload <$> genAccountAddress,
                  MintDistributionCPV1UpdatePayload <$> genMintDistribution,
                  TransactionFeeDistributionUpdatePayload <$> genTransactionFeeDistribution,
                  CooldownParametersCPV1UpdatePayload <$> genCooldownParametersV1,
                  PoolParametersCPV1UpdatePayload <$> genPoolParametersV1,
                  TimeParametersCPV1UpdatePayload <$> genTimeParametersV1,
                  TimeoutParametersUpdatePayload <$> genTimeoutParameters,
                  MinBlockTimeUpdatePayload <$> genDuration,
                  BlockEnergyLimitUpdatePayload . Energy <$> arbitrary,
                  GASRewardsCPV2UpdatePayload <$> genGASRewards
                ]

genUpdatePayload :: (IsProtocolVersion pv) => SProtocolVersion pv -> Gen UpdatePayload
genUpdatePayload spv =
    oneof
        [ genLevel2UpdatePayload $ sChainParametersVersionFor spv,
          RootUpdatePayload <$> genRootUpdate (sAuthorizationsVersionFor spv),
          Level1UpdatePayload <$> genLevel1Update (sAuthorizationsVersionFor spv)
        ]

genRawUpdateInstruction :: (IsProtocolVersion pv) => SProtocolVersion pv -> Gen RawUpdateInstruction
genRawUpdateInstruction spv = do
    ruiSeqNumber <- Nonce <$> arbitrary
    ruiEffectiveTime <- oneof [return 0, TransactionTime <$> arbitrary]
    ruiTimeout <- TransactionTime <$> arbitrary
    ruiPayload <- genUpdatePayload spv
    return RawUpdateInstruction{..}

genLevel2RawUpdateInstruction :: SChainParametersVersion cpv -> Gen RawUpdateInstruction
genLevel2RawUpdateInstruction scpv = do
    ruiSeqNumber <- Nonce <$> arbitrary
    ruiEffectiveTime <- oneof [return 0, TransactionTime <$> arbitrary]
    ruiTimeout <- TransactionTime <$> arbitrary
    ruiPayload <- genLevel2UpdatePayload scpv
    return RawUpdateInstruction{..}

-- | Generate an 'Authorizations' structure and the list of key pairs.
--  The threshold for each access structure is specified.
genAuthorizationsAndKeys ::
    forall auv.
    (IsAuthorizationsVersion auv) =>
    -- | Threshold for each access structure
    UpdateKeysThreshold ->
    Gen (Authorizations auv, [KeyPair])
genAuthorizationsAndKeys thr = do
    let nKeys = case sing @auv of
            SAuthorizationsVersion0 -> fromIntegral thr * 12
            SAuthorizationsVersion1 -> fromIntegral thr * 14
            SAuthorizationsVersion2 -> fromIntegral thr * 15
    kps <- vectorOf nKeys genSigSchemeKeyPair
    let asKeys = Vec.fromList $ correspondingVerifyKey <$> kps
    let genAccessStructure = do
            asnKeys <- chooseBoundedIntegral (fromIntegral thr, nKeys)
            accessPublicKeys <- Set.fromList . take asnKeys <$> shuffle [0 .. fromIntegral nKeys - 1]
            return AccessStructure{accessThreshold = thr, ..}
    asEmergency <- genAccessStructure
    asProtocol <- genAccessStructure
    asParamConsensusParameters <- genAccessStructure
    asParamEuroPerEnergy <- genAccessStructure
    asParamMicroGTUPerEuro <- genAccessStructure
    asParamFoundationAccount <- genAccessStructure
    asParamMintDistribution <- genAccessStructure
    asParamTransactionFeeDistribution <- genAccessStructure
    asParamGASRewards <- genAccessStructure
    asPoolParameters <- genAccessStructure
    asAddAnonymityRevoker <- genAccessStructure
    asAddIdentityProvider <- genAccessStructure
    asCooldownParameters <- conditionallyA (sSupportsCooldownParametersAccessStructure (sing @auv)) genAccessStructure
    asTimeParameters <- conditionallyA (sSupportsTimeParameters (sing @auv)) genAccessStructure
    asCreatePLT <- conditionallyA (sSupportsCreatePLT (sing @auv)) genAccessStructure
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

genKeyCollection :: (IsAuthorizationsVersion auv) => UpdateKeysThreshold -> Gen (UpdateKeysCollection auv, [KeyPair], [KeyPair], [KeyPair])
genKeyCollection thr = do
    (rootKeys, a) <- genRootKeys thr
    (level1Keys, b) <- genLevel1Keys thr
    (level2Keys, c) <- genAuthorizationsAndKeys thr
    return (UpdateKeysCollection{..}, a, b, c)
