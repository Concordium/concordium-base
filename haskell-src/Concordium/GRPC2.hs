{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Part of the implementation of the GRPC2 interface. This module contains
--  a single typeclass 'ToProto' that is used to convert from Haskell types
--  to the generate Proto types.
module Concordium.GRPC2 (
    ToProto (..),
    BakerAddedEvent,
    BakerKeysEvent,
    BlockHashInput (..),
    BlockHeightInput (..),

    -- * Helpers
    mkSerialize,
    mkWord64,
    mkWord32,
    mkWord16,
    mkWord8,
)
where

import Control.Monad
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as BSS
import Data.Coerce
import Data.Foldable (toList)
import qualified Data.Map.Strict as Map
import qualified Data.ProtoLens as Proto
import qualified Data.ProtoLens.Combinators as Proto
import qualified Data.ProtoLens.Field
import qualified Data.Ratio as Ratio
import qualified Data.Serialize as S
import qualified Data.Set as Set
import Data.Singletons
import Data.Text (Text)
import Data.Text.Encoding (decodeUtf8)
import Data.Time (UTCTime)
import qualified Data.Vector as Vec
import Data.Word
import Lens.Micro.Platform
import qualified Proto.V2.Concordium.Kernel as Proto
import qualified Proto.V2.Concordium.ProtocolLevelTokens as Proto
import qualified Proto.V2.Concordium.ProtocolLevelTokens_Fields as PLTFields
import qualified Proto.V2.Concordium.Types as Proto
import qualified Proto.V2.Concordium.Types_Fields as ProtoFields

import Concordium.Crypto.EncryptedTransfers
import Concordium.ID.Types
import Concordium.Types
import Concordium.Types.Accounts
import Concordium.Types.Conditionally
import Concordium.Types.Queries
import qualified Concordium.Types.Queries as QueryTypes
import qualified Concordium.Types.Transactions as Transactions
import qualified Concordium.Types.Transactions as TxTypes

import Concordium.Common.Time
import Concordium.Common.Version
import qualified Concordium.Crypto.BlockSignature as BlockSignature
import Concordium.Crypto.SHA256 (Hash)
import Concordium.Crypto.SignatureScheme (Signature (..), VerifyKey (..))
import qualified Concordium.ID.AnonymityRevoker as ArInfo
import qualified Concordium.ID.IdentityProvider as IpInfo
import Concordium.Types.Accounts.Releases
import Concordium.Types.Block (AbsoluteBlockHeight (..))
import Concordium.Types.Execution
import qualified Concordium.Types.InvokeContract as InvokeContract
import qualified Concordium.Types.Parameters as Parameters
import qualified Concordium.Types.Queries.KonsensusV1 as KonsensusV1
import Concordium.Types.Queries.Tokens
import qualified Concordium.Types.Updates as Updates
import qualified Concordium.Wasm as Wasm

-- | A helper function that can be used to construct a value of a protobuf
--  "wrapper" type by serializing the provided value @a@ using its serialize
--  instance.
--
--  More concretely, the wrapper type should be of the form
--
--  > message Wrapper {
--  >    bytes value = 1
--  > }
--
--  where the name @Wrapper@ can be arbitrary, but the @value@ field must exist,
--  and it must have type @bytes@.
mkSerialize ::
    ( Proto.Message b,
      Data.ProtoLens.Field.HasField
        b
        "value"
        BS.ByteString,
      S.Serialize a
    ) =>
    a ->
    b
mkSerialize ek = Proto.make (ProtoFields.value .= S.encode ek)

-- | Like 'mkSerialize' above, but used to set a wrapper type whose @value@ field
--  has type @uint64@. The supplied value must be coercible to a 'Word64'.
--  Coercible here means that the value is a newtype wrapper (possibly repeated)
--  of a Word64.
mkWord64 ::
    ( Proto.Message b,
      Data.ProtoLens.Field.HasField
        b
        "value"
        Word64,
      Coercible a Word64
    ) =>
    a ->
    b
mkWord64 a = Proto.make (ProtoFields.value .= coerce a)

-- | Like 'mkWord64', but for 32-bit integers instead of 64.
mkWord32 ::
    ( Proto.Message b,
      Data.ProtoLens.Field.HasField
        b
        "value"
        Word32,
      Coercible a Word32
    ) =>
    a ->
    b
mkWord32 a = Proto.make (ProtoFields.value .= coerce a)

-- | Like 'mkWord32', but the supplied value must be coercible to
--  'Word16'.
mkWord16 ::
    forall a b.
    ( Proto.Message b,
      Data.ProtoLens.Field.HasField
        b
        "value"
        Word32,
      Coercible a Word16
    ) =>
    a ->
    b
mkWord16 a = Proto.make (ProtoFields.value .= (fromIntegral (coerce a :: Word16) :: Word32))

-- | Like 'mkWord32', but the supplied value must be coercible to
--  'Word8'.
mkWord8 ::
    forall a b.
    ( Proto.Message b,
      Data.ProtoLens.Field.HasField
        b
        "value"
        Word32,
      Coercible a Word8
    ) =>
    a ->
    b
mkWord8 a = Proto.make (ProtoFields.value .= (fromIntegral (coerce a :: Word8) :: Word32))

-- | A helper class analogous to something like Aeson's ToJSON.
--  It exists to make it more manageable to convert the internal Haskell types to
--  their Protobuf equivalents.
class ToProto a where
    -- | The corresponding Proto type.
    type Output a

    -- | A conversion function from the type to its protobuf equivalent.
    toProto :: a -> Output a

instance ToProto Amount where
    type Output Amount = Proto.Amount
    toProto = mkWord64

instance ToProto BlockHash where
    type Output BlockHash = Proto.BlockHash
    toProto = mkSerialize

instance ToProto Hash where
    type Output Hash = Proto.Sha256Hash
    toProto = mkSerialize

instance ToProto TransactionHashV0 where
    type Output TransactionHashV0 = Proto.TransactionHash
    toProto = mkSerialize

instance ToProto ModuleRef where
    type Output ModuleRef = Proto.ModuleRef
    toProto = mkSerialize

instance ToProto Wasm.WasmModule where
    type Output Wasm.WasmModule = Proto.VersionedModuleSource
    toProto (Wasm.WasmModuleV0 modul) =
        Proto.make
            ( ProtoFields.v0
                .= Proto.make (ProtoFields.value .= Wasm.moduleSource (Wasm.wmvSource modul))
            )
    toProto (Wasm.WasmModuleV1 modul) =
        Proto.make
            ( ProtoFields.v1
                .= Proto.make (ProtoFields.value .= Wasm.moduleSource (Wasm.wmvSource modul))
            )

instance ToProto Wasm.InstanceInfo where
    type Output Wasm.InstanceInfo = Proto.InstanceInfo
    toProto Wasm.InstanceInfoV0{..} =
        Proto.make
            ( ProtoFields.v0
                .= Proto.make
                    ( do
                        ProtoFields.owner .= mkSerialize iiOwner
                        ProtoFields.amount .= mkWord64 iiAmount
                        ProtoFields.methods .= (toProto <$> Set.toList iiMethods)
                        ProtoFields.name .= toProto iiName
                        ProtoFields.sourceModule .= toProto iiSourceModule
                        ProtoFields.model .= toProto iiModel
                    )
            )
    toProto Wasm.InstanceInfoV1{..} =
        Proto.make
            ( ProtoFields.v1
                .= Proto.make
                    ( do
                        ProtoFields.owner .= mkSerialize iiOwner
                        ProtoFields.amount .= mkWord64 iiAmount
                        ProtoFields.methods .= (toProto <$> Set.toList iiMethods)
                        ProtoFields.name .= toProto iiName
                        ProtoFields.sourceModule .= toProto iiSourceModule
                    )
            )

instance ToProto Wasm.ReceiveName where
    type Output Wasm.ReceiveName = Proto.ReceiveName
    toProto name = Proto.make $ ProtoFields.value .= Wasm.receiveName name

instance ToProto Wasm.InitName where
    type Output Wasm.InitName = Proto.InitName
    toProto name = Proto.make $ ProtoFields.value .= Wasm.initName name

instance ToProto Wasm.ContractState where
    type Output Wasm.ContractState = Proto.ContractStateV0
    toProto Wasm.ContractState{..} = Proto.make $ ProtoFields.value .= contractState

instance ToProto ContractAddress where
    type Output ContractAddress = Proto.ContractAddress
    toProto ContractAddress{..} = Proto.make $ do
        ProtoFields.index .= _contractIndex contractIndex
        ProtoFields.subindex .= _contractSubindex contractSubindex

instance ToProto BlockHeight where
    type Output BlockHeight = Proto.BlockHeight
    toProto = mkWord64

instance ToProto AbsoluteBlockHeight where
    type Output AbsoluteBlockHeight = Proto.AbsoluteBlockHeight
    toProto = mkWord64

instance ToProto AccountAddress where
    type Output AccountAddress = Proto.AccountAddress
    toProto = mkSerialize

instance ToProto Nonce where
    type Output Nonce = Proto.SequenceNumber
    toProto = mkWord64

instance ToProto UTCTime where
    type Output UTCTime = Proto.Timestamp
    toProto time = mkWord64 $ utcTimeToTimestamp time

instance ToProto Duration where
    type Output Duration = Proto.Duration
    toProto = mkWord64

instance ToProto GenesisIndex where
    type Output GenesisIndex = Proto.GenesisIndex
    toProto = mkWord32

instance ToProto ProtocolVersion where
    type Output ProtocolVersion = Proto.ProtocolVersion
    toProto P1 = Proto.PROTOCOL_VERSION_1
    toProto P2 = Proto.PROTOCOL_VERSION_2
    toProto P3 = Proto.PROTOCOL_VERSION_3
    toProto P4 = Proto.PROTOCOL_VERSION_4
    toProto P5 = Proto.PROTOCOL_VERSION_5
    toProto P6 = Proto.PROTOCOL_VERSION_6
    toProto P7 = Proto.PROTOCOL_VERSION_7
    toProto P8 = Proto.PROTOCOL_VERSION_8
    toProto P9 = Proto.PROTOCOL_VERSION_9

instance ToProto QueryTypes.NextAccountNonce where
    type Output QueryTypes.NextAccountNonce = Proto.NextAccountSequenceNumber
    toProto QueryTypes.NextAccountNonce{..} = Proto.make $ do
        ProtoFields.sequenceNumber .= toProto nanNonce
        ProtoFields.allFinal .= nanAllFinal

instance ToProto QueryTypes.ConsensusStatus where
    type Output QueryTypes.ConsensusStatus = Proto.ConsensusInfo
    toProto QueryTypes.ConsensusStatus{..} = Proto.make $ do
        ProtoFields.bestBlock .= toProto csBestBlock
        ProtoFields.genesisBlock .= toProto csGenesisBlock
        ProtoFields.genesisTime .= toProto csGenesisTime
        ProtoFields.maybe'slotDuration .= fmap toProto csSlotDuration
        ProtoFields.epochDuration .= toProto csEpochDuration
        ProtoFields.lastFinalizedBlock .= toProto csLastFinalizedBlock
        ProtoFields.bestBlockHeight .= toProto csBestBlockHeight
        ProtoFields.lastFinalizedBlockHeight .= toProto csLastFinalizedBlockHeight
        ProtoFields.blocksReceivedCount .= fromIntegral csBlocksReceivedCount
        ProtoFields.maybe'blockLastReceivedTime .= fmap toProto csBlockLastReceivedTime
        ProtoFields.blockReceiveLatencyEma .= csBlockReceiveLatencyEMA
        ProtoFields.blockReceiveLatencyEmsd .= csBlockReceiveLatencyEMSD
        ProtoFields.maybe'blockReceivePeriodEma .= csBlockReceivePeriodEMA
        ProtoFields.maybe'blockReceivePeriodEmsd .= csBlockReceivePeriodEMSD
        ProtoFields.blocksVerifiedCount .= fromIntegral csBlocksVerifiedCount
        ProtoFields.maybe'blockLastArrivedTime .= fmap toProto csBlockLastArrivedTime
        ProtoFields.blockArriveLatencyEma .= csBlockArriveLatencyEMA
        ProtoFields.blockArriveLatencyEmsd .= csBlockArriveLatencyEMSD
        ProtoFields.maybe'blockArrivePeriodEma .= csBlockArrivePeriodEMA
        ProtoFields.maybe'blockArrivePeriodEmsd .= csBlockArrivePeriodEMSD
        ProtoFields.transactionsPerBlockEma .= csTransactionsPerBlockEMA
        ProtoFields.transactionsPerBlockEmsd .= csTransactionsPerBlockEMSD
        ProtoFields.finalizationCount .= fromIntegral csFinalizationCount
        ProtoFields.maybe'lastFinalizedTime .= fmap toProto csLastFinalizedTime
        ProtoFields.maybe'finalizationPeriodEma .= csFinalizationPeriodEMA
        ProtoFields.maybe'finalizationPeriodEmsd .= csFinalizationPeriodEMSD
        ProtoFields.protocolVersion .= toProto csProtocolVersion
        ProtoFields.genesisIndex .= toProto csGenesisIndex
        ProtoFields.currentEraGenesisBlock .= toProto csCurrentEraGenesisBlock
        ProtoFields.currentEraGenesisTime .= toProto csCurrentEraGenesisTime
        ProtoFields.maybe'currentTimeoutDuration .= fmap (toProto . cbftsCurrentTimeoutDuration) csConcordiumBFTStatus
        ProtoFields.maybe'currentRound .= fmap (toProto . cbftsCurrentRound) csConcordiumBFTStatus
        ProtoFields.maybe'currentEpoch .= fmap (toProto . cbftsCurrentEpoch) csConcordiumBFTStatus
        ProtoFields.maybe'triggerBlockTime .= fmap (toProto . cbftsTriggerBlockTime) csConcordiumBFTStatus

instance ToProto AccountThreshold where
    type Output AccountThreshold = Proto.AccountThreshold
    toProto = mkWord8

instance ToProto SignatureThreshold where
    type Output SignatureThreshold = Proto.SignatureThreshold
    toProto = mkWord8

instance ToProto Threshold where
    type Output Threshold = Proto.ArThreshold
    toProto = mkWord8

instance ToProto AccountIndex where
    type Output AccountIndex = Proto.AccountIndex
    toProto = mkWord64

instance ToProto BakerId where
    type Output BakerId = Proto.BakerId
    toProto = mkWord64

instance ToProto DelegatorId where
    type Output DelegatorId = Proto.DelegatorId
    toProto v = Proto.make $ ProtoFields.id .= toProto (delegatorAccountIndex v)

instance ToProto EncryptedAmount where
    type Output EncryptedAmount = Proto.EncryptedAmount
    toProto = mkSerialize

instance ToProto AccountEncryptedAmount where
    type Output AccountEncryptedAmount = Proto.EncryptedBalance
    toProto encBal =
        case _aggregatedAmount encBal of
            Nothing -> Proto.make mkEncryptedBalance
            Just (aggAmount, numAgg) -> Proto.make $ do
                mkEncryptedBalance
                ProtoFields.aggregatedAmount .= toProto aggAmount
                ProtoFields.numAggregated .= numAgg
      where
        mkEncryptedBalance = do
            ProtoFields.selfAmount .= toProto (_selfAmount encBal)
            ProtoFields.startIndex .= coerce (_startIndex encBal)
            ProtoFields.incomingAmounts .= (toProto <$> toList (_incomingEncryptedAmounts encBal))

instance ToProto AccountReleaseSummary where
    type Output AccountReleaseSummary = Proto.ReleaseSchedule
    toProto ars = Proto.make $ do
        ProtoFields.total .= toProto (releaseTotal ars)
        ProtoFields.schedules .= (toProto <$> releaseSchedule ars)

instance ToProto ScheduledRelease where
    type Output ScheduledRelease = Proto.Release
    toProto r = Proto.make $ do
        ProtoFields.timestamp .= mkWord64 (releaseTimestamp r)
        ProtoFields.amount .= toProto (releaseAmount r)
        ProtoFields.transactions .= (toProto <$> releaseTransactions r)

instance ToProto (Timestamp, Amount) where
    type Output (Timestamp, Amount) = Proto.NewRelease
    toProto (t, a) = Proto.make $ do
        ProtoFields.timestamp .= toProto t
        ProtoFields.amount .= toProto a

instance ToProto Timestamp where
    type Output Timestamp = Proto.Timestamp
    toProto timestamp = mkWord64 $ tsMillis timestamp

instance ToProto (StakePendingChange' UTCTime) where
    type Output (StakePendingChange' UTCTime) = Maybe Proto.StakePendingChange
    toProto NoChange = Nothing
    toProto (ReduceStake newStake effectiveTime) =
        Just . Proto.make $
            ( ProtoFields.reduce
                .= Proto.make
                    ( do
                        ProtoFields.newStake .= toProto newStake
                        ProtoFields.effectiveTime .= toProto effectiveTime
                    )
            )
    toProto (RemoveStake effectiveTime) =
        Just . Proto.make $ (ProtoFields.remove .= toProto effectiveTime)

instance ToProto (StakePendingChange' Timestamp) where
    type Output (StakePendingChange' Timestamp) = Maybe Proto.StakePendingChange
    toProto NoChange = Nothing
    toProto (ReduceStake newStake effectiveTime) =
        Just $
            Proto.make
                ( ProtoFields.reduce
                    .= Proto.make
                        ( do
                            ProtoFields.newStake .= toProto newStake
                            ProtoFields.effectiveTime .= toProto effectiveTime
                        )
                )
    toProto (RemoveStake effectiveTime) =
        Just $ Proto.make (ProtoFields.remove .= toProto effectiveTime)

instance ToProto BakerInfo where
    type Output BakerInfo = Proto.BakerInfo
    toProto BakerInfo{..} =
        Proto.make
            ( do
                ProtoFields.bakerId .= mkWord64 _bakerIdentity
                ProtoFields.electionKey .= mkSerialize _bakerElectionVerifyKey
                ProtoFields.signatureKey .= mkSerialize _bakerSignatureVerifyKey
                ProtoFields.aggregationKey .= mkSerialize _bakerAggregationVerifyKey
            )

instance ToProto OpenStatus where
    type Output OpenStatus = Proto.OpenStatus
    toProto OpenForAll = Proto.OPEN_STATUS_OPEN_FOR_ALL
    toProto ClosedForNew = Proto.OPEN_STATUS_CLOSED_FOR_NEW
    toProto ClosedForAll = Proto.OPEN_STATUS_CLOSED_FOR_ALL

instance ToProto UrlText where
    type Output UrlText = Text
    toProto (UrlText s) = s

instance ToProto PartsPerHundredThousands where
    type Output PartsPerHundredThousands = Proto.AmountFraction
    toProto (PartsPerHundredThousands ppht) = Proto.make (ProtoFields.partsPerHundredThousand .= fromIntegral ppht)

instance ToProto AmountFraction where
    type Output AmountFraction = Proto.AmountFraction
    toProto (AmountFraction ppht) = Proto.make (ProtoFields.partsPerHundredThousand .= fromIntegral ppht)

instance ToProto ElectionDifficulty where
    type Output ElectionDifficulty = Proto.ElectionDifficulty
    toProto (ElectionDifficulty ppht) = Proto.make $ ProtoFields.value . ProtoFields.partsPerHundredThousand .= fromIntegral ppht

instance ToProto CommissionRates where
    type Output CommissionRates = Proto.CommissionRates
    toProto CommissionRates{..} = Proto.make $ do
        ProtoFields.finalization .= toProto _finalizationCommission
        ProtoFields.baking .= toProto _bakingCommission
        ProtoFields.transaction .= toProto _transactionCommission

instance ToProto BakerPoolInfo where
    type Output BakerPoolInfo = Proto.BakerPoolInfo
    toProto BakerPoolInfo{..} = Proto.make $ do
        ProtoFields.openStatus .= toProto _poolOpenStatus
        ProtoFields.url .= toProto _poolMetadataUrl
        ProtoFields.commissionRates .= toProto _poolCommissionRates

instance ToProto AccountStakingInfo where
    type Output AccountStakingInfo = Maybe Proto.AccountStakingInfo
    toProto AccountStakingNone = Nothing
    toProto AccountStakingBaker{..} =
        Just . Proto.make $
            ( do
                ProtoFields.baker
                    .= Proto.make
                        ( do
                            ProtoFields.stakedAmount .= toProto asiStakedAmount
                            ProtoFields.restakeEarnings .= asiStakeEarnings
                            ProtoFields.bakerInfo .= toProto asiBakerInfo
                            ProtoFields.maybe'pendingChange .= toProto asiPendingChange
                            case asiPoolInfo of
                                Nothing -> return ()
                                Just asipi -> ProtoFields.poolInfo .= toProto asipi
                            ProtoFields.isSuspended .= asiIsSuspended
                        )
            )
    toProto AccountStakingDelegated{..} =
        Just . Proto.make $
            ( do
                ProtoFields.delegator
                    .= Proto.make
                        ( do
                            ProtoFields.stakedAmount .= mkWord64 asiStakedAmount
                            ProtoFields.restakeEarnings .= asiStakeEarnings
                            ProtoFields.target .= toProto asiDelegationTarget
                            ProtoFields.maybe'pendingChange .= toProto asiDelegationPendingChange
                        )
            )

instance ToProto DelegationTarget where
    type Output DelegationTarget = Proto.DelegationTarget
    toProto DelegatePassive = Proto.make $ ProtoFields.passive .= Proto.defMessage
    toProto (DelegateToBaker bi) = Proto.make $ ProtoFields.baker .= toProto bi

instance ToProto (Map.Map CredentialIndex (Versioned RawAccountCredential)) where
    type Output (Map.Map CredentialIndex (Versioned RawAccountCredential)) = Map.Map Word32 Proto.AccountCredential
    toProto = Map.fromAscList . map (\(k, v) -> (fromIntegral k, toProto (vValue v))) . Map.toAscList

instance ToProto CredentialPublicKeys where
    type Output CredentialPublicKeys = Proto.CredentialPublicKeys
    toProto CredentialPublicKeys{..} = Proto.make $ do
        ProtoFields.threshold .= mkWord8 credThreshold
        ProtoFields.keys .= (Map.fromAscList . map convertKey . Map.toAscList $ credKeys)
      where
        convertKey (ki, VerifyKeyEd25519 key) = (fromIntegral ki, Proto.make $ ProtoFields.ed25519Key .= S.encode key)

instance ToProto Policy where
    type Output Policy = Proto.Policy
    toProto Policy{..} = Proto.make $ do
        ProtoFields.createdAt .= toProto pCreatedAt
        ProtoFields.validTo .= toProto pValidTo
        ProtoFields.attributes .= mkAttributes pItems
      where
        mkAttributes =
            Map.fromAscList
                . map (\(AttributeTag tag, value) -> (fromIntegral tag, S.runPut (S.putShortByteString (coerce value))))
                . Map.toAscList

instance ToProto YearMonth where
    type Output YearMonth = Proto.YearMonth
    toProto YearMonth{..} = Proto.make $ do
        ProtoFields.year .= fromIntegral ymYear
        ProtoFields.month .= fromIntegral ymMonth

instance ToProto RawCredentialRegistrationID where
    type Output RawCredentialRegistrationID = Proto.CredentialRegistrationId
    toProto = mkSerialize

instance ToProto CredentialRegistrationID where
    type Output CredentialRegistrationID = Proto.CredentialRegistrationId
    toProto = toProto . toRawCredRegId

instance ToProto IdentityProviderIdentity where
    type Output IdentityProviderIdentity = Proto.IdentityProviderIdentity
    toProto = mkWord32

instance ToProto Commitment where
    type Output Commitment = Proto.Commitment
    toProto = mkSerialize

instance ToProto CredentialDeploymentCommitments where
    type Output CredentialDeploymentCommitments = Proto.CredentialCommitments
    toProto CredentialDeploymentCommitments{..} = Proto.make $ do
        ProtoFields.prf .= toProto cmmPrf
        ProtoFields.credCounter .= toProto cmmCredCounter
        ProtoFields.maxAccounts .= toProto cmmMaxAccounts
        ProtoFields.attributes
            .= ( Map.fromAscList
                    . map (\(AttributeTag tag, v) -> (fromIntegral tag :: Word32, toProto v))
                    . Map.toAscList
               )
                cmmAttributes
        ProtoFields.idCredSecSharingCoeff .= map toProto cmmIdCredSecSharingCoeff

instance ToProto (Map.Map ArIdentity ChainArData) where
    type Output (Map.Map ArIdentity ChainArData) = Map.Map Word32 Proto.ChainArData
    toProto = Map.fromAscList . map (\(k, v) -> (coerce k, dataToProto v)) . Map.toAscList
      where
        dataToProto d = Proto.make (ProtoFields.encIdCredPubShare .= S.encode d)

instance ToProto RawAccountCredential where
    type Output RawAccountCredential = Proto.AccountCredential
    toProto (InitialAC InitialCredentialDeploymentValues{..}) =
        Proto.make $
            ProtoFields.initial
                .= Proto.make
                    ( do
                        ProtoFields.keys .= toProto icdvAccount
                        ProtoFields.credId .= toProto icdvRegId
                        ProtoFields.ipId .= toProto icdvIpId
                        ProtoFields.policy .= toProto icdvPolicy
                    )
    toProto (NormalAC CredentialDeploymentValues{..} commitments) =
        Proto.make $
            ProtoFields.normal
                .= Proto.make
                    ( do
                        ProtoFields.keys .= toProto cdvPublicKeys
                        ProtoFields.credId .= toProto cdvCredId
                        ProtoFields.ipId .= toProto cdvIpId
                        ProtoFields.policy .= toProto cdvPolicy
                        ProtoFields.arThreshold .= toProto cdvThreshold
                        ProtoFields.arData .= toProto cdvArData
                        ProtoFields.commitments .= toProto commitments
                    )

instance ToProto AccountEncryptionKey where
    type Output AccountEncryptionKey = Proto.EncryptionKey
    toProto = mkSerialize

instance ToProto CooldownStatus where
    type Output CooldownStatus = Proto.Cooldown'CooldownStatus
    toProto StatusCooldown = Proto.Cooldown'COOLDOWN
    toProto StatusPreCooldown = Proto.Cooldown'PRE_COOLDOWN
    toProto StatusPrePreCooldown = Proto.Cooldown'PRE_PRE_COOLDOWN

instance ToProto Cooldown where
    type Output Cooldown = Proto.Cooldown
    toProto Cooldown{..} = Proto.make $ do
        ProtoFields.endTime .= toProto cooldownTimestamp
        ProtoFields.amount .= toProto cooldownAmount
        ProtoFields.status .= toProto cooldownStatus

instance ToProto TokenAmount where
    type Output TokenAmount = Proto.TokenAmount
    toProto TokenAmount{..} = Proto.make $ do
        PLTFields.digits .= digits
        PLTFields.nrOfDecimals .= fromIntegral nrDecimals

instance ToProto TokenAccountState where
    type Output TokenAccountState = Proto.TokenAccountState
    toProto TokenAccountState{..} = Proto.make $ do
        PLTFields.balance .= toProto balance

instance ToProto Token where
    type Output Token = Proto.AccountInfo'Token
    toProto Token{..} = Proto.make $ do
        ProtoFields.tokenId .= toProto tokenId
        ProtoFields.tokenAccountState .= toProto tokenAccountState

instance ToProto AccountInfo where
    type Output AccountInfo = Proto.AccountInfo
    toProto AccountInfo{..} = Proto.make $ do
        ProtoFields.sequenceNumber .= toProto aiAccountNonce
        ProtoFields.amount .= toProto aiAccountAmount
        ProtoFields.schedule .= toProto aiAccountReleaseSchedule
        ProtoFields.creds .= toProto aiAccountCredentials
        ProtoFields.threshold .= toProto aiAccountThreshold
        ProtoFields.encryptedBalance .= toProto aiAccountEncryptedAmount
        ProtoFields.encryptionKey .= toProto aiAccountEncryptionKey
        ProtoFields.index .= toProto aiAccountIndex
        ProtoFields.address .= toProto aiAccountAddress
        ProtoFields.maybe'stake .= toProto aiStakingInfo
        ProtoFields.cooldowns .= fmap toProto aiAccountCooldowns
        ProtoFields.availableBalance .= toProto aiAccountAvailableAmount
        ProtoFields.tokens .= fmap toProto aiAccountTokens

instance ToProto TokenState where
    type Output TokenState = Proto.TokenState
    toProto TokenState{..} = Proto.make $ do
        PLTFields.tokenModuleRef .= toProto tsTokenModuleRef
        PLTFields.issuer .= toProto tsIssuer
        PLTFields.nrOfDecimals .= fromIntegral tsDecimals
        PLTFields.totalSupply .= toProto tsTotalSupply
        PLTFields.moduleState .= Proto.make (PLTFields.value .= tsModuleState)

instance ToProto TokenInfo where
    type Output TokenInfo = Proto.TokenInfo
    toProto TokenInfo{..} = Proto.make $ do
        ProtoFields.tokenId .= toProto tiTokenId
        ProtoFields.tokenState .= toProto tiTokenState

instance ToProto Wasm.Parameter where
    type Output Wasm.Parameter = Proto.Parameter
    toProto Wasm.Parameter{..} = Proto.make $ ProtoFields.value .= BSS.fromShort parameter

instance ToProto TokenModuleRef where
    type Output TokenModuleRef = Proto.TokenModuleRef
    toProto = mkSerialize

instance ToProto TokenModuleRejectReason where
    type Output TokenModuleRejectReason = Proto.TokenModuleRejectReason
    toProto TokenModuleRejectReason{..} = Proto.make $ do
        PLTFields.tokenSymbol .= toProto tmrrTokenSymbol
        PLTFields.type' .= toProto tmrrType
        PLTFields.maybe'details .= fmap toProto tmrrDetails

instance ToProto RejectReason where
    type Output RejectReason = Proto.RejectReason
    toProto r = case r of
        ModuleNotWF -> Proto.make $ ProtoFields.moduleNotWf .= Proto.defMessage
        ModuleHashAlreadyExists moduleRef -> Proto.make $ ProtoFields.moduleHashAlreadyExists .= toProto moduleRef
        InvalidAccountReference addr -> Proto.make $ ProtoFields.invalidAccountReference .= toProto addr
        InvalidInitMethod moduleRef initName ->
            Proto.make $
                ProtoFields.invalidInitMethod
                    .= Proto.make
                        ( do
                            ProtoFields.moduleRef .= toProto moduleRef
                            ProtoFields.initName .= toProto initName
                        )
        InvalidReceiveMethod moduleRef receiveName ->
            Proto.make $
                ProtoFields.invalidReceiveMethod
                    .= Proto.make
                        ( do
                            ProtoFields.moduleRef .= toProto moduleRef
                            ProtoFields.receiveName .= toProto receiveName
                        )
        InvalidModuleReference moduleRef -> Proto.make $ ProtoFields.invalidModuleReference .= toProto moduleRef
        InvalidContractAddress addr -> Proto.make $ ProtoFields.invalidContractAddress .= toProto addr
        RuntimeFailure -> Proto.make $ ProtoFields.runtimeFailure .= Proto.defMessage
        AmountTooLarge addr amount ->
            Proto.make $
                ProtoFields.amountTooLarge
                    .= Proto.make
                        ( do
                            ProtoFields.address .= toProto addr
                            ProtoFields.amount .= toProto amount
                        )
        SerializationFailure -> Proto.make $ ProtoFields.serializationFailure .= Proto.defMessage
        OutOfEnergy -> Proto.make $ ProtoFields.outOfEnergy .= Proto.defMessage
        RejectedInit{..} -> Proto.make $ ProtoFields.rejectedInit . ProtoFields.rejectReason .= rejectReason
        RejectedReceive{..} ->
            Proto.make $
                ProtoFields.rejectedReceive
                    .= Proto.make
                        ( do
                            ProtoFields.rejectReason .= rejectReason
                            ProtoFields.contractAddress .= toProto contractAddress
                            ProtoFields.receiveName .= toProto receiveName
                            ProtoFields.parameter .= toProto parameter
                        )
        InvalidProof -> Proto.make $ ProtoFields.invalidProof .= Proto.defMessage
        AlreadyABaker bakerId -> Proto.make $ ProtoFields.alreadyABaker .= toProto bakerId
        NotABaker addr -> Proto.make $ ProtoFields.notABaker .= toProto addr
        InsufficientBalanceForBakerStake -> Proto.make $ ProtoFields.insufficientBalanceForBakerStake .= Proto.defMessage
        StakeUnderMinimumThresholdForBaking -> Proto.make $ ProtoFields.stakeUnderMinimumThresholdForBaking .= Proto.defMessage
        BakerInCooldown -> Proto.make $ ProtoFields.bakerInCooldown .= Proto.defMessage
        DuplicateAggregationKey k -> Proto.make $ ProtoFields.duplicateAggregationKey .= mkSerialize k
        NonExistentCredentialID -> Proto.make $ ProtoFields.nonExistentCredentialId .= Proto.defMessage
        KeyIndexAlreadyInUse -> Proto.make $ ProtoFields.keyIndexAlreadyInUse .= Proto.defMessage
        InvalidAccountThreshold -> Proto.make $ ProtoFields.invalidAccountThreshold .= Proto.defMessage
        InvalidCredentialKeySignThreshold -> Proto.make $ ProtoFields.invalidCredentialKeySignThreshold .= Proto.defMessage
        InvalidEncryptedAmountTransferProof -> Proto.make $ ProtoFields.invalidEncryptedAmountTransferProof .= Proto.defMessage
        InvalidTransferToPublicProof -> Proto.make $ ProtoFields.invalidTransferToPublicProof .= Proto.defMessage
        EncryptedAmountSelfTransfer addr -> Proto.make $ ProtoFields.encryptedAmountSelfTransfer .= toProto addr
        InvalidIndexOnEncryptedTransfer -> Proto.make $ ProtoFields.invalidIndexOnEncryptedTransfer .= Proto.defMessage
        ZeroScheduledAmount -> Proto.make $ ProtoFields.zeroScheduledAmount .= Proto.defMessage
        NonIncreasingSchedule -> Proto.make $ ProtoFields.nonIncreasingSchedule .= Proto.defMessage
        FirstScheduledReleaseExpired -> Proto.make $ ProtoFields.firstScheduledReleaseExpired .= Proto.defMessage
        ScheduledSelfTransfer addr -> Proto.make $ ProtoFields.scheduledSelfTransfer .= toProto addr
        InvalidCredentials -> Proto.make $ ProtoFields.invalidCredentials .= Proto.defMessage
        DuplicateCredIDs ids -> Proto.make $ ProtoFields.duplicateCredIds . ProtoFields.ids .= (toProto <$> ids)
        NonExistentCredIDs ids -> Proto.make $ ProtoFields.nonExistentCredIds . ProtoFields.ids .= (toProto <$> ids)
        RemoveFirstCredential -> Proto.make $ ProtoFields.removeFirstCredential .= Proto.defMessage
        CredentialHolderDidNotSign -> Proto.make $ ProtoFields.credentialHolderDidNotSign .= Proto.defMessage
        NotAllowedMultipleCredentials -> Proto.make $ ProtoFields.notAllowedMultipleCredentials .= Proto.defMessage
        NotAllowedToReceiveEncrypted -> Proto.make $ ProtoFields.notAllowedToReceiveEncrypted .= Proto.defMessage
        NotAllowedToHandleEncrypted -> Proto.make $ ProtoFields.notAllowedToHandleEncrypted .= Proto.defMessage
        MissingBakerAddParameters -> Proto.make $ ProtoFields.missingBakerAddParameters .= Proto.defMessage
        FinalizationRewardCommissionNotInRange -> Proto.make $ ProtoFields.finalizationRewardCommissionNotInRange .= Proto.defMessage
        BakingRewardCommissionNotInRange -> Proto.make $ ProtoFields.bakingRewardCommissionNotInRange .= Proto.defMessage
        TransactionFeeCommissionNotInRange -> Proto.make $ ProtoFields.transactionFeeCommissionNotInRange .= Proto.defMessage
        AlreadyADelegator -> Proto.make $ ProtoFields.alreadyADelegator .= Proto.defMessage
        InsufficientBalanceForDelegationStake -> Proto.make $ ProtoFields.insufficientBalanceForDelegationStake .= Proto.defMessage
        MissingDelegationAddParameters -> Proto.make $ ProtoFields.missingDelegationAddParameters .= Proto.defMessage
        InsufficientDelegationStake -> Proto.make $ ProtoFields.insufficientDelegationStake .= Proto.defMessage
        DelegatorInCooldown -> Proto.make $ ProtoFields.delegatorInCooldown .= Proto.defMessage
        NotADelegator addr -> Proto.make $ ProtoFields.notADelegator .= toProto addr
        DelegationTargetNotABaker bakerId -> Proto.make $ ProtoFields.delegationTargetNotABaker .= toProto bakerId
        StakeOverMaximumThresholdForPool -> Proto.make $ ProtoFields.stakeOverMaximumThresholdForPool .= Proto.defMessage
        PoolWouldBecomeOverDelegated -> Proto.make $ ProtoFields.poolWouldBecomeOverDelegated .= Proto.defMessage
        PoolClosed -> Proto.make $ ProtoFields.poolClosed .= Proto.defMessage
        NonExistentTokenId tokenId -> Proto.make $ ProtoFields.nonExistentTokenId .= toProto tokenId
        TokenHolderTransactionFailed reason -> Proto.make $ ProtoFields.tokenHolderTransactionFailed .= toProto reason
        TokenGovernanceTransactionFailed reason -> Proto.make $ ProtoFields.tokenGovernanceTransactionFailed .= toProto reason
        UnauthorizedTokenGovernance tokenId -> Proto.make $ ProtoFields.unauthorizedTokenGovernance .= toProto tokenId

-- | Attempt to convert the node's TransactionStatus type into the protobuf BlockItemStatus type.
--   The protobuf type is better structured and removes the need for handling impossible cases.
--   For example the case of an account transfer resulting in a smart contract update, which is a
--   technical possibility in the way that the node's trx status is defined.
instance ToProto QueryTypes.SupplementedTransactionStatus where
    type Output QueryTypes.SupplementedTransactionStatus = Either ConversionError Proto.BlockItemStatus
    toProto ts = case ts of
        QueryTypes.Received -> Right . Proto.make $ ProtoFields.received .= Proto.defMessage
        QueryTypes.Finalized bh trx -> do
            bis <- toBis trx
            trxInBlock <- toTrxInBlock bh bis
            Right . Proto.make $ ProtoFields.finalized . ProtoFields.outcome .= trxInBlock
        QueryTypes.Committed trxs -> do
            outcomes <- mapM (\(bh, trx) -> toTrxInBlock bh =<< toBis trx) $ Map.toList trxs
            Right . Proto.make $ ProtoFields.committed . ProtoFields.outcomes .= outcomes
      where
        -- \|Convert a transaction summary to a proto block item summary.
        --  The transaction summary can technically be Nothing, but it should never occur.
        toBis :: Maybe SupplementedTransactionSummary -> Either ConversionError Proto.BlockItemSummary
        toBis Nothing = Left CEInvalidTransactionResult
        toBis (Just t) = toProto t

        toTrxInBlock bh bis = Right . Proto.make $ do
            ProtoFields.blockHash .= toProto bh
            ProtoFields.outcome .= bis

-- | Attempt to convert a SupplementedTransactionSummary type into the protobuf BlockItemSummary
--   type. See @toBlockItemStatus@ for more context.
instance ToProto SupplementedTransactionSummary where
    type Output SupplementedTransactionSummary = Either ConversionError Proto.BlockItemSummary
    toProto TransactionSummary{..} = case tsType of
        TSTAccountTransaction tty -> do
            sender <- case tsSender of
                Nothing -> Left CEInvalidTransactionResult
                Just acc -> Right acc
            details <- convertAccountTransaction tty tsCost sender tsResult
            Right . Proto.make $ do
                ProtoFields.index .= mkWord64 tsIndex
                ProtoFields.energyCost .= toProto tsEnergyCost
                ProtoFields.hash .= toProto tsHash
                ProtoFields.accountTransaction .= details
        TSTCredentialDeploymentTransaction ct -> case tsResult of
            TxReject _ -> Left CEFailedAccountCreation
            TxSuccess events -> case events of
                [AccountCreated addr, CredentialDeployed{..}] ->
                    let
                        details = Proto.make $ do
                            ProtoFields.credentialType .= toProto ct
                            ProtoFields.address .= toProto addr
                            ProtoFields.regId .= toProto ecdRegId
                    in
                        Right . Proto.make $ do
                            ProtoFields.index .= mkWord64 tsIndex
                            ProtoFields.energyCost .= toProto tsEnergyCost
                            ProtoFields.hash .= toProto tsHash
                            ProtoFields.accountCreation .= details
                _ -> Left CEInvalidAccountCreation
        TSTUpdateTransaction ut -> case tsResult of
            TxReject _ -> Left CEFailedUpdate
            TxSuccess events -> case events of
                [UpdateEnqueued{..}] -> do
                    payload <- convertUpdatePayload ut uePayload
                    details <- Right . Proto.make $ do
                        ProtoFields.effectiveTime .= toProto ueEffectiveTime
                        ProtoFields.payload .= payload
                    Right . Proto.make $ do
                        ProtoFields.index .= mkWord64 tsIndex
                        ProtoFields.energyCost .= toProto tsEnergyCost
                        ProtoFields.hash .= toProto tsHash
                        ProtoFields.update .= details
                _ -> Left CEInvalidUpdateResult

instance ToProto Updates.ProtocolUpdate where
    type Output Updates.ProtocolUpdate = Proto.ProtocolUpdate
    toProto Updates.ProtocolUpdate{..} = Proto.make $ do
        ProtoFields.message .= puMessage
        ProtoFields.specificationUrl .= puSpecificationURL
        ProtoFields.specificationHash .= toProto puSpecificationHash
        ProtoFields.specificationAuxiliaryData .= puSpecificationAuxiliaryData

instance ToProto (Parameters.MintDistribution 'Parameters.MintDistributionVersion0) where
    type Output (Parameters.MintDistribution 'Parameters.MintDistributionVersion0) = Proto.MintDistributionCpv0
    toProto md = Proto.make $ do
        ProtoFields.mintPerSlot .= toProto (md ^. Parameters.mdMintPerSlot . Parameters.unconditionally)
        ProtoFields.bakingReward .= toProto (Parameters._mdBakingReward md)
        ProtoFields.finalizationReward .= toProto (Parameters._mdFinalizationReward md)

instance ToProto (Parameters.MintDistribution 'Parameters.MintDistributionVersion1) where
    type Output (Parameters.MintDistribution 'Parameters.MintDistributionVersion1) = Proto.MintDistributionCpv1
    toProto md = Proto.make $ do
        ProtoFields.bakingReward .= toProto (Parameters._mdBakingReward md)
        ProtoFields.finalizationReward .= toProto (Parameters._mdFinalizationReward md)

instance ToProto Parameters.TransactionFeeDistribution where
    type Output Parameters.TransactionFeeDistribution = Proto.TransactionFeeDistribution
    toProto Parameters.TransactionFeeDistribution{..} = Proto.make $ do
        ProtoFields.baker .= toProto _tfdBaker
        ProtoFields.gasAccount .= toProto _tfdGASAccount

instance ToProto (Parameters.GASRewards 'Parameters.GASRewardsVersion0) where
    type Output (Parameters.GASRewards 'Parameters.GASRewardsVersion0) = Proto.GasRewards
    toProto Parameters.GASRewards{..} = Proto.make $ do
        ProtoFields.baker .= toProto _gasBaker
        ProtoFields.finalizationProof .= toProto (_gasFinalizationProof ^. Parameters.unconditionally)
        ProtoFields.accountCreation .= toProto _gasAccountCreation
        ProtoFields.chainUpdate .= toProto _gasChainUpdate

instance ToProto (Parameters.GASRewards 'Parameters.GASRewardsVersion1) where
    type Output (Parameters.GASRewards 'Parameters.GASRewardsVersion1) = Proto.GasRewardsCpv2
    toProto Parameters.GASRewards{..} = Proto.make $ do
        ProtoFields.baker .= toProto _gasBaker
        ProtoFields.accountCreation .= toProto _gasAccountCreation
        ProtoFields.chainUpdate .= toProto _gasChainUpdate

instance ToProto (Parameters.PoolParameters' 'Parameters.PoolParametersVersion0) where
    type Output (Parameters.PoolParameters' 'Parameters.PoolParametersVersion0) = Proto.BakerStakeThreshold
    toProto pp = Proto.make $ ProtoFields.bakerStakeThreshold .= toProto (pp ^. Parameters.ppBakerStakeThreshold)

instance ToProto (Parameters.PoolParameters' 'Parameters.PoolParametersVersion1) where
    type Output (Parameters.PoolParameters' 'Parameters.PoolParametersVersion1) = Proto.PoolParametersCpv1
    toProto pp = Proto.make $ do
        ProtoFields.passiveFinalizationCommission .= toProto (pp ^. Parameters.ppPassiveCommissions . finalizationCommission)
        ProtoFields.passiveBakingCommission .= toProto (pp ^. Parameters.ppPassiveCommissions . bakingCommission)
        ProtoFields.passiveTransactionCommission .= toProto (pp ^. Parameters.ppPassiveCommissions . transactionCommission)
        ProtoFields.commissionBounds
            .= Proto.make
                ( do
                    ProtoFields.finalization .= toProto (pp ^. Parameters.ppCommissionBounds . Parameters.finalizationCommissionRange)
                    ProtoFields.baking .= toProto (pp ^. Parameters.ppCommissionBounds . Parameters.bakingCommissionRange)
                    ProtoFields.transaction .= toProto (pp ^. Parameters.ppCommissionBounds . Parameters.transactionCommissionRange)
                )
        ProtoFields.minimumEquityCapital .= toProto (pp ^. Parameters.ppMinimumEquityCapital)
        ProtoFields.capitalBound .= toProto (pp ^. Parameters.ppCapitalBound)
        ProtoFields.leverageBound .= toProto (pp ^. Parameters.ppLeverageBound)

instance ToProto (Parameters.CooldownParameters' 'Parameters.CooldownParametersVersion1) where
    type Output (Parameters.CooldownParameters' 'Parameters.CooldownParametersVersion1) = Proto.CooldownParametersCpv1
    toProto (Parameters.CooldownParametersV1{..}) = Proto.make $ do
        ProtoFields.poolOwnerCooldown .= toProto _cpPoolOwnerCooldown
        ProtoFields.delegatorCooldown .= toProto _cpDelegatorCooldown

instance ToProto Parameters.TimeParameters where
    type Output Parameters.TimeParameters = Proto.TimeParametersCpv1
    toProto Parameters.TimeParametersV1{..} = Proto.make $ do
        ProtoFields.rewardPeriodLength .= toProto _tpRewardPeriodLength
        ProtoFields.mintPerPayday .= toProto _tpMintPerPayday

instance ToProto Parameters.TimeoutParameters where
    type Output Parameters.TimeoutParameters = Proto.TimeoutParameters
    toProto Parameters.TimeoutParameters{..} = Proto.make $ do
        ProtoFields.timeoutBase .= toProto _tpTimeoutBase
        ProtoFields.timeoutIncrease .= toProto _tpTimeoutIncrease
        ProtoFields.timeoutDecrease .= toProto _tpTimeoutDecrease

instance ToProto Parameters.FinalizationCommitteeParameters where
    type Output Parameters.FinalizationCommitteeParameters = Proto.FinalizationCommitteeParameters
    toProto Parameters.FinalizationCommitteeParameters{..} = Proto.make $ do
        ProtoFields.minimumFinalizers .= _fcpMinFinalizers
        ProtoFields.maximumFinalizers .= _fcpMaxFinalizers
        ProtoFields.finalizerRelativeStakeThreshold .= toProto _fcpFinalizerRelativeStakeThreshold

instance ToProto Parameters.ValidatorScoreParameters where
    type Output Parameters.ValidatorScoreParameters = Proto.ValidatorScoreParameters
    toProto Parameters.ValidatorScoreParameters{..} =
        Proto.make $
            ProtoFields.maximumMissedRounds .= _vspMaxMissedRounds

instance ToProto (Parameters.ConsensusParameters' 'Parameters.ConsensusParametersVersion1) where
    type Output (Parameters.ConsensusParameters' 'Parameters.ConsensusParametersVersion1) = Proto.ConsensusParametersV1
    toProto Parameters.ConsensusParametersV1{..} = Proto.make $ do
        ProtoFields.timeoutParameters .= toProto _cpTimeoutParameters
        ProtoFields.minBlockTime .= toProto _cpMinBlockTime
        ProtoFields.blockEnergyLimit .= toProto _cpBlockEnergyLimit

instance ToProto CreatePLT where
    type Output CreatePLT = Proto.CreatePLT
    toProto CreatePLT{..} = Proto.make $ do
        PLTFields.tokenSymbol .= toProto _cpltTokenSymbol
        PLTFields.tokenModule .= toProto _cpltTokenModule
        PLTFields.governanceAccount .= toProto _cpltGovernanceAccount
        PLTFields.decimals .= fromIntegral _cpltDecimals
        PLTFields.initializationParameters .= toProto _cpltInitializationParameters

-- | Attempt to construct the protobuf updatepayload.
--   See @toBlockItemStatus@ for more context.
convertUpdatePayload :: Updates.UpdateType -> Updates.UpdatePayload -> Either ConversionError Proto.UpdatePayload
convertUpdatePayload ut pl = case (ut, pl) of
    (Updates.UpdateProtocol, Updates.ProtocolUpdatePayload pu) -> Right . Proto.make $ ProtoFields.protocolUpdate .= toProto pu
    (Updates.UpdateElectionDifficulty, Updates.ElectionDifficultyUpdatePayload ed) -> Right . Proto.make $ ProtoFields.electionDifficultyUpdate .= toProto ed
    (Updates.UpdateEuroPerEnergy, Updates.EuroPerEnergyUpdatePayload er) -> Right . Proto.make $ ProtoFields.euroPerEnergyUpdate .= toProto er
    (Updates.UpdateMicroGTUPerEuro, Updates.MicroGTUPerEuroUpdatePayload er) -> Right . Proto.make $ ProtoFields.microCcdPerEuroUpdate .= toProto er
    (Updates.UpdateFoundationAccount, Updates.FoundationAccountUpdatePayload addr) -> Right . Proto.make $ ProtoFields.foundationAccountUpdate .= toProto addr
    (Updates.UpdateMintDistribution, Updates.MintDistributionUpdatePayload md) -> Right . Proto.make $ ProtoFields.mintDistributionUpdate .= toProto md
    (Updates.UpdateTransactionFeeDistribution, Updates.TransactionFeeDistributionUpdatePayload tfd) ->
        Right . Proto.make $ ProtoFields.transactionFeeDistributionUpdate .= toProto tfd
    (Updates.UpdateGASRewards, Updates.GASRewardsUpdatePayload gr) -> Right . Proto.make $ ProtoFields.gasRewardsUpdate .= toProto gr
    (Updates.UpdateGASRewards, Updates.GASRewardsCPV2UpdatePayload gr) -> Right . Proto.make $ ProtoFields.gasRewardsCpv2Update .= toProto gr
    (Updates.UpdatePoolParameters, Updates.BakerStakeThresholdUpdatePayload pp) ->
        Right . Proto.make $ ProtoFields.bakerStakeThresholdUpdate .= toProto pp
    (Updates.UpdateRootKeys, Updates.RootUpdatePayload ru@(Updates.RootKeysRootUpdate{})) -> Right . Proto.make $ ProtoFields.rootUpdate .= toProto ru
    (Updates.UpdateLevel1Keys, Updates.RootUpdatePayload ru@(Updates.Level1KeysRootUpdate{})) -> Right . Proto.make $ ProtoFields.rootUpdate .= toProto ru
    (Updates.UpdateLevel2Keys, Updates.RootUpdatePayload ru@(Updates.Level2KeysRootUpdate{})) -> Right . Proto.make $ ProtoFields.rootUpdate .= toProto ru
    (Updates.UpdateLevel2Keys, Updates.RootUpdatePayload ru@(Updates.Level2KeysRootUpdateV1{})) -> Right . Proto.make $ ProtoFields.rootUpdate .= toProto ru
    (Updates.UpdateLevel1Keys, Updates.Level1UpdatePayload u@(Updates.Level1KeysLevel1Update{})) -> Right . Proto.make $ ProtoFields.level1Update .= toProto u
    (Updates.UpdateLevel2Keys, Updates.Level1UpdatePayload u@(Updates.Level2KeysLevel1Update{})) -> Right . Proto.make $ ProtoFields.level1Update .= toProto u
    (Updates.UpdateLevel2Keys, Updates.Level1UpdatePayload u@(Updates.Level2KeysLevel1UpdateV1{})) -> Right . Proto.make $ ProtoFields.level1Update .= toProto u
    (Updates.UpdateAddAnonymityRevoker, Updates.AddAnonymityRevokerUpdatePayload ai) -> Right . Proto.make $ ProtoFields.addAnonymityRevokerUpdate .= toProto ai
    (Updates.UpdateAddIdentityProvider, Updates.AddIdentityProviderUpdatePayload ip) -> Right . Proto.make $ ProtoFields.addIdentityProviderUpdate .= toProto ip
    (Updates.UpdateCooldownParameters, Updates.CooldownParametersCPV1UpdatePayload cp) -> Right $ Proto.make $ ProtoFields.cooldownParametersCpv1Update .= toProto cp
    (Updates.UpdatePoolParameters, Updates.PoolParametersCPV1UpdatePayload pp) -> Right . Proto.make $ ProtoFields.poolParametersCpv1Update .= toProto pp
    (Updates.UpdateTimeParameters, Updates.TimeParametersCPV1UpdatePayload tp) -> Right . Proto.make $ ProtoFields.timeParametersCpv1Update .= toProto tp
    (Updates.UpdateMintDistribution, Updates.MintDistributionCPV1UpdatePayload md) -> Right . Proto.make $ ProtoFields.mintDistributionCpv1Update .= toProto md
    (Updates.UpdateTimeoutParameters, Updates.TimeoutParametersUpdatePayload tp) -> Right . Proto.make $ ProtoFields.timeoutParametersUpdate .= toProto tp
    (Updates.UpdateMinBlockTime, Updates.MinBlockTimeUpdatePayload mbt) -> Right . Proto.make $ ProtoFields.minBlockTimeUpdate .= toProto mbt
    (Updates.UpdateBlockEnergyLimit, Updates.BlockEnergyLimitUpdatePayload bel) -> Right . Proto.make $ ProtoFields.blockEnergyLimitUpdate .= toProto bel
    (Updates.UpdateFinalizationCommitteeParameters, Updates.FinalizationCommitteeParametersUpdatePayload fcp) -> Right . Proto.make $ ProtoFields.finalizationCommitteeParametersUpdate .= toProto fcp
    (Updates.UpdateValidatorScoreParameters, Updates.ValidatorScoreParametersUpdatePayload vsp) -> Right . Proto.make $ ProtoFields.validatorScoreParametersUpdate .= toProto vsp
    (Updates.UpdateCreatePLT, Updates.CreatePLTUpdatePayload cplt) -> Right . Proto.make $ ProtoFields.createPltUpdate .= toProto cplt
    _ -> Left CEInvalidUpdateResult

-- | The different conversions errors possible in @toBlockItemStatus@ (and the helper to* functions it calls).
data ConversionError
    = -- | An account creation failed.
      CEFailedAccountCreation
    | -- | An account creation transaction occurred but was malformed and could not be converted.
      CEInvalidAccountCreation
    | -- | An update transaction failed.
      CEFailedUpdate
    | -- | An update transaction occurred but was malformed and could not be converted.
      CEInvalidUpdateResult
    | -- | An account transaction occurred but was malformed and could not be converted.
      CEInvalidTransactionResult
    deriving (Eq)

instance Show ConversionError where
    show e = case e of
        CEFailedAccountCreation -> "An account creation failed."
        CEInvalidAccountCreation -> "An account creation transaction occurred but was malformed and could not be converted."
        CEFailedUpdate -> "An update transaction failed."
        CEInvalidUpdateResult -> "An update transaction occurred but was malformed and could not be converted."
        CEInvalidTransactionResult -> "An account transaction occurred but was malformed and could not be converted."

instance ToProto TransactionTime where
    type Output TransactionTime = Proto.TransactionTime
    toProto = mkWord64

instance ToProto ExchangeRate where
    type Output ExchangeRate = Proto.ExchangeRate
    toProto (ExchangeRate r) = Proto.make $ ProtoFields.value .= toProto r

instance ToProto (Ratio.Ratio Word64) where
    type Output (Ratio.Ratio Word64) = Proto.Ratio
    toProto r = Proto.make $ do
        ProtoFields.numerator .= Ratio.numerator r
        ProtoFields.denominator .= Ratio.denominator r

instance ToProto (Parameters.InclusiveRange AmountFraction) where
    type Output (Parameters.InclusiveRange AmountFraction) = Proto.InclusiveRangeAmountFraction
    toProto Parameters.InclusiveRange{..} = Proto.make $ do
        ProtoFields.min .= toProto irMin
        ProtoFields.max .= toProto irMax

instance ToProto Parameters.CapitalBound where
    type Output Parameters.CapitalBound = Proto.CapitalBound
    toProto Parameters.CapitalBound{..} = Proto.make $ ProtoFields.value .= toProto theCapitalBound

instance ToProto Parameters.LeverageFactor where
    type Output Parameters.LeverageFactor = Proto.LeverageFactor
    toProto Parameters.LeverageFactor{..} = Proto.make $ ProtoFields.value .= toProto theLeverageFactor

instance ToProto RewardPeriodLength where
    type Output RewardPeriodLength = Proto.RewardPeriodLength
    toProto rpl = Proto.make $ ProtoFields.value .= mkWord64 rpl

instance ToProto DurationSeconds where
    type Output DurationSeconds = Proto.DurationSeconds
    toProto = mkWord64

instance ToProto ArInfo.ArInfo where
    type Output ArInfo.ArInfo = Proto.ArInfo
    toProto ai = Proto.make $ do
        ProtoFields.identity .= mkWord32 (ArInfo.arIdentity ai)
        ProtoFields.description
            .= Proto.make
                ( do
                    ProtoFields.name .= ArInfo.arName ai
                    ProtoFields.url .= ArInfo.arUrl ai
                    ProtoFields.description .= ArInfo.arDescription ai
                )
        ProtoFields.publicKey . ProtoFields.value .= ArInfo.arPublicKey ai

instance ToProto IpInfo.IpInfo where
    type Output IpInfo.IpInfo = Proto.IpInfo
    toProto ii = Proto.make $ do
        ProtoFields.identity .= mkWord32 (IpInfo.ipIdentity ii)
        ProtoFields.description
            .= Proto.make
                ( do
                    ProtoFields.name .= IpInfo.ipName ii
                    ProtoFields.url .= IpInfo.ipUrl ii
                    ProtoFields.description .= IpInfo.ipDescription ii
                )
        ProtoFields.verifyKey . ProtoFields.value .= IpInfo.ipVerifyKey ii
        ProtoFields.cdiVerifyKey . ProtoFields.value .= IpInfo.ipCdiVerifyKey ii

instance ToProto Updates.Level1Update where
    type Output Updates.Level1Update = Proto.Level1Update
    toProto Updates.Level1KeysLevel1Update{..} = Proto.make $ ProtoFields.level1KeysUpdate .= toProto l1kl1uKeys
    toProto Updates.Level2KeysLevel1Update{..} = Proto.make $ ProtoFields.level2KeysUpdateV0 .= toProto l2kl1uAuthorizations
    toProto Updates.Level2KeysLevel1UpdateV1{..} = Proto.make $ ProtoFields.level2KeysUpdateV1 .= toProto l2kl1uAuthorizationsV1

instance ToProto Updates.RootUpdate where
    type Output Updates.RootUpdate = Proto.RootUpdate
    toProto ru = case ru of
        Updates.RootKeysRootUpdate{..} -> Proto.make $ ProtoFields.rootKeysUpdate .= toProto rkruKeys
        Updates.Level1KeysRootUpdate{..} -> Proto.make $ ProtoFields.level1KeysUpdate .= toProto l1kruKeys
        Updates.Level2KeysRootUpdate{..} -> Proto.make $ ProtoFields.level2KeysUpdateV0 .= toProto l2kruAuthorizations
        Updates.Level2KeysRootUpdateV1{..} -> Proto.make $ ProtoFields.level2KeysUpdateV1 .= toProto l2kruAuthorizationsV1

instance ToProto (Updates.HigherLevelKeys kind) where
    type Output (Updates.HigherLevelKeys kind) = Proto.HigherLevelKeys
    toProto keys = Proto.make $ do
        ProtoFields.keys .= map toProto (Vec.toList $ Updates.hlkKeys keys)
        ProtoFields.threshold .= toProto (Updates.hlkThreshold keys)

instance (Parameters.IsAuthorizationsVersion auv) => ToProto (Updates.Authorizations auv) where
    type Output (Updates.Authorizations auv) = AuthorizationsFamily auv
    toProto auth =
        let
            v0 :: Proto.AuthorizationsV0
            v0 = Proto.make $ do
                ProtoFields.keys .= map toProto (Vec.toList $ Updates.asKeys auth)
                ProtoFields.emergency .= toProto (Updates.asEmergency auth)
                ProtoFields.protocol .= toProto (Updates.asProtocol auth)
                ProtoFields.parameterConsensus .= toProto (Updates.asParamConsensusParameters auth)
                ProtoFields.parameterEuroPerEnergy .= toProto (Updates.asParamEuroPerEnergy auth)
                ProtoFields.parameterMicroCCDPerEuro .= toProto (Updates.asParamMicroGTUPerEuro auth)
                ProtoFields.parameterFoundationAccount .= toProto (Updates.asParamFoundationAccount auth)
                ProtoFields.parameterMintDistribution .= toProto (Updates.asParamMintDistribution auth)
                ProtoFields.parameterTransactionFeeDistribution .= toProto (Updates.asParamTransactionFeeDistribution auth)
                ProtoFields.parameterGasRewards .= toProto (Updates.asParamGASRewards auth)
                ProtoFields.poolParameters .= toProto (Updates.asPoolParameters auth)
                ProtoFields.addAnonymityRevoker .= toProto (Updates.asAddAnonymityRevoker auth)
                ProtoFields.addIdentityProvider .= toProto (Updates.asAddIdentityProvider auth)
        in
            case sing @auv of
                Parameters.SAuthorizationsVersion0 -> v0
                Parameters.SAuthorizationsVersion1 -> Proto.make $ do
                    ProtoFields.v0 .= v0
                    ProtoFields.parameterCooldown .= toProto (Updates.asCooldownParameters auth ^. Parameters.unconditionally)
                    ProtoFields.parameterTime .= toProto (Updates.asTimeParameters auth ^. Parameters.unconditionally)

-- | Defines a type family that is used in the ToProto instance for Updates.Authorizations.
type family AuthorizationsFamily cpv where
    AuthorizationsFamily 'Parameters.AuthorizationsVersion0 = Proto.AuthorizationsV0
    AuthorizationsFamily 'Parameters.AuthorizationsVersion1 = Proto.AuthorizationsV1

instance ToProto Updates.AccessStructure where
    type Output Updates.AccessStructure = Proto.AccessStructure
    toProto Updates.AccessStructure{..} = Proto.make $ do
        ProtoFields.accessPublicKeys .= map toProtoUpdateKeysIndex (Set.toList accessPublicKeys)
        ProtoFields.accessThreshold .= toProto accessThreshold
      where
        toProtoUpdateKeysIndex i = Proto.make $ ProtoFields.value .= fromIntegral i

instance ToProto Updates.UpdatePublicKey where
    type Output Updates.UpdatePublicKey = Proto.UpdatePublicKey
    toProto (VerifyKeyEd25519 key) = Proto.make $ ProtoFields.value .= S.encode key

instance ToProto Updates.UpdateKeysThreshold where
    type Output Updates.UpdateKeysThreshold = Proto.UpdateKeysThreshold
    toProto Updates.UpdateKeysThreshold{..} = Proto.make $ ProtoFields.value .= fromIntegral uktTheThreshold

instance ToProto MintRate where
    type Output MintRate = Proto.MintRate
    toProto MintRate{..} = Proto.make $ do
        ProtoFields.mantissa .= mrMantissa
        ProtoFields.exponent .= fromIntegral mrExponent

instance ToProto Wasm.WasmVersion where
    type Output Wasm.WasmVersion = Proto.ContractVersion
    toProto Wasm.V0 = Proto.V0
    toProto Wasm.V1 = Proto.V1

instance ToProto Wasm.ContractEvent where
    type Output Wasm.ContractEvent = Proto.ContractEvent
    toProto (Wasm.ContractEvent shortBS) = Proto.make $ ProtoFields.value .= BSS.fromShort shortBS

instance ToProto CredentialType where
    type Output CredentialType = Proto.CredentialType
    toProto Initial = Proto.CREDENTIAL_TYPE_INITIAL
    toProto Normal = Proto.CREDENTIAL_TYPE_NORMAL

type BakerAddedEvent = (BakerKeysEvent, Amount, Bool)

instance ToProto BakerAddedEvent where
    type Output BakerAddedEvent = Proto.BakerEvent'BakerAdded
    toProto (keysEvent, stake, restakeEarnings) = Proto.make $ do
        ProtoFields.keysEvent .= toProto keysEvent
        ProtoFields.stake .= toProto stake
        ProtoFields.restakeEarnings .= restakeEarnings

type BakerKeysEvent = (BakerId, AccountAddress, BakerSignVerifyKey, BakerElectionVerifyKey, BakerAggregationVerifyKey)
instance ToProto BakerKeysEvent where
    type Output BakerKeysEvent = Proto.BakerKeysEvent
    toProto (bakerId, addr, signKey, electionKey, aggregationKey) = Proto.make $ do
        ProtoFields.bakerId .= toProto bakerId
        ProtoFields.account .= toProto addr
        ProtoFields.signKey .= toProto signKey
        ProtoFields.electionKey .= toProto electionKey
        ProtoFields.aggregationKey .= toProto aggregationKey

instance ToProto BakerSignVerifyKey where
    type Output BakerSignVerifyKey = Proto.BakerSignatureVerifyKey
    toProto = mkSerialize

instance ToProto BakerElectionVerifyKey where
    type Output BakerElectionVerifyKey = Proto.BakerElectionVerifyKey
    toProto = mkSerialize

instance ToProto BakerAggregationVerifyKey where
    type Output BakerAggregationVerifyKey = Proto.BakerAggregationVerifyKey
    toProto = mkSerialize

instance ToProto Memo where
    type Output Memo = Proto.Memo
    toProto (Memo shortBS) = Proto.make $ ProtoFields.value .= BSS.fromShort shortBS

instance ToProto RegisteredData where
    type Output RegisteredData = Proto.RegisteredData
    toProto (RegisteredData shortBS) = Proto.make $ ProtoFields.value .= BSS.fromShort shortBS

convertContractRelatedEvents ::
    SupplementedEvent -> Either ConversionError Proto.ContractTraceElement
convertContractRelatedEvents event = case event of
    Updated{..} ->
        Right . Proto.make $
            ProtoFields.updated
                .= Proto.make
                    ( do
                        ProtoFields.contractVersion .= toProto euContractVersion
                        ProtoFields.address .= toProto euAddress
                        ProtoFields.instigator .= toProto euInstigator
                        ProtoFields.amount .= toProto euAmount
                        ProtoFields.parameter .= toProto euMessage
                        ProtoFields.receiveName .= toProto euReceiveName
                        ProtoFields.events .= map toProto euEvents
                    )
    Transferred{..} -> do
        sender' <- case etFrom of
            AddressAccount _ -> Left CEInvalidTransactionResult
            AddressContract addr -> Right addr
        receiver <- case etTo of
            AddressAccount addr -> Right addr
            AddressContract _ -> Left CEInvalidTransactionResult
        Right . Proto.make $
            ProtoFields.transferred
                .= Proto.make
                    ( do
                        ProtoFields.sender .= toProto sender'
                        ProtoFields.amount .= toProto etAmount
                        ProtoFields.receiver .= toProto receiver
                    )
    Interrupted{..} ->
        Right . Proto.make $
            ProtoFields.interrupted
                .= Proto.make
                    ( do
                        ProtoFields.address .= toProto iAddress
                        ProtoFields.events .= map toProto iEvents
                    )
    Resumed{..} ->
        Right . Proto.make $
            ProtoFields.resumed
                .= Proto.make
                    ( do
                        ProtoFields.address .= toProto rAddress
                        ProtoFields.success .= rSuccess
                    )
    Upgraded{..} ->
        Right . Proto.make $
            ProtoFields.upgraded
                .= Proto.make
                    ( do
                        ProtoFields.address .= toProto euAddress
                        ProtoFields.from .= toProto euFrom
                        ProtoFields.to .= toProto euTo
                    )
    _ -> Left CEInvalidTransactionResult

-- | Attempt to construct the protobuf type AccounTransactionType.
--  See @toBlockItemStatus@ for more context.
convertAccountTransaction ::
    -- | The transaction type. @Nothing@ means that the transaction was serialized incorrectly.
    Maybe TransactionType ->
    -- | The cost of the transaction.
    Amount ->
    -- | The sender of the transaction.
    AccountAddress ->
    -- | The result of the transaction. If the transaction was rejected, it contains the reject reason.
    --   Otherwise it contains the events.
    SupplementedValidResult ->
    Either ConversionError Proto.AccountTransactionDetails
convertAccountTransaction ty cost sender result = case ty of
    Nothing -> Right . mkNone $ SerializationFailure
    Just ty' -> case result of
        TxReject rejectReason -> Right . mkNone $ rejectReason
        TxSuccess events -> case ty' of
            TTDeployModule ->
                mkSuccess <$> do
                    v <- case events of
                        [ModuleDeployed moduleRef] -> Right $ toProto moduleRef
                        _ -> Left CEInvalidTransactionResult
                    Right . Proto.make $ ProtoFields.moduleDeployed .= v
            TTInitContract ->
                mkSuccess <$> do
                    v <- case events of
                        [ContractInitialized{..}] -> Right $ Proto.make $ do
                            ProtoFields.contractVersion .= toProto ecContractVersion
                            ProtoFields.originRef .= toProto ecRef
                            ProtoFields.address .= toProto ecAddress
                            ProtoFields.amount .= toProto ecAmount
                            ProtoFields.initName .= toProto ecInitName
                            ProtoFields.events .= map toProto ecEvents
                            ProtoFields.parameter .= toProto (uncond ecParameter)
                        _ -> Left CEInvalidTransactionResult
                    Right . Proto.make $ ProtoFields.contractInitialized .= v
            TTUpdate ->
                mkSuccess <$> do
                    v <- mapM convertContractRelatedEvents events
                    Right . Proto.make $ ProtoFields.contractUpdateIssued . ProtoFields.effects .= v
            TTTransfer ->
                mkSuccess <$> do
                    v <- case events of
                        [Transferred{..}] -> case etTo of
                            AddressContract _ -> Left CEInvalidTransactionResult
                            AddressAccount receiver -> Right . Proto.make $ do
                                ProtoFields.amount .= toProto etAmount
                                ProtoFields.receiver .= toProto receiver
                        _ -> Left CEInvalidTransactionResult
                    Right . Proto.make $ ProtoFields.accountTransfer .= v
            TTTransferWithMemo ->
                mkSuccess <$> do
                    v <- case events of
                        [Transferred{..}, TransferMemo{..}] -> case etTo of
                            AddressContract _ -> Left CEInvalidTransactionResult
                            AddressAccount receiver -> Right . Proto.make $ do
                                ProtoFields.amount .= toProto etAmount
                                ProtoFields.receiver .= toProto receiver
                                ProtoFields.memo .= toProto tmMemo
                        _ -> Left CEInvalidTransactionResult
                    Right . Proto.make $ ProtoFields.accountTransfer .= v
            TTAddBaker ->
                mkSuccess <$> do
                    v <- case events of
                        [BakerAdded{..}] -> Right $ toProto ((ebaBakerId, ebaAccount, ebaSignKey, ebaElectionKey, ebaAggregationKey), ebaStake, ebaRestakeEarnings)
                        _ -> Left CEInvalidTransactionResult
                    Right . Proto.make $ ProtoFields.bakerAdded .= v
            TTRemoveBaker ->
                mkSuccess <$> do
                    v <- case events of
                        [BakerRemoved{..}] -> Right $ toProto ebrBakerId
                        _ -> Left CEInvalidTransactionResult
                    Right . Proto.make $ ProtoFields.bakerRemoved .= v
            TTUpdateBakerStake ->
                mkSuccess <$> do
                    v <- case events of
                        [] -> Right Nothing
                        [BakerStakeIncreased{..}] -> Right . Just . Proto.make $ do
                            ProtoFields.bakerId .= toProto ebsiBakerId
                            ProtoFields.newStake .= toProto ebsiNewStake
                            ProtoFields.increased .= True
                        [BakerStakeDecreased{..}] -> Right . Just . Proto.make $ do
                            ProtoFields.bakerId .= toProto ebsiBakerId
                            ProtoFields.newStake .= toProto ebsiNewStake
                            ProtoFields.increased .= False
                        _ -> Left CEInvalidTransactionResult
                    case v of
                        Nothing -> Right . Proto.make $ ProtoFields.bakerStakeUpdated .= Proto.defMessage
                        Just val -> Right . Proto.make $ ProtoFields.bakerStakeUpdated . ProtoFields.update .= val
            TTUpdateBakerRestakeEarnings ->
                mkSuccess <$> do
                    v <- case events of
                        [BakerSetRestakeEarnings{..}] -> Right $ Proto.make $ do
                            ProtoFields.bakerId .= toProto ebsreBakerId
                            ProtoFields.restakeEarnings .= ebsreRestakeEarnings
                        _ -> Left CEInvalidTransactionResult
                    Right . Proto.make $ ProtoFields.bakerRestakeEarningsUpdated .= v
            TTUpdateBakerKeys ->
                mkSuccess <$> do
                    v <- case events of
                        [BakerKeysUpdated{..}] -> Right $ toProto (ebkuBakerId, ebkuAccount, ebkuSignKey, ebkuElectionKey, ebkuAggregationKey)
                        _ -> Left CEInvalidTransactionResult
                    Right . Proto.make $ ProtoFields.bakerKeysUpdated .= v
            TTEncryptedAmountTransfer ->
                mkSuccess <$> do
                    v <- case events of
                        [EncryptedAmountsRemoved{..}, NewEncryptedAmount{..}] ->
                            let
                                removed = Proto.make $ do
                                    ProtoFields.account .= toProto earAccount
                                    ProtoFields.newAmount .= toProto earNewAmount
                                    ProtoFields.inputAmount .= toProto earInputAmount
                                    ProtoFields.upToIndex .= theAggIndex earUpToIndex
                                added = Proto.make $ do
                                    ProtoFields.receiver .= toProto neaAccount
                                    ProtoFields.newIndex .= theIndex neaNewIndex
                                    ProtoFields.encryptedAmount .= toProto neaEncryptedAmount
                            in
                                Right . Proto.make $ do
                                    ProtoFields.removed .= removed
                                    ProtoFields.added .= added
                        _ -> Left CEInvalidTransactionResult
                    Right . Proto.make $ ProtoFields.encryptedAmountTransferred .= v
            TTEncryptedAmountTransferWithMemo ->
                mkSuccess <$> do
                    v <- case events of
                        [EncryptedAmountsRemoved{..}, NewEncryptedAmount{..}, TransferMemo{..}] ->
                            let
                                removed = Proto.make $ do
                                    ProtoFields.account .= toProto earAccount
                                    ProtoFields.newAmount .= toProto earNewAmount
                                    ProtoFields.inputAmount .= toProto earInputAmount
                                    ProtoFields.upToIndex .= theAggIndex earUpToIndex
                                added = Proto.make $ do
                                    ProtoFields.receiver .= toProto neaAccount
                                    ProtoFields.newIndex .= theIndex neaNewIndex
                                    ProtoFields.encryptedAmount .= toProto neaEncryptedAmount
                            in
                                Right . Proto.make $ do
                                    ProtoFields.removed .= removed
                                    ProtoFields.added .= added
                                    ProtoFields.memo .= toProto tmMemo
                        _ -> Left CEInvalidTransactionResult
                    Right . Proto.make $ ProtoFields.encryptedAmountTransferred .= v
            TTTransferToEncrypted ->
                mkSuccess <$> do
                    v <- case events of
                        [EncryptedSelfAmountAdded{..}] -> Right . Proto.make $ do
                            ProtoFields.account .= toProto eaaAccount
                            ProtoFields.newAmount .= toProto eaaNewAmount
                            ProtoFields.amount .= toProto eaaAmount
                        _ -> Left CEInvalidTransactionResult
                    Right . Proto.make $ ProtoFields.transferredToEncrypted .= v
            TTTransferToPublic ->
                mkSuccess <$> do
                    v <- case events of
                        [EncryptedAmountsRemoved{..}, AmountAddedByDecryption{..}] ->
                            let
                                removed = Proto.make $ do
                                    ProtoFields.account .= toProto earAccount
                                    ProtoFields.newAmount .= toProto earNewAmount
                                    ProtoFields.inputAmount .= toProto earInputAmount
                                    ProtoFields.upToIndex .= theAggIndex earUpToIndex
                            in
                                Right . Proto.make $ do
                                    ProtoFields.removed .= removed
                                    ProtoFields.amount .= toProto aabdAmount
                        _ -> Left CEInvalidTransactionResult
                    Right . Proto.make $ ProtoFields.transferredToPublic .= v
            TTTransferWithSchedule ->
                mkSuccess <$> do
                    v <- case events of
                        [TransferredWithSchedule{..}] -> Right . Proto.make $ do
                            ProtoFields.receiver .= toProto etwsTo
                            ProtoFields.amount .= map toProto etwsAmount
                        _ -> Left CEInvalidTransactionResult
                    Right . Proto.make $ ProtoFields.transferredWithSchedule .= v
            TTTransferWithScheduleAndMemo ->
                mkSuccess <$> do
                    v <- case events of
                        [TransferredWithSchedule{..}, TransferMemo{..}] -> Right . Proto.make $ do
                            ProtoFields.receiver .= toProto etwsTo
                            ProtoFields.amount .= map toProto etwsAmount
                            ProtoFields.memo .= toProto tmMemo
                        _ -> Left CEInvalidTransactionResult
                    Right . Proto.make $ ProtoFields.transferredWithSchedule .= v
            TTUpdateCredentialKeys ->
                mkSuccess <$> do
                    v <- case events of
                        [CredentialKeysUpdated{..}] -> Right $ toProto ckuCredId
                        _ -> Left CEInvalidTransactionResult
                    Right . Proto.make $ ProtoFields.credentialKeysUpdated .= v
            TTUpdateCredentials ->
                mkSuccess <$> do
                    v <- case events of
                        [CredentialsUpdated{..}] -> Right . Proto.make $ do
                            ProtoFields.newCredIds .= map toProto cuNewCredIds
                            ProtoFields.removedCredIds .= map toProto cuRemovedCredIds
                            ProtoFields.newThreshold .= toProto cuNewThreshold
                        _ -> Left CEInvalidTransactionResult
                    Right . Proto.make $ ProtoFields.credentialsUpdated .= v
            TTRegisterData ->
                mkSuccess <$> do
                    v <- case events of
                        [DataRegistered{..}] -> Right $ toProto drData
                        _ -> Left CEInvalidTransactionResult
                    Right . Proto.make $ ProtoFields.dataRegistered .= v
            TTConfigureBaker ->
                mkSuccess <$> do
                    let toBakerEvent = \case
                            BakerAdded{..} ->
                                Right . Proto.make $
                                    ProtoFields.bakerAdded
                                        .= toProto ((ebaBakerId, ebaAccount, ebaSignKey, ebaElectionKey, ebaAggregationKey), ebaStake, ebaRestakeEarnings)
                            BakerRemoved{..} -> Right . Proto.make $ ProtoFields.bakerRemoved .= toProto ebrBakerId
                            BakerStakeIncreased{..} ->
                                Right . Proto.make $
                                    ProtoFields.bakerStakeIncreased
                                        .= Proto.make
                                            ( do
                                                ProtoFields.bakerId .= toProto ebsiBakerId
                                                ProtoFields.newStake .= toProto ebsiNewStake
                                            )
                            BakerStakeDecreased{..} ->
                                Right . Proto.make $
                                    ProtoFields.bakerStakeDecreased
                                        .= Proto.make
                                            ( do
                                                ProtoFields.bakerId .= toProto ebsiBakerId
                                                ProtoFields.newStake .= toProto ebsiNewStake
                                            )
                            BakerSetRestakeEarnings{..} ->
                                Right . Proto.make $
                                    ProtoFields.bakerRestakeEarningsUpdated
                                        .= Proto.make
                                            ( do
                                                ProtoFields.bakerId .= toProto ebsreBakerId
                                                ProtoFields.restakeEarnings .= ebsreRestakeEarnings
                                            )
                            BakerKeysUpdated{..} -> Right . Proto.make $ ProtoFields.bakerKeysUpdated .= toProto (ebkuBakerId, ebkuAccount, ebkuSignKey, ebkuElectionKey, ebkuAggregationKey)
                            BakerSetOpenStatus{..} ->
                                Right . Proto.make $
                                    ProtoFields.bakerSetOpenStatus
                                        .= Proto.make
                                            ( do
                                                ProtoFields.bakerId .= toProto ebsosBakerId
                                                ProtoFields.openStatus .= toProto ebsosOpenStatus
                                            )
                            BakerSetMetadataURL{..} ->
                                Right . Proto.make $
                                    ProtoFields.bakerSetMetadataUrl
                                        .= Proto.make
                                            ( do
                                                ProtoFields.bakerId .= toProto ebsmuBakerId
                                                ProtoFields.url .= toProto ebsmuMetadataURL
                                            )
                            BakerSetTransactionFeeCommission{..} ->
                                Right . Proto.make $
                                    ProtoFields.bakerSetTransactionFeeCommission
                                        .= Proto.make
                                            ( do
                                                ProtoFields.bakerId .= toProto ebstfcBakerId
                                                ProtoFields.transactionFeeCommission .= toProto ebstfcTransactionFeeCommission
                                            )
                            BakerSetBakingRewardCommission{..} ->
                                Right . Proto.make $
                                    ProtoFields.bakerSetBakingRewardCommission
                                        .= Proto.make
                                            ( do
                                                ProtoFields.bakerId .= toProto ebsbrcBakerId
                                                ProtoFields.bakingRewardCommission .= toProto ebsbrcBakingRewardCommission
                                            )
                            BakerSetFinalizationRewardCommission{..} ->
                                Right . Proto.make $
                                    ProtoFields.bakerSetFinalizationRewardCommission
                                        .= Proto.make
                                            ( do
                                                ProtoFields.bakerId .= toProto ebsfrcBakerId
                                                ProtoFields.finalizationRewardCommission .= toProto ebsfrcFinalizationRewardCommission
                                            )
                            DelegationRemoved{..} ->
                                Right . Proto.make $
                                    ProtoFields.delegationRemoved
                                        .= Proto.make
                                            (ProtoFields.delegatorId .= toProto edrDelegatorId)
                            BakerSuspended{..} ->
                                Right . Proto.make $
                                    ProtoFields.bakerSuspended
                                        .= Proto.make (ProtoFields.bakerId .= toProto ebsBakerId)
                            BakerResumed{..} ->
                                Right . Proto.make $
                                    ProtoFields.bakerResumed
                                        .= Proto.make (ProtoFields.bakerId .= toProto ebrBakerId)
                            _ -> Left CEInvalidTransactionResult
                    v <- mapM toBakerEvent events
                    Right . Proto.make $ ProtoFields.bakerConfigured . ProtoFields.events .= v
            TTConfigureDelegation ->
                mkSuccess <$> do
                    let toDelegationEvent = \case
                            DelegationStakeIncreased{..} ->
                                Right . Proto.make $
                                    ProtoFields.delegationStakeIncreased
                                        .= Proto.make
                                            ( do
                                                ProtoFields.delegatorId .= toProto edsiDelegatorId
                                                ProtoFields.newStake .= toProto edsiNewStake
                                            )
                            DelegationStakeDecreased{..} ->
                                Right . Proto.make $
                                    ProtoFields.delegationStakeDecreased
                                        .= Proto.make
                                            ( do
                                                ProtoFields.delegatorId .= toProto edsdDelegatorId
                                                ProtoFields.newStake .= toProto edsdNewStake
                                            )
                            DelegationSetRestakeEarnings{..} ->
                                Right . Proto.make $
                                    ProtoFields.delegationSetRestakeEarnings
                                        .= Proto.make
                                            ( do
                                                ProtoFields.delegatorId .= toProto edsreDelegatorId
                                                ProtoFields.restakeEarnings .= edsreRestakeEarnings
                                            )
                            DelegationSetDelegationTarget{..} ->
                                Right . Proto.make $
                                    ProtoFields.delegationSetDelegationTarget
                                        .= Proto.make
                                            ( do
                                                ProtoFields.delegatorId .= toProto edsdtDelegatorId
                                                ProtoFields.delegationTarget .= toProto edsdtDelegationTarget
                                            )
                            DelegationAdded{..} -> Right . Proto.make $ ProtoFields.delegationAdded .= toProto edaDelegatorId
                            DelegationRemoved{..} -> Right . Proto.make $ ProtoFields.delegationRemoved .= toProto edrDelegatorId
                            BakerRemoved{..} ->
                                Right . Proto.make $
                                    ProtoFields.bakerRemoved
                                        .= Proto.make (ProtoFields.bakerId .= toProto ebrBakerId)
                            _ -> Left CEInvalidTransactionResult
                    v <- mapM toDelegationEvent events
                    Right . Proto.make $ ProtoFields.delegationConfigured . ProtoFields.events .= v
            TTTokenHolder ->
                mkSuccess <$> do
                    let eventToProto :: Event' s -> Either ConversionError Proto.TokenHolderEvent
                        eventToProto = \case
                            TokenModuleEvent (TokenEvent{..}) -> Right . Proto.make $ do
                                PLTFields.tokenSymbol .= toProto _teSymbol
                                PLTFields.type' .= toProto _teType
                                PLTFields.details .= toProto _teDetails
                            _ -> Left CEInvalidTransactionResult
                    v <- mapM eventToProto events
                    Right . Proto.make $ ProtoFields.tokenHolderEffect . ProtoFields.events .= v
            TTTokenGovernance ->
                mkSuccess <$> do
                    let eventToProto :: Event' s -> Either ConversionError Proto.TokenGovernanceEvent
                        eventToProto = \case
                            TokenModuleEvent (TokenEvent{..}) -> Right . Proto.make $ do
                                PLTFields.tokenSymbol .= toProto _teSymbol
                                PLTFields.type' .= toProto _teType
                                PLTFields.details .= toProto _teDetails
                            _ -> Left CEInvalidTransactionResult
                    v <- mapM eventToProto events
                    Right . Proto.make $ ProtoFields.tokenGovernanceEffect . ProtoFields.events .= v
  where
    mkSuccess :: Proto.AccountTransactionEffects -> Proto.AccountTransactionDetails
    mkSuccess effects = Proto.make $ do
        ProtoFields.cost .= toProto cost
        ProtoFields.sender .= toProto sender
        ProtoFields.effects .= effects

    mkNone :: RejectReason -> Proto.AccountTransactionDetails
    mkNone rr = Proto.make $ do
        ProtoFields.cost .= toProto cost
        ProtoFields.sender .= toProto sender
        ProtoFields.effects
            . ProtoFields.none
            .= ( Proto.make $ do
                    ProtoFields.rejectReason .= toProto rr
                    case ty of
                        Nothing -> return ()
                        Just ty' -> ProtoFields.transactionType .= toProto ty'
               )

instance ToProto TokenParameter where
    type Output TokenParameter = Proto.CBor
    toProto (TokenParameter parameter) = Proto.make $ PLTFields.value .= BSS.fromShort parameter

instance ToProto TokenEventDetails where
    type Output TokenEventDetails = Proto.CBor
    toProto (TokenEventDetails details) = Proto.make $ PLTFields.value .= BSS.fromShort details

instance ToProto TokenEventType where
    type Output TokenEventType = Text
    toProto (TokenEventType eventType) = decodeUtf8 (BSS.fromShort eventType)

instance ToProto Address where
    type Output Address = Proto.Address
    toProto (AddressAccount addr) = Proto.make $ ProtoFields.account .= toProto addr
    toProto (AddressContract addr) = Proto.make $ ProtoFields.contract .= toProto addr

instance ToProto Updates.UpdateType where
    type Output Updates.UpdateType = Proto.UpdateType
    toProto Updates.UpdateProtocol = Proto.UPDATE_PROTOCOL
    toProto Updates.UpdateElectionDifficulty = Proto.UPDATE_ELECTION_DIFFICULTY
    toProto Updates.UpdateEuroPerEnergy = Proto.UPDATE_EURO_PER_ENERGY
    toProto Updates.UpdateMicroGTUPerEuro = Proto.UPDATE_MICRO_CCD_PER_EURO
    toProto Updates.UpdateFoundationAccount = Proto.UPDATE_FOUNDATION_ACCOUNT
    toProto Updates.UpdateMintDistribution = Proto.UPDATE_MINT_DISTRIBUTION
    toProto Updates.UpdateTransactionFeeDistribution = Proto.UPDATE_TRANSACTION_FEE_DISTRIBUTION
    toProto Updates.UpdateGASRewards = Proto.UPDATE_GAS_REWARDS
    toProto Updates.UpdatePoolParameters = Proto.UPDATE_POOL_PARAMETERS
    toProto Updates.UpdateAddAnonymityRevoker = Proto.ADD_ANONYMITY_REVOKER
    toProto Updates.UpdateAddIdentityProvider = Proto.ADD_IDENTITY_PROVIDER
    toProto Updates.UpdateRootKeys = Proto.UPDATE_ROOT_KEYS
    toProto Updates.UpdateLevel1Keys = Proto.UPDATE_LEVEL1_KEYS
    toProto Updates.UpdateLevel2Keys = Proto.UPDATE_LEVEL2_KEYS
    toProto Updates.UpdateCooldownParameters = Proto.UPDATE_COOLDOWN_PARAMETERS
    toProto Updates.UpdateTimeParameters = Proto.UPDATE_TIME_PARAMETERS
    toProto Updates.UpdateTimeoutParameters = Proto.UPDATE_TIMEOUT_PARAMETERS
    toProto Updates.UpdateMinBlockTime = Proto.UPDATE_MIN_BLOCK_TIME
    toProto Updates.UpdateBlockEnergyLimit = Proto.UPDATE_BLOCK_ENERGY_LIMIT
    toProto Updates.UpdateFinalizationCommitteeParameters = Proto.UPDATE_FINALIZATION_COMMITTEE_PARAMETERS
    toProto Updates.UpdateValidatorScoreParameters = Proto.UPDATE_VALIDATOR_SCORE_PARAMETERS
    toProto Updates.UpdateCreatePLT = Proto.UPDATE_CREATE_PLT

instance ToProto TransactionType where
    type Output TransactionType = Proto.TransactionType
    toProto TTDeployModule = Proto.DEPLOY_MODULE
    toProto TTInitContract = Proto.INIT_CONTRACT
    toProto TTUpdate = Proto.UPDATE
    toProto TTTransfer = Proto.TRANSFER
    toProto TTAddBaker = Proto.ADD_BAKER
    toProto TTRemoveBaker = Proto.REMOVE_BAKER
    toProto TTUpdateBakerStake = Proto.UPDATE_BAKER_STAKE
    toProto TTUpdateBakerRestakeEarnings = Proto.UPDATE_BAKER_RESTAKE_EARNINGS
    toProto TTUpdateBakerKeys = Proto.UPDATE_BAKER_KEYS
    toProto TTUpdateCredentialKeys = Proto.UPDATE_CREDENTIAL_KEYS
    toProto TTEncryptedAmountTransfer = Proto.ENCRYPTED_AMOUNT_TRANSFER
    toProto TTTransferToEncrypted = Proto.TRANSFER_TO_ENCRYPTED
    toProto TTTransferToPublic = Proto.TRANSFER_TO_PUBLIC
    toProto TTTransferWithSchedule = Proto.TRANSFER_WITH_SCHEDULE
    toProto TTUpdateCredentials = Proto.UPDATE_CREDENTIALS
    toProto TTRegisterData = Proto.REGISTER_DATA
    toProto TTTransferWithMemo = Proto.TRANSFER_WITH_MEMO
    toProto TTEncryptedAmountTransferWithMemo = Proto.ENCRYPTED_AMOUNT_TRANSFER_WITH_MEMO
    toProto TTTransferWithScheduleAndMemo = Proto.TRANSFER_WITH_SCHEDULE_AND_MEMO
    toProto TTConfigureBaker = Proto.CONFIGURE_BAKER
    toProto TTConfigureDelegation = Proto.CONFIGURE_DELEGATION
    toProto TTTokenHolder = Proto.TOKEN_HOLDER
    toProto TTTokenGovernance = Proto.TOKEN_GOVERNANCE

instance ToProto Energy where
    type Output Energy = Proto.Energy
    toProto = mkWord64

instance ToProto InvokeContract.InvokeContractResult where
    -- Since this is a conversion that may fail we use Either in the output type
    -- here so that we can forward errors, which is not in-line with other
    -- instances which are not fallible. The caller is meant to catch the error.
    type Output InvokeContract.InvokeContractResult = Either ConversionError Proto.InvokeInstanceResponse
    toProto InvokeContract.Failure{..} =
        return $
            Proto.make $
                ProtoFields.failure
                    .= Proto.make
                        ( do
                            ProtoFields.maybe'returnValue .= rcrReturnValue
                            ProtoFields.usedEnergy .= toProto rcrUsedEnergy
                            ProtoFields.reason .= toProto rcrReason
                        )
    toProto InvokeContract.Success{..} = do
        effects <- mapM convertContractRelatedEvents rcrEvents
        return $
            Proto.make $
                ProtoFields.success
                    .= Proto.make
                        ( do
                            ProtoFields.maybe'returnValue .= rcrReturnValue
                            ProtoFields.usedEnergy .= toProto rcrUsedEnergy
                            ProtoFields.effects .= effects
                        )

instance ToProto Slot where
    type Output Slot = Proto.Slot
    toProto = mkWord64

instance ToProto StateHash where
    type Output StateHash = Proto.StateHash
    toProto = mkSerialize

instance ToProto QueryTypes.BlockInfo where
    type Output QueryTypes.BlockInfo = Proto.BlockInfo
    toProto QueryTypes.BlockInfo{..} = Proto.make $ do
        ProtoFields.hash .= toProto biBlockHash
        ProtoFields.height .= toProto biBlockHeight
        ProtoFields.parentBlock .= toProto biBlockParent
        ProtoFields.lastFinalizedBlock .= toProto biBlockLastFinalized
        ProtoFields.genesisIndex .= toProto biGenesisIndex
        ProtoFields.eraBlockHeight .= toProto biEraBlockHeight
        ProtoFields.receiveTime .= toProto biBlockReceiveTime
        ProtoFields.arriveTime .= toProto biBlockArriveTime
        ProtoFields.maybe'slotNumber .= fmap toProto biBlockSlot
        ProtoFields.slotTime .= toProto biBlockSlotTime
        ProtoFields.maybe'baker .= fmap toProto biBlockBaker
        ProtoFields.finalized .= biFinalized
        ProtoFields.transactionCount .= fromIntegral biTransactionCount
        ProtoFields.transactionsEnergyCost .= toProto biTransactionEnergyCost
        ProtoFields.transactionsSize .= fromIntegral biTransactionsSize
        ProtoFields.stateHash .= toProto biBlockStateHash
        ProtoFields.protocolVersion .= toProto biProtocolVersion
        ProtoFields.maybe'round .= fmap toProto biRound
        ProtoFields.maybe'epoch .= fmap toProto biEpoch

instance ToProto QueryTypes.BakerPoolStatus where
    type Output QueryTypes.BakerPoolStatus = Proto.PoolInfoResponse
    toProto QueryTypes.BakerPoolStatus{..} = Proto.make $ do
        ProtoFields.baker .= toProto psBakerId
        ProtoFields.address .= toProto psBakerAddress
        forM_ psActiveStatus $ \ActiveBakerPoolStatus{..} -> do
            ProtoFields.equityCapital .= toProto abpsBakerEquityCapital
            ProtoFields.delegatedCapital .= toProto abpsDelegatedCapital
            ProtoFields.delegatedCapitalCap .= toProto abpsDelegatedCapitalCap
            ProtoFields.poolInfo .= toProto abpsPoolInfo
            ProtoFields.maybe'equityPendingChange .= toProto abpsBakerStakePendingChange
            ProtoFields.maybe'isSuspended .= abpsIsSuspended
        ProtoFields.maybe'currentPaydayInfo .= fmap toProto psCurrentPaydayStatus
        ProtoFields.allPoolTotalCapital .= toProto psAllPoolTotalCapital

instance ToProto QueryTypes.PassiveDelegationStatus where
    type Output QueryTypes.PassiveDelegationStatus = Proto.PassiveDelegationInfo
    toProto QueryTypes.PassiveDelegationStatus{..} = Proto.make $ do
        ProtoFields.delegatedCapital .= toProto pdsDelegatedCapital
        ProtoFields.commissionRates .= toProto pdsCommissionRates
        ProtoFields.currentPaydayTransactionFeesEarned .= toProto pdsCurrentPaydayTransactionFeesEarned
        ProtoFields.currentPaydayDelegatedCapital .= toProto pdsCurrentPaydayDelegatedCapital
        ProtoFields.allPoolTotalCapital .= toProto pdsAllPoolTotalCapital

instance ToProto QueryTypes.PoolPendingChange where
    type Output QueryTypes.PoolPendingChange = Maybe Proto.PoolPendingChange
    toProto QueryTypes.PPCNoChange = Nothing
    toProto QueryTypes.PPCReduceBakerCapital{..} =
        Just $
            Proto.make $
                ProtoFields.reduce
                    .= Proto.make
                        ( do
                            ProtoFields.reducedEquityCapital .= toProto ppcBakerEquityCapital
                            ProtoFields.effectiveTime .= toProto ppcEffectiveTime
                        )
    toProto QueryTypes.PPCRemovePool{..} =
        Just $
            Proto.make $
                ProtoFields.remove
                    .= Proto.make
                        (ProtoFields.effectiveTime .= toProto ppcEffectiveTime)

instance ToProto QueryTypes.CurrentPaydayBakerPoolStatus where
    type Output QueryTypes.CurrentPaydayBakerPoolStatus = Proto.PoolCurrentPaydayInfo
    toProto QueryTypes.CurrentPaydayBakerPoolStatus{..} = Proto.make $ do
        ProtoFields.blocksBaked .= fromIntegral bpsBlocksBaked
        ProtoFields.finalizationLive .= bpsFinalizationLive
        ProtoFields.transactionFeesEarned .= toProto bpsTransactionFeesEarned
        ProtoFields.effectiveStake .= toProto bpsEffectiveStake
        ProtoFields.lotteryPower .= bpsLotteryPower
        ProtoFields.bakerEquityCapital .= toProto bpsBakerEquityCapital
        ProtoFields.delegatedCapital .= toProto bpsDelegatedCapital
        ProtoFields.commissionRates .= toProto bpsCommissionRates
        ProtoFields.maybe'isPrimedForSuspension .= bpsIsPrimedForSuspension
        ProtoFields.maybe'missedRounds .= bpsMissedRounds

instance ToProto QueryTypes.RewardStatus where
    type Output QueryTypes.RewardStatus = Proto.TokenomicsInfo
    toProto QueryTypes.RewardStatusV0{..} =
        Proto.make
            ( ProtoFields.v0
                .= Proto.make
                    ( do
                        ProtoFields.totalAmount .= toProto rsTotalAmount
                        ProtoFields.totalEncryptedAmount .= toProto rsTotalEncryptedAmount
                        ProtoFields.bakingRewardAccount .= toProto rsBakingRewardAccount
                        ProtoFields.finalizationRewardAccount .= toProto rsFinalizationRewardAccount
                        ProtoFields.gasAccount .= toProto rsGasAccount
                        ProtoFields.protocolVersion .= toProto rsProtocolVersion
                    )
            )
    toProto QueryTypes.RewardStatusV1{..} =
        Proto.make
            ( ProtoFields.v1
                .= Proto.make
                    ( do
                        ProtoFields.totalAmount .= toProto rsTotalAmount
                        ProtoFields.totalEncryptedAmount .= toProto rsTotalEncryptedAmount
                        ProtoFields.bakingRewardAccount .= toProto rsBakingRewardAccount
                        ProtoFields.finalizationRewardAccount .= toProto rsFinalizationRewardAccount
                        ProtoFields.gasAccount .= toProto rsGasAccount
                        ProtoFields.foundationTransactionRewards .= toProto rsFoundationTransactionRewards
                        ProtoFields.nextPaydayTime .= toProto rsNextPaydayTime
                        ProtoFields.nextPaydayMintRate .= toProto rsNextPaydayMintRate
                        ProtoFields.totalStakedCapital .= toProto rsTotalStakedCapital
                        ProtoFields.protocolVersion .= toProto rsProtocolVersion
                    )
            )

instance ToProto DelegatorInfo where
    type Output DelegatorInfo = Proto.DelegatorInfo
    toProto DelegatorInfo{..} = Proto.make $ do
        ProtoFields.account .= toProto pdiAccount
        ProtoFields.stake .= toProto pdiStake
        ProtoFields.maybe'pendingChange .= toProto pdiPendingChanges

instance ToProto DelegatorRewardPeriodInfo where
    type Output DelegatorRewardPeriodInfo = Proto.DelegatorRewardPeriodInfo
    toProto DelegatorRewardPeriodInfo{..} = Proto.make $ do
        ProtoFields.account .= toProto pdrpiAccount
        ProtoFields.stake .= toProto pdrpiStake

instance ToProto QueryTypes.Branch where
    type Output QueryTypes.Branch = Proto.Branch
    toProto QueryTypes.Branch{..} = Proto.make $ do
        ProtoFields.blockHash .= toProto branchBlockHash
        ProtoFields.children .= fmap toProto branchChildren

instance ToProto QueryTypes.BlockBirkParameters where
    type Output QueryTypes.BlockBirkParameters = Maybe Proto.ElectionInfo
    toProto QueryTypes.BlockBirkParameters{..} = do
        bakerElectionInfo <- mapM toProto (Vec.toList bbpBakers)
        Just $ Proto.make $ do
            ProtoFields.maybe'electionDifficulty .= fmap toProto bbpElectionDifficulty
            ProtoFields.electionNonce .= mkSerialize bbpElectionNonce
            ProtoFields.bakerElectionInfo .= bakerElectionInfo

instance ToProto QueryTypes.BakerSummary where
    type Output QueryTypes.BakerSummary = Maybe Proto.ElectionInfo'Baker
    toProto QueryTypes.BakerSummary{..} = do
        bakerAccount <- bsBakerAccount
        Just $ Proto.make $ do
            ProtoFields.baker .= toProto bsBakerId
            ProtoFields.account .= toProto bakerAccount
            ProtoFields.lotteryPower .= bsBakerLotteryPower

instance ToProto Transactions.TransactionHeader where
    type Output Transactions.TransactionHeader = Proto.AccountTransactionHeader

    toProto Transactions.TransactionHeader{..} = Proto.make $ do
        ProtoFields.sender .= toProto thSender
        ProtoFields.sequenceNumber .= toProto thNonce
        ProtoFields.energyAmount .= toProto thEnergyAmount
        ProtoFields.expiry .= toProto thExpiry

instance ToProto Signature where
    type Output Signature = Proto.Signature

    toProto (Signature bss) = Proto.make $ do
        ProtoFields.value .= BSS.fromShort bss

instance ToProto Transactions.TransactionSignature where
    type Output Transactions.TransactionSignature = Proto.AccountTransactionSignature

    toProto Transactions.TransactionSignature{..} = Proto.make $ do
        ProtoFields.signatures .= (Map.fromAscList . map mk . Map.toAscList $ tsSignatures)
      where
        mk (k, s) = (fromIntegral k, mkSingleSig s)
        mkSingleSig sigs = Proto.make $ do
            ProtoFields.signatures .= (Map.fromAscList . map (\(ki, sig) -> (fromIntegral ki, toProto sig)) . Map.toAscList $ sigs)

instance ToProto Transactions.AccountTransaction where
    type Output Transactions.AccountTransaction = Proto.AccountTransaction

    toProto Transactions.AccountTransaction{..} = Proto.make $ do
        ProtoFields.signature .= toProto atrSignature
        ProtoFields.header .= toProto atrHeader
        ProtoFields.payload
            .= Proto.make
                ( ProtoFields.rawPayload .= BSS.fromShort (_spayload atrPayload)
                )

instance ToProto Transactions.AccountCreation where
    type Output Transactions.AccountCreation = Proto.CredentialDeployment

    toProto Transactions.AccountCreation{..} = Proto.make $ do
        ProtoFields.messageExpiry .= toProto messageExpiry
        ProtoFields.rawPayload .= S.encode credential

instance ToProto Updates.UpdateInstructionSignatures where
    type Output Updates.UpdateInstructionSignatures = Proto.SignatureMap

    toProto Updates.UpdateInstructionSignatures{..} = Proto.make $ do
        ProtoFields.signatures .= (Map.fromAscList . map mk . Map.toAscList $ signatures)
      where
        mk (k, s) = (fromIntegral k, toProto s)

instance ToProto Updates.UpdateHeader where
    type Output Updates.UpdateHeader = Proto.UpdateInstructionHeader

    toProto Updates.UpdateHeader{..} = Proto.make $ do
        -- since UpdateSequenceNumber is an alias for Nonce in Haskell, but not in
        -- the .proto file we have to use mkWord64 or similar, and not toProto since
        -- that one is defined for the Nonce.
        ProtoFields.sequenceNumber .= mkWord64 updateSeqNumber
        ProtoFields.effectiveTime .= toProto updateEffectiveTime
        ProtoFields.timeout .= toProto updateTimeout

instance ToProto Updates.UpdateInstruction where
    type Output Updates.UpdateInstruction = Proto.UpdateInstruction

    toProto Updates.UpdateInstruction{..} = Proto.make $ do
        ProtoFields.signatures .= toProto uiSignatures
        ProtoFields.header .= toProto uiHeader
        ProtoFields.payload
            .= Proto.make
                ( ProtoFields.rawPayload .= S.runPut (Updates.putUpdatePayload uiPayload)
                )

instance ToProto Transactions.BlockItem where
    type Output Transactions.BlockItem = Proto.BlockItem
    toProto bi = Proto.make $ do
        ProtoFields.hash .= toProto (Transactions.wmdHash bi)
        case Transactions.wmdData bi of
            Transactions.NormalTransaction accTx -> do
                ProtoFields.accountTransaction .= toProto accTx
            Transactions.CredentialDeployment cred ->
                ProtoFields.credentialDeployment .= toProto cred
            Transactions.ChainUpdate cu ->
                ProtoFields.updateInstruction .= toProto cu

instance ToProto TxTypes.AccountAmounts where
    type Output TxTypes.AccountAmounts = Proto.BlockSpecialEvent'AccountAmounts
    toProto TxTypes.AccountAmounts{..} = Proto.make $ ProtoFields.entries .= fmap mapper (Map.toList accountAmounts)
      where
        mapper (account, amount) = Proto.make $ do
            ProtoFields.account .= toProto account
            ProtoFields.amount .= toProto amount

instance ToProto TxTypes.SpecialTransactionOutcome where
    type Output TxTypes.SpecialTransactionOutcome = Proto.BlockSpecialEvent
    toProto TxTypes.BakingRewards{..} =
        Proto.make $
            ProtoFields.bakingRewards
                .= Proto.make
                    ( do
                        ProtoFields.bakerRewards .= toProto stoBakerRewards
                        ProtoFields.remainder .= toProto stoRemainder
                    )
    toProto TxTypes.Mint{..} =
        Proto.make $
            ProtoFields.mint
                .= Proto.make
                    ( do
                        ProtoFields.mintBakingReward .= toProto stoMintBakingReward
                        ProtoFields.mintFinalizationReward .= toProto stoMintFinalizationReward
                        ProtoFields.mintPlatformDevelopmentCharge .= toProto stoMintPlatformDevelopmentCharge
                        ProtoFields.foundationAccount .= toProto stoFoundationAccount
                    )
    toProto TxTypes.FinalizationRewards{..} =
        Proto.make $
            ProtoFields.finalizationRewards
                .= Proto.make
                    ( do
                        ProtoFields.finalizationRewards .= toProto stoFinalizationRewards
                        ProtoFields.remainder .= toProto stoRemainder
                    )
    toProto TxTypes.BlockReward{..} =
        Proto.make $
            ProtoFields.blockReward
                .= Proto.make
                    ( do
                        ProtoFields.transactionFees .= toProto stoTransactionFees
                        ProtoFields.oldGasAccount .= toProto stoOldGASAccount
                        ProtoFields.newGasAccount .= toProto stoNewGASAccount
                        ProtoFields.bakerReward .= toProto stoBakerReward
                        ProtoFields.foundationCharge .= toProto stoFoundationCharge
                        ProtoFields.baker .= toProto stoBaker
                        ProtoFields.foundationAccount .= toProto stoFoundationAccount
                    )
    toProto TxTypes.PaydayFoundationReward{..} =
        Proto.make $
            ProtoFields.paydayFoundationReward
                .= Proto.make
                    ( do
                        ProtoFields.foundationAccount .= toProto stoFoundationAccount
                        ProtoFields.developmentCharge .= toProto stoDevelopmentCharge
                    )
    toProto TxTypes.PaydayAccountReward{..} =
        Proto.make $
            ProtoFields.paydayAccountReward
                .= Proto.make
                    ( do
                        ProtoFields.account .= toProto stoAccount
                        ProtoFields.transactionFees .= toProto stoTransactionFees
                        ProtoFields.bakerReward .= toProto stoBakerReward
                        ProtoFields.finalizationReward .= toProto stoFinalizationReward
                    )
    toProto TxTypes.BlockAccrueReward{..} =
        Proto.make $
            ProtoFields.blockAccrueReward
                .= Proto.make
                    ( do
                        ProtoFields.transactionFees .= toProto stoTransactionFees
                        ProtoFields.oldGasAccount .= toProto stoOldGASAccount
                        ProtoFields.newGasAccount .= toProto stoNewGASAccount
                        ProtoFields.bakerReward .= toProto stoBakerReward
                        ProtoFields.passiveReward .= toProto stoPassiveReward
                        ProtoFields.foundationCharge .= toProto stoFoundationCharge
                        ProtoFields.baker .= toProto stoBakerId
                    )
    toProto TxTypes.PaydayPoolReward{..} =
        Proto.make $
            ProtoFields.paydayPoolReward
                .= Proto.make
                    ( do
                        ProtoFields.maybe'poolOwner .= fmap toProto stoPoolOwner
                        ProtoFields.transactionFees .= toProto stoTransactionFees
                        ProtoFields.bakerReward .= toProto stoBakerReward
                        ProtoFields.finalizationReward .= toProto stoFinalizationReward
                    )
    toProto TxTypes.ValidatorPrimedForSuspension{..} =
        Proto.make $
            ProtoFields.validatorPrimedForSuspension
                .= Proto.make
                    ( do
                        ProtoFields.bakerId .= toProto vpfsBakerId
                        ProtoFields.account .= toProto vpfsAccount
                    )
    toProto TxTypes.ValidatorSuspended{..} =
        Proto.make $
            ProtoFields.validatorSuspended
                .= Proto.make
                    ( do
                        ProtoFields.bakerId .= toProto vsBakerId
                        ProtoFields.account .= toProto vsAccount
                    )

instance ToProto (TransactionTime, QueryTypes.PendingUpdateEffect) where
    type Output (TransactionTime, QueryTypes.PendingUpdateEffect) = Proto.PendingUpdate
    toProto (time, effect) = Proto.make $ do
        ProtoFields.effectiveTime .= toProto time
        case effect of
            QueryTypes.PUERootKeys keys -> ProtoFields.rootKeys .= toProto keys
            QueryTypes.PUELevel1Keys keys -> ProtoFields.level1Keys .= toProto keys
            QueryTypes.PUELevel2KeysV0 auth -> ProtoFields.level2KeysCpv0 .= toProto auth
            QueryTypes.PUELevel2KeysV1 auth -> ProtoFields.level2KeysCpv1 .= toProto auth
            QueryTypes.PUEProtocol protocolUpdate -> ProtoFields.protocol .= toProto protocolUpdate
            QueryTypes.PUEElectionDifficulty electionDifficulty -> ProtoFields.electionDifficulty .= toProto electionDifficulty
            QueryTypes.PUEEuroPerEnergy euroPerEnergy -> ProtoFields.euroPerEnergy .= toProto euroPerEnergy
            QueryTypes.PUEMicroCCDPerEuro microCcdPerEuro -> ProtoFields.microCcdPerEuro .= toProto microCcdPerEuro
            QueryTypes.PUEFoundationAccount foundationAccount -> ProtoFields.foundationAccount .= toProto foundationAccount
            QueryTypes.PUEMintDistributionV0 mintDistributionCpv0 -> ProtoFields.mintDistributionCpv0 .= toProto mintDistributionCpv0
            QueryTypes.PUEMintDistributionV1 mintDistributionCpv1 -> ProtoFields.mintDistributionCpv1 .= toProto mintDistributionCpv1
            QueryTypes.PUETransactionFeeDistribution transactionFeeDistribution -> ProtoFields.transactionFeeDistribution .= toProto transactionFeeDistribution
            QueryTypes.PUEGASRewardsV0 gasRewards -> ProtoFields.gasRewards .= toProto gasRewards
            QueryTypes.PUEPoolParametersV0 poolParametersCpv0 -> ProtoFields.poolParametersCpv0 .= toProto poolParametersCpv0
            QueryTypes.PUEPoolParametersV1 poolParametersCpv1 -> ProtoFields.poolParametersCpv1 .= toProto poolParametersCpv1
            QueryTypes.PUEAddAnonymityRevoker addAnonymityRevoker -> ProtoFields.addAnonymityRevoker .= toProto addAnonymityRevoker
            QueryTypes.PUEAddIdentityProvider addIdentityProvider -> ProtoFields.addIdentityProvider .= toProto addIdentityProvider
            QueryTypes.PUECooldownParameters cooldownParameters -> ProtoFields.cooldownParameters .= toProto cooldownParameters
            QueryTypes.PUETimeParameters timeParameters -> ProtoFields.timeParameters .= toProto timeParameters
            QueryTypes.PUEGASRewardsV1 gasRewards -> ProtoFields.gasRewardsCpv2 .= toProto gasRewards
            QueryTypes.PUETimeoutParameters timeoutParameters -> ProtoFields.timeoutParameters .= toProto timeoutParameters
            QueryTypes.PUEMinBlockTime minBlockTime -> ProtoFields.minBlockTime .= toProto minBlockTime
            QueryTypes.PUEBlockEnergyLimit blockEnergyLimit -> ProtoFields.blockEnergyLimit .= toProto blockEnergyLimit
            QueryTypes.PUEFinalizationCommitteeParameters finalizationCommitteeParameters -> ProtoFields.finalizationCommitteeParameters .= toProto finalizationCommitteeParameters
            QueryTypes.PUEValidatorScoreParameters validatorScoreParameters -> ProtoFields.validatorScoreParameters .= toProto validatorScoreParameters

instance ToProto QueryTypes.NextUpdateSequenceNumbers where
    type Output QueryTypes.NextUpdateSequenceNumbers = Proto.NextUpdateSequenceNumbers
    toProto QueryTypes.NextUpdateSequenceNumbers{..} = Proto.make $ do
        ProtoFields.rootKeys .= toProto _nusnRootKeys
        ProtoFields.level1Keys .= toProto _nusnLevel1Keys
        ProtoFields.level2Keys .= toProto _nusnLevel2Keys
        ProtoFields.protocol .= toProto _nusnProtocol
        ProtoFields.electionDifficulty .= toProto _nusnElectionDifficulty
        ProtoFields.euroPerEnergy .= toProto _nusnEuroPerEnergy
        ProtoFields.microCcdPerEuro .= toProto _nusnMicroCCDPerEuro
        ProtoFields.foundationAccount .= toProto _nusnFoundationAccount
        ProtoFields.mintDistribution .= toProto _nusnMintDistribution
        ProtoFields.transactionFeeDistribution .= toProto _nusnTransactionFeeDistribution
        ProtoFields.gasRewards .= toProto _nusnGASRewards
        ProtoFields.poolParameters .= toProto _nusnPoolParameters
        ProtoFields.addAnonymityRevoker .= toProto _nusnAddAnonymityRevoker
        ProtoFields.addIdentityProvider .= toProto _nusnAddIdentityProvider
        ProtoFields.cooldownParameters .= toProto _nusnCooldownParameters
        ProtoFields.timeParameters .= toProto _nusnTimeParameters
        ProtoFields.timeoutParameters .= toProto _nusnTimeoutParameters
        ProtoFields.minBlockTime .= toProto _nusnMinBlockTime
        ProtoFields.blockEnergyLimit .= toProto _nusnBlockEnergyLimit
        ProtoFields.finalizationCommitteeParameters .= toProto _nusnFinalizationCommitteeParameters
        ProtoFields.validatorScoreParameters .= toProto _nusnValidatorScoreParameters
        ProtoFields.protocolLevelTokens .= toProto _nusnProtocolLevelTokensParameters

instance ToProto Epoch where
    type Output Epoch = Proto.Epoch
    toProto = mkWord64

instance ToProto Round where
    type Output Round = Proto.Round
    toProto (Round r) = mkWord64 r

instance ToProto CredentialsPerBlockLimit where
    type Output CredentialsPerBlockLimit = Proto.CredentialsPerBlockLimit
    toProto = mkWord16

instance ToProto (AccountAddress, EChainParametersAndKeys) where
    type Output (AccountAddress, EChainParametersAndKeys) = Proto.ChainParameters

    toProto (foundationAddr, EChainParametersAndKeys (params :: Parameters.ChainParameters' cpv) keys) =
        case chainParametersVersion @cpv of
            SChainParametersV0 ->
                let Parameters.ChainParameters
                        { _cpCooldownParameters = Parameters.CooldownParametersV0 epochs,
                          _cpPoolParameters = Parameters.PoolParametersV0 minThreshold,
                          ..
                        } = params
                in  Proto.make $
                        ProtoFields.v0
                            .= Proto.make
                                ( do
                                    ProtoFields.electionDifficulty .= toProto (Parameters._cpElectionDifficulty _cpConsensusParameters)
                                    ProtoFields.euroPerEnergy .= toProto (Parameters._erEuroPerEnergy _cpExchangeRates)
                                    ProtoFields.microCcdPerEuro .= toProto (Parameters._erMicroGTUPerEuro _cpExchangeRates)
                                    ProtoFields.bakerCooldownEpochs .= toProto epochs
                                    ProtoFields.accountCreationLimit .= toProto _cpAccountCreationLimit
                                    ProtoFields.mintDistribution .= toProto (Parameters._rpMintDistribution _cpRewardParameters)
                                    ProtoFields.transactionFeeDistribution .= toProto (Parameters._rpTransactionFeeDistribution _cpRewardParameters)
                                    ProtoFields.gasRewards .= toProto (Parameters._rpGASRewards _cpRewardParameters)
                                    ProtoFields.foundationAccount .= toProto foundationAddr
                                    ProtoFields.minimumThresholdForBaking .= toProto minThreshold
                                    ProtoFields.rootKeys .= toProto (Updates.rootKeys keys)
                                    ProtoFields.level1Keys .= toProto (Updates.level1Keys keys)
                                    ProtoFields.level2Keys .= toProto (Updates.level2Keys keys)
                                )
            SChainParametersV1 ->
                let Parameters.ChainParameters{..} = params
                in  Proto.make $
                        ProtoFields.v1
                            .= Proto.make
                                ( do
                                    ProtoFields.electionDifficulty .= toProto (Parameters._cpElectionDifficulty _cpConsensusParameters)
                                    ProtoFields.euroPerEnergy .= toProto (Parameters._erEuroPerEnergy _cpExchangeRates)
                                    ProtoFields.microCcdPerEuro .= toProto (Parameters._erMicroGTUPerEuro _cpExchangeRates)
                                    ProtoFields.cooldownParameters .= toProto _cpCooldownParameters
                                    ProtoFields.timeParameters .= toProto (Parameters.unOParam _cpTimeParameters)
                                    ProtoFields.accountCreationLimit .= toProto _cpAccountCreationLimit
                                    ProtoFields.mintDistribution .= toProto (Parameters._rpMintDistribution _cpRewardParameters)
                                    ProtoFields.transactionFeeDistribution .= toProto (Parameters._rpTransactionFeeDistribution _cpRewardParameters)
                                    ProtoFields.gasRewards .= toProto (Parameters._rpGASRewards _cpRewardParameters)
                                    ProtoFields.foundationAccount .= toProto foundationAddr
                                    ProtoFields.poolParameters .= toProto _cpPoolParameters
                                    ProtoFields.rootKeys .= toProto (Updates.rootKeys keys)
                                    ProtoFields.level1Keys .= toProto (Updates.level1Keys keys)
                                    ProtoFields.level2Keys .= toProto (Updates.level2Keys keys)
                                )
            SChainParametersV2 ->
                let Parameters.ChainParameters{..} = params
                in  Proto.make $
                        ProtoFields.v2
                            .= Proto.make
                                ( do
                                    ProtoFields.consensusParameters .= toProto _cpConsensusParameters
                                    ProtoFields.euroPerEnergy .= toProto (Parameters._erEuroPerEnergy _cpExchangeRates)
                                    ProtoFields.microCcdPerEuro .= toProto (Parameters._erMicroGTUPerEuro _cpExchangeRates)
                                    ProtoFields.cooldownParameters .= toProto _cpCooldownParameters
                                    ProtoFields.timeParameters .= toProto (Parameters.unOParam _cpTimeParameters)
                                    ProtoFields.accountCreationLimit .= toProto _cpAccountCreationLimit
                                    ProtoFields.mintDistribution .= toProto (Parameters._rpMintDistribution _cpRewardParameters)
                                    ProtoFields.transactionFeeDistribution .= toProto (Parameters._rpTransactionFeeDistribution _cpRewardParameters)
                                    ProtoFields.gasRewards .= toProto (Parameters._rpGASRewards _cpRewardParameters)
                                    ProtoFields.foundationAccount .= toProto foundationAddr
                                    ProtoFields.poolParameters .= toProto _cpPoolParameters
                                    ProtoFields.rootKeys .= toProto (Updates.rootKeys keys)
                                    ProtoFields.level1Keys .= toProto (Updates.level1Keys keys)
                                    ProtoFields.level2Keys .= toProto (Updates.level2Keys keys)
                                    ProtoFields.finalizationCommitteeParameters .= toProto (Parameters.unOParam _cpFinalizationCommitteeParameters)
                                )
            SChainParametersV3 ->
                let Parameters.ChainParameters{..} = params
                in  Proto.make $
                        ProtoFields.v3
                            .= Proto.make
                                ( do
                                    ProtoFields.consensusParameters .= toProto _cpConsensusParameters
                                    ProtoFields.euroPerEnergy .= toProto (Parameters._erEuroPerEnergy _cpExchangeRates)
                                    ProtoFields.microCcdPerEuro .= toProto (Parameters._erMicroGTUPerEuro _cpExchangeRates)
                                    ProtoFields.cooldownParameters .= toProto _cpCooldownParameters
                                    ProtoFields.timeParameters .= toProto (Parameters.unOParam _cpTimeParameters)
                                    ProtoFields.accountCreationLimit .= toProto _cpAccountCreationLimit
                                    ProtoFields.mintDistribution .= toProto (Parameters._rpMintDistribution _cpRewardParameters)
                                    ProtoFields.transactionFeeDistribution .= toProto (Parameters._rpTransactionFeeDistribution _cpRewardParameters)
                                    ProtoFields.gasRewards .= toProto (Parameters._rpGASRewards _cpRewardParameters)
                                    ProtoFields.foundationAccount .= toProto foundationAddr
                                    ProtoFields.poolParameters .= toProto _cpPoolParameters
                                    ProtoFields.rootKeys .= toProto (Updates.rootKeys keys)
                                    ProtoFields.level1Keys .= toProto (Updates.level1Keys keys)
                                    ProtoFields.level2Keys .= toProto (Updates.level2Keys keys)
                                    ProtoFields.finalizationCommitteeParameters .= toProto (Parameters.unOParam _cpFinalizationCommitteeParameters)
                                    ProtoFields.validatorScoreParameters .= toProto (Parameters.unOParam _cpValidatorScoreParameters)
                                )
            SChainParametersV4 ->
                let Parameters.ChainParameters{..} = params
                in  Proto.make $
                        -- Notice we use v3 and not v4 here, as we decided not to introduce anymore
                        -- chain parameters versions in the API and instead extend the v3 with optional fields.
                        ProtoFields.v3
                            .= Proto.make
                                ( do
                                    ProtoFields.consensusParameters .= toProto _cpConsensusParameters
                                    ProtoFields.euroPerEnergy .= toProto (Parameters._erEuroPerEnergy _cpExchangeRates)
                                    ProtoFields.microCcdPerEuro .= toProto (Parameters._erMicroGTUPerEuro _cpExchangeRates)
                                    ProtoFields.cooldownParameters .= toProto _cpCooldownParameters
                                    ProtoFields.timeParameters .= toProto (Parameters.unOParam _cpTimeParameters)
                                    ProtoFields.accountCreationLimit .= toProto _cpAccountCreationLimit
                                    ProtoFields.mintDistribution .= toProto (Parameters._rpMintDistribution _cpRewardParameters)
                                    ProtoFields.transactionFeeDistribution .= toProto (Parameters._rpTransactionFeeDistribution _cpRewardParameters)
                                    ProtoFields.gasRewards .= toProto (Parameters._rpGASRewards _cpRewardParameters)
                                    ProtoFields.foundationAccount .= toProto foundationAddr
                                    ProtoFields.poolParameters .= toProto _cpPoolParameters
                                    ProtoFields.rootKeys .= toProto (Updates.rootKeys keys)
                                    ProtoFields.level1Keys .= toProto (Updates.level1Keys keys)
                                    ProtoFields.level2Keys .= toProto (Updates.level2Keys keys)
                                    ProtoFields.finalizationCommitteeParameters .= toProto (Parameters.unOParam _cpFinalizationCommitteeParameters)
                                    ProtoFields.validatorScoreParameters .= toProto (Parameters.unOParam _cpValidatorScoreParameters)
                                )

instance ToProto FinalizationIndex where
    type Output FinalizationIndex = Proto.FinalizationIndex

    toProto = mkWord64

instance ToProto QueryTypes.FinalizationSummaryParty where
    type Output QueryTypes.FinalizationSummaryParty = Proto.FinalizationSummaryParty

    toProto QueryTypes.FinalizationSummaryParty{..} = Proto.make $ do
        ProtoFields.baker .= toProto fspBakerId
        ProtoFields.weight .= fromIntegral fspWeight
        ProtoFields.signed .= fspSigned

instance ToProto BlockFinalizationSummary where
    type Output BlockFinalizationSummary = Proto.BlockFinalizationSummary

    toProto NoSummary = Proto.make (ProtoFields.none .= Proto.defMessage)
    toProto (Summary QueryTypes.FinalizationSummary{..}) =
        Proto.make
            ( ProtoFields.record
                .= Proto.make
                    ( do
                        ProtoFields.block .= toProto fsFinalizationBlockPointer
                        ProtoFields.index .= toProto fsFinalizationIndex
                        ProtoFields.delay .= toProto fsFinalizationDelay
                        ProtoFields.finalizers .= map toProto (Vec.toList fsFinalizers)
                    )
            )

instance ToProto AccountIdentifier where
    type Output AccountIdentifier = Proto.AccountIdentifierInput
    toProto = \case
        CredRegID cred -> Proto.make $ ProtoFields.credId .= toProto cred
        AccAddress addr -> Proto.make $ ProtoFields.address .= toProto addr
        AccIndex accIdx -> Proto.make $ ProtoFields.accountIndex .= toProto accIdx

instance ToProto Transactions.BareBlockItem where
    type Output Transactions.BareBlockItem = Proto.SendBlockItemRequest
    toProto bbi = Proto.make $
        case bbi of
            Transactions.NormalTransaction aTransaction ->
                ProtoFields.accountTransaction .= toProto aTransaction
            Transactions.CredentialDeployment aCreation ->
                ProtoFields.credentialDeployment .= toProto aCreation
            Transactions.ChainUpdate uInstruction ->
                ProtoFields.updateInstruction .= toProto uInstruction

instance ToProto BlockHashInput where
    type Output BlockHashInput = Proto.BlockHashInput
    toProto = \case
        Best -> Proto.make $ ProtoFields.best .= Proto.defMessage
        LastFinal -> Proto.make $ ProtoFields.lastFinal .= Proto.defMessage
        Given bh -> Proto.make $ ProtoFields.given .= toProto bh
        AtHeight (Absolute{..}) -> Proto.make $ ProtoFields.absoluteHeight .= toProto aBlockHeight
        AtHeight (Relative{..}) ->
            Proto.make $
                ProtoFields.relativeHeight
                    .= Proto.make
                        ( do
                            ProtoFields.genesisIndex .= toProto rGenesisIndex
                            ProtoFields.height .= toProto rBlockHeight
                            ProtoFields.restrict .= rRestrict
                        )

instance ToProto BlockHeightInput where
    type Output BlockHeightInput = Proto.BlocksAtHeightRequest
    toProto Relative{..} =
        Proto.make $
            ProtoFields.relative
                .= Proto.make
                    ( do
                        ProtoFields.genesisIndex .= toProto rGenesisIndex
                        ProtoFields.height .= toProto rBlockHeight
                        ProtoFields.restrict .= rRestrict
                    )
    toProto Absolute{..} =
        Proto.make $
            ProtoFields.absolute .= Proto.make (ProtoFields.height .= toProto aBlockHeight)

instance ToProto (BlockHashInput, InvokeContract.ContractContext) where
    type Output (BlockHashInput, InvokeContract.ContractContext) = Proto.InvokeInstanceRequest
    toProto (bhi, InvokeContract.ContractContext{..}) =
        Proto.make $ do
            ProtoFields.blockHash .= toProto bhi
            ProtoFields.maybe'invoker .= fmap toProto ccInvoker
            ProtoFields.instance' .= toProto ccContract
            ProtoFields.amount .= toProto ccAmount
            ProtoFields.entrypoint .= toProto ccMethod
            ProtoFields.parameter .= toProto ccParameter
            ProtoFields.energy .= toProto ccEnergy

instance ToProto IpAddress where
    type Output IpAddress = Proto.IpAddress
    toProto ip = Proto.make $ ProtoFields.value .= ipAddress ip

instance ToProto IpPort where
    type Output IpPort = Proto.Port
    toProto ip = Proto.make $ ProtoFields.value .= fromIntegral (ipPort ip)

instance ToProto KonsensusV1.QuorumCertificateSignature where
    type Output KonsensusV1.QuorumCertificateSignature = Proto.QuorumSignature
    toProto (KonsensusV1.QuorumCertificateSignature sig) = mkSerialize sig

instance ToProto KonsensusV1.QuorumCertificate where
    type Output KonsensusV1.QuorumCertificate = Proto.QuorumCertificate
    toProto KonsensusV1.QuorumCertificate{..} =
        Proto.make $ do
            ProtoFields.blockHash .= toProto qcBlock
            ProtoFields.round .= toProto qcRound
            ProtoFields.epoch .= toProto qcEpoch
            ProtoFields.aggregateSignature .= toProto qcAggregateSignature
            ProtoFields.signatories .= (toProto <$> qcSignatories)

instance ToProto KonsensusV1.FinalizerRound where
    type Output KonsensusV1.FinalizerRound = Proto.FinalizerRound
    toProto KonsensusV1.FinalizerRound{..} =
        Proto.make $ do
            ProtoFields.round .= toProto frRound
            ProtoFields.finalizers .= (toProto <$> frFinalizers)

instance ToProto KonsensusV1.TimeoutCertificateSignature where
    type Output KonsensusV1.TimeoutCertificateSignature = Proto.TimeoutSignature
    toProto (KonsensusV1.TimeoutCertificateSignature sig) = mkSerialize sig

instance ToProto KonsensusV1.TimeoutCertificate where
    type Output KonsensusV1.TimeoutCertificate = Proto.TimeoutCertificate
    toProto KonsensusV1.TimeoutCertificate{..} =
        Proto.make $ do
            ProtoFields.round .= toProto tcRound
            ProtoFields.minEpoch .= toProto tcMinEpoch
            ProtoFields.qcRoundsFirstEpoch .= (toProto <$> tcFinalizerQCRoundsFirstEpoch)
            ProtoFields.qcRoundsSecondEpoch .= (toProto <$> tcFinalizerQCRoundsSecondEpoch)
            ProtoFields.aggregateSignature .= toProto tcAggregateSignature

instance ToProto KonsensusV1.SuccessorProof where
    type Output KonsensusV1.SuccessorProof = Proto.SuccessorProof
    toProto (KonsensusV1.SuccessorProof proof) = mkSerialize proof

instance ToProto KonsensusV1.EpochFinalizationEntry where
    type Output KonsensusV1.EpochFinalizationEntry = Proto.EpochFinalizationEntry
    toProto KonsensusV1.EpochFinalizationEntry{..} =
        Proto.make $ do
            ProtoFields.finalizedQc .= toProto efeFinalizedQC
            ProtoFields.successorQc .= toProto efeSuccessorQC
            ProtoFields.successorProof .= toProto efeSuccessorProof

instance ToProto KonsensusV1.BlockCertificates where
    type Output KonsensusV1.BlockCertificates = Proto.BlockCertificates
    toProto KonsensusV1.BlockCertificates{..} =
        Proto.make $ do
            ProtoFields.maybe'quorumCertificate .= fmap toProto bcQuorumCertificate
            ProtoFields.maybe'timeoutCertificate .= fmap toProto bcTimeoutCertificate
            ProtoFields.maybe'epochFinalizationEntry .= fmap toProto bcEpochFinalizationEntry

instance ToProto BakerRewardPeriodInfo where
    type Output BakerRewardPeriodInfo = Proto.BakerRewardPeriodInfo
    toProto BakerRewardPeriodInfo{..} =
        Proto.make $ do
            ProtoFields.baker .= toProto brpiBaker
            ProtoFields.effectiveStake .= toProto brpiEffectiveStake
            ProtoFields.commissionRates .= toProto brpiCommissionRates
            ProtoFields.equityCapital .= toProto brpiEquityCapital
            ProtoFields.delegatedCapital .= toProto brpiDelegatedCapital
            ProtoFields.isFinalizer .= brpiIsFinalizer

instance ToProto EpochRequest where
    type Output EpochRequest = Proto.EpochRequest
    toProto SpecifiedEpoch{..} = Proto.make $ do
        ProtoFields.relativeEpoch
            .= Proto.make
                ( do
                    ProtoFields.genesisIndex .= toProto erGenesisIndex
                    ProtoFields.epoch .= toProto erEpoch
                )
    toProto EpochOfBlock{..} = Proto.make $ do
        ProtoFields.blockHash .= toProto erBlock

instance ToProto WinningBaker where
    type Output WinningBaker = Proto.WinningBaker
    toProto WinningBaker{..} = Proto.make $ do
        ProtoFields.round .= toProto wbRound
        ProtoFields.winner .= toProto wbWinner
        ProtoFields.present .= wbPresent

instance ToProto DryRunError where
    type Output DryRunError = Proto.DryRunErrorResponse
    toProto DryRunErrorNoState =
        Proto.make $ ProtoFields.noState .= Proto.defMessage
    toProto DryRunErrorBlockNotFound =
        Proto.make $ ProtoFields.blockNotFound .= Proto.defMessage
    toProto DryRunErrorAccountNotFound =
        Proto.make $ ProtoFields.accountNotFound .= Proto.defMessage
    toProto DryRunErrorInstanceNotFound =
        Proto.make $ ProtoFields.instanceNotFound .= Proto.defMessage
    toProto DryRunErrorAmountOverLimit{..} =
        Proto.make $ ProtoFields.amountOverLimit .= Proto.build (ProtoFields.amountLimit .~ toProto dreMaximumMintAmount)
    toProto DryRunErrorBalanceInsufficient{..} =
        Proto.make $
            ProtoFields.balanceInsufficient
                .= Proto.make
                    ( do
                        ProtoFields.requiredAmount .= toProto dreRequiredAmount
                        ProtoFields.availableAmount .= toProto dreAvailableAmount
                    )
    toProto DryRunErrorEnergyInsufficient{..} =
        Proto.make $
            ProtoFields.energyInsufficient
                .= Proto.make
                    (ProtoFields.energyRequired .= toProto dreEnergyRequired)

instance ToProto DryRunSuccess where
    type Output DryRunSuccess = Proto.DryRunSuccessResponse
    toProto DryRunSuccessBlockStateLoaded{..} =
        Proto.make $ do
            ProtoFields.blockStateLoaded
                .= Proto.make
                    ( do
                        ProtoFields.currentTimestamp .= toProto drsCurrentTimestamp
                        ProtoFields.blockHash .= toProto drsBlockHash
                        ProtoFields.protocolVersion .= toProto drsProtocolVersion
                    )
    toProto DryRunSuccessAccountInfo{..} =
        Proto.make $ ProtoFields.accountInfo .= toProto drsAccountInfo
    toProto DryRunSuccessInstanceInfo{..} =
        Proto.make $ ProtoFields.instanceInfo .= toProto drsInstanceInfo
    toProto DryRunSuccessTimestampSet =
        Proto.make $ ProtoFields.timestampSet .= Proto.defMessage
    toProto DryRunSuccessMintedToAccount =
        Proto.make $ ProtoFields.mintedToAccount .= Proto.defMessage

instance ToProto (DryRunResponse DryRunSuccess) where
    type Output (DryRunResponse DryRunSuccess) = Proto.DryRunResponse
    toProto (DryRunResponse{..}) = Proto.make $ do
        ProtoFields.success .= toProto drrResponse
        ProtoFields.quotaRemaining .= toProto drrQuotaRemaining

instance ToProto (DryRunResponse DryRunError) where
    type Output (DryRunResponse DryRunError) = Proto.DryRunResponse
    toProto (DryRunResponse{..}) = Proto.make $ do
        ProtoFields.error .= toProto drrResponse
        ProtoFields.quotaRemaining .= toProto drrQuotaRemaining

instance ToProto (DryRunResponse InvokeContract.InvokeContractResult) where
    -- Since this is a conversion that may fail we use Either in the output type
    -- here so that we can forward errors, which is not in-line with other
    -- instances which are not fallible. The caller is meant to catch the error.
    type
        Output (DryRunResponse InvokeContract.InvokeContractResult) =
            Either ConversionError Proto.DryRunResponse
    toProto (DryRunResponse InvokeContract.Failure{..} quotaRem) =
        return $
            Proto.make $ do
                ProtoFields.error
                    .= Proto.make
                        ( ProtoFields.invokeFailed
                            .= Proto.make
                                ( do
                                    ProtoFields.maybe'returnValue .= rcrReturnValue
                                    ProtoFields.usedEnergy .= toProto rcrUsedEnergy
                                    ProtoFields.reason .= toProto rcrReason
                                )
                        )
                ProtoFields.quotaRemaining .= toProto quotaRem
    toProto (DryRunResponse InvokeContract.Success{..} quotaRem) = do
        effects <- mapM convertContractRelatedEvents rcrEvents
        return $
            Proto.make $ do
                ProtoFields.success
                    .= Proto.make
                        ( ProtoFields.invokeSucceeded
                            .= Proto.make
                                ( do
                                    ProtoFields.maybe'returnValue .= rcrReturnValue
                                    ProtoFields.usedEnergy .= toProto rcrUsedEnergy
                                    ProtoFields.effects .= effects
                                )
                        )
                ProtoFields.quotaRemaining .= toProto quotaRem

instance ToProto (DryRunResponse (TransactionSummary' SupplementedValidResultWithReturn)) where
    type
        Output (DryRunResponse (TransactionSummary' SupplementedValidResultWithReturn)) =
            Either ConversionError Proto.DryRunResponse
    toProto (DryRunResponse TransactionSummary{..} quotaRem) = case tsType of
        TSTAccountTransaction tty -> do
            sender <- case tsSender of
                Nothing -> Left CEInvalidTransactionResult
                Just acc -> Right acc
            details <- convertAccountTransaction tty tsCost sender (vrwrResult tsResult)
            Right . Proto.make $ do
                ProtoFields.success
                    .= Proto.make
                        ( ProtoFields.transactionExecuted
                            .= Proto.make
                                ( do
                                    mapM_ (ProtoFields.returnValue .=) $ vrwrReturnValue tsResult
                                    ProtoFields.energyCost .= toProto tsEnergyCost
                                    ProtoFields.details .= details
                                )
                        )
                ProtoFields.quotaRemaining .= toProto quotaRem
        _ -> do
            -- Since only account transactions can be executed in a dry run, we should not have
            -- other transaction summary types.
            Left CEInvalidTransactionResult

instance ToProto BlockSignature.Signature where
    type Output BlockSignature.Signature = Proto.BlockSignature
    toProto = mkSerialize

instance ToProto AccountPending where
    type Output AccountPending = Proto.AccountPending
    toProto AccountPending{..} = Proto.make $ do
        ProtoFields.accountIndex .= toProto apAccountIndex
        ProtoFields.firstTimestamp .= toProto apFirstTimestamp

instance ToProto TokenId where
    type Output TokenId = Proto.TokenId
    toProto (TokenId bss) = Proto.make $ do
        PLTFields.symbol .= decodeUtf8 (BSS.fromShort bss)
