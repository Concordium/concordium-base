{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}

-- | Types for representing the inputs to and results of consensus queries.
module Concordium.Types.Queries where

import Control.Applicative
import Control.Monad
import Data.Aeson
import Data.Aeson.TH
import Data.Char (isLower)
import qualified Data.Map as Map
import Data.Text (Text)
import Data.Time (UTCTime)
import qualified Data.Vector as Vec
import Data.Word

import Concordium.Types
import Concordium.Types.Accounts
import qualified Concordium.Types.AnonymityRevokers as ARS
import Concordium.Types.Block
import Concordium.Types.Execution (TransactionSummary)
import qualified Concordium.Types.IdentityProviders as IPS
import Concordium.Types.Parameters (
    AuthorizationsVersion (..),
    AuthorizationsVersionFor,
    ChainParameters',
    CooldownParameters,
    FinalizationCommitteeParameters,
    GASRewards,
    GASRewardsVersion (..),
    MintDistribution,
    MintDistributionVersion (..),
    OParam (..),
    PoolParameters,
    TimeParameters,
    TimeoutParameters,
    TransactionFeeDistribution,
 )
import qualified Concordium.Types.UpdateQueues as UQ
import qualified Concordium.Types.Updates as U
import Concordium.Utils
import qualified Concordium.Wasm as Wasm

-- | Result type for @getConsensusStatus@ queries.  A number of fields are not defined when no blocks
--  have so far been received, verified or finalized. In such cases, the values will be 'Nothing'.
--
--  The JSON serialization of this structure is as an object, with fields named as in the record,
--  but without the "cs" prefix, and the first letter in lowercase.
data ConsensusStatus = ConsensusStatus
    { -- | Hash of the current best block
      csBestBlock :: !BlockHash,
      -- | Hash of the (original) genesis block
      csGenesisBlock :: !BlockHash,
      -- | Time of the (original) genesis block
      csGenesisTime :: !UTCTime,
      -- | (Current) slot duration in milliseconds. Only present in protocol versions 1-5.
      csSlotDuration :: !(Maybe Duration),
      -- | (Current) epoch duration in milliseconds
      csEpochDuration :: !Duration,
      -- | Hash of the last finalized block
      csLastFinalizedBlock :: !BlockHash,
      -- | Absolute height of the best block
      csBestBlockHeight :: !AbsoluteBlockHeight,
      -- | Absolute height of the last finalized block
      csLastFinalizedBlockHeight :: !AbsoluteBlockHeight,
      -- | Total number of blocks received
      csBlocksReceivedCount :: !Int,
      -- | The last time a block was received
      csBlockLastReceivedTime :: !(Maybe UTCTime),
      -- | Moving average latency between a block's slot time and received time
      csBlockReceiveLatencyEMA :: !Double,
      -- | Standard deviation of moving average latency between a block's slot time and received time
      csBlockReceiveLatencyEMSD :: !Double,
      -- | Moving average time between receiving blocks
      csBlockReceivePeriodEMA :: !(Maybe Double),
      -- | Standard deviation of moving average time between receiving blocks
      csBlockReceivePeriodEMSD :: !(Maybe Double),
      -- | Total number of blocks received and verified
      csBlocksVerifiedCount :: !Int,
      -- | The last time a block was verified (added to the tree)
      csBlockLastArrivedTime :: !(Maybe UTCTime),
      -- | Moving average latency between a block's slot time and its arrival
      csBlockArriveLatencyEMA :: !Double,
      -- | Standard deviation of moving average latency between a block's slot time and its arrival
      csBlockArriveLatencyEMSD :: !Double,
      -- | Moving average time between block arrivals
      csBlockArrivePeriodEMA :: !(Maybe Double),
      -- | Standard deviation of moving average time between block arrivals
      csBlockArrivePeriodEMSD :: !(Maybe Double),
      -- | Moving average number of transactions per block
      csTransactionsPerBlockEMA :: !Double,
      -- | Standard deviation of moving average number of transactions per block
      csTransactionsPerBlockEMSD :: !Double,
      -- | Number of finalizations
      csFinalizationCount :: !Int,
      -- | Time of last verified finalization
      csLastFinalizedTime :: !(Maybe UTCTime),
      -- | Moving average time between finalizations
      csFinalizationPeriodEMA :: !(Maybe Double),
      -- | Standard deviation of moving average time between finalizations
      csFinalizationPeriodEMSD :: !(Maybe Double),
      -- | Currently active protocol version.
      csProtocolVersion :: !ProtocolVersion,
      -- | The number of chain restarts via a protocol update. An effected
      --  protocol update instruction might not change the protocol version
      --  specified in the previous field, but it always increments the genesis
      --  index.
      csGenesisIndex :: !GenesisIndex,
      -- | Block hash of the genesis block of current era, i.e., since the last protocol update.
      --  Initially this is equal to 'csGenesisBlock'.
      csCurrentEraGenesisBlock :: !BlockHash,
      -- | Time when the current era started.
      csCurrentEraGenesisTime :: !UTCTime,
      -- | Parameters that pertain only to the consensus protocol effective at protocol 6 and onward.
      csConcordiumBFTStatus :: !(Maybe ConcordiumBFTStatus)
    }
    deriving (Show)

-- | Part of 'ConsensusStatus' that pertains only to the Concordium BFT
--  consensus and is only present when protocol 6 or later is in effect.
data ConcordiumBFTStatus = ConcordiumBFTStatus
    { -- | The current duration to wait before a round times out.
      cbftsCurrentTimeoutDuration :: !Duration,
      -- | The current round.
      cbftsCurrentRound :: !Round,
      -- | The current epoch.
      cbftsCurrentEpoch :: !Epoch,
      -- | The trigger block time of the seedstate of the last finalized block. The first block in
      --  the epoch with timestamp at least this is considered to be the trigger block for the epoch
      --  transition.
      cbftsTriggerBlockTime :: !UTCTime
    }
    deriving (Show)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''ConcordiumBFTStatus)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''ConsensusStatus)

-- | Result type for @getBranches@ query. A 'Branch' consists of the hash of a block and 'Branch'es
--  for each child of the block.
data Branch = Branch
    { -- | Block hash
      branchBlockHash :: !BlockHash,
      -- | Child branches
      branchChildren :: ![Branch]
    }
    deriving (Eq, Ord, Show)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''Branch)

-- | Result type for @getNextAccountNonce@ query.
--  If all account transactions are finalized then this information is reliable.
--  Otherwise this is the best guess, assuming all other transactions will be
--  committed to blocks and eventually finalized.
data NextAccountNonce = NextAccountNonce
    { -- | The next account nonce
      nanNonce :: !Nonce,
      -- | True if all transactions on the account are finalized
      nanAllFinal :: !Bool
    }
    deriving (Show)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''NextAccountNonce)

-- | Result type for @getBlockInfo@ query.
data BlockInfo = BlockInfo
    { -- | The block hash
      biBlockHash :: !BlockHash,
      -- | The parent block hash. For a re-genesis block, this will be the terminal block of the
      --  previous chain. For the initial genesis block, this will be the hash of the block itself.
      biBlockParent :: !BlockHash,
      -- | The last finalized block when this block was baked
      biBlockLastFinalized :: !BlockHash,
      -- | The height of this block
      biBlockHeight :: !AbsoluteBlockHeight,
      -- | The genesis index for this block. This counts the number of protocol updates that have
      --  preceded this block, and defines the era of the block.
      biGenesisIndex :: !GenesisIndex,
      -- | The height of this block relative to the (re)genesis block of its era.
      biEraBlockHeight :: !BlockHeight,
      -- | The time the block was received
      biBlockReceiveTime :: !UTCTime,
      -- | The time the block was verified
      biBlockArriveTime :: !UTCTime,
      -- | The slot number in which the block was baked. Only present in protocol versions 1-5.
      biBlockSlot :: !(Maybe Slot),
      -- | The time of the slot in which the block was baked
      biBlockSlotTime :: !UTCTime,
      -- | The identifier of the block baker, or @Nothing@ for a
      --  genesis block.
      biBlockBaker :: !(Maybe BakerId),
      -- | Whether the block is finalized
      biFinalized :: !Bool,
      -- | The number of transactions in the block
      biTransactionCount :: !Int,
      -- | The energy cost of the transaction in the block
      biTransactionEnergyCost :: !Energy,
      -- | The size of the transactions
      biTransactionsSize :: !Int,
      -- | The hash of the block state
      biBlockStateHash :: !StateHash,
      -- | Protocol version that the block belongs to.
      biProtocolVersion :: !ProtocolVersion,
      -- | The round of the block. Present from protocol version 6.
      biRound :: !(Maybe Round),
      -- | The epoch of the block. Present from protocol version 6.
      biEpoch :: !(Maybe Epoch)
    }
    deriving (Show)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''BlockInfo)

-- | Details of a party in a finalization.
data FinalizationSummaryParty = FinalizationSummaryParty
    { -- | The identity of the baker
      fspBakerId :: !BakerId,
      -- | The party's relative weight in the committee
      fspWeight :: !Integer,
      -- | Whether the party's signature is present
      fspSigned :: !Bool
    }
    deriving (Show)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''FinalizationSummaryParty)

-- | Details of a finalization record.
data FinalizationSummary = FinalizationSummary
    { -- | Hash of the finalized block
      fsFinalizationBlockPointer :: !BlockHash,
      -- | Index of the finalization
      fsFinalizationIndex :: !FinalizationIndex,
      -- | Finalization delay value
      fsFinalizationDelay :: !BlockHeight,
      -- | The finalization committee
      fsFinalizers :: !(Vec.Vector FinalizationSummaryParty)
    }
    deriving (Show)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''FinalizationSummary)

-- | Status of the reward accounts. The type parameter determines the type used to represent time.
data RewardStatus' t
    = RewardStatusV0
        { -- | The total CCD in existence
          rsTotalAmount :: !Amount,
          -- | The total CCD in encrypted balances
          rsTotalEncryptedAmount :: !Amount,
          -- | The amount in the baking reward account
          rsBakingRewardAccount :: !Amount,
          -- | The amount in the finalization reward account
          rsFinalizationRewardAccount :: !Amount,
          -- | The amount in the GAS account
          rsGasAccount :: !Amount,
          -- | The protocol version
          rsProtocolVersion :: !ProtocolVersion
        }
    | RewardStatusV1
        { -- | The total CCD in existence
          rsTotalAmount :: !Amount,
          -- | The total CCD in encrypted balances
          rsTotalEncryptedAmount :: !Amount,
          -- | The amount in the baking reward account
          rsBakingRewardAccount :: !Amount,
          -- | The amount in the finalization reward account
          rsFinalizationRewardAccount :: !Amount,
          -- | The amount in the GAS account
          rsGasAccount :: !Amount,
          -- | The transaction reward fraction accruing to the foundation (to be paid at next payday)
          rsFoundationTransactionRewards :: !Amount,
          -- | The time of the next payday
          rsNextPaydayTime :: !t,
          -- | The rate at which CCD will be minted (as a proportion of the total supply) at the next payday
          rsNextPaydayMintRate :: !MintRate,
          -- | The total capital put up as stake by bakers and delegators
          rsTotalStakedCapital :: !Amount,
          -- | The protocol version
          rsProtocolVersion :: !ProtocolVersion
        }
    deriving (Eq, Show, Functor)

-- | Status of the reward accounts, with times represented as 'UTCTime'.
type RewardStatus = RewardStatus' UTCTime

instance ToJSON RewardStatus where
    toJSON RewardStatusV0{..} =
        object
            [ "totalAmount" .= rsTotalAmount,
              "totalEncryptedAmount" .= rsTotalEncryptedAmount,
              "bakingRewardAccount" .= rsBakingRewardAccount,
              "finalizationRewardAccount" .= rsFinalizationRewardAccount,
              "gasAccount" .= rsGasAccount,
              "protocolVersion" .= rsProtocolVersion
            ]
    toJSON RewardStatusV1{..} =
        object
            [ "totalAmount" .= rsTotalAmount,
              "totalEncryptedAmount" .= rsTotalEncryptedAmount,
              "bakingRewardAccount" .= rsBakingRewardAccount,
              "finalizationRewardAccount" .= rsFinalizationRewardAccount,
              "gasAccount" .= rsGasAccount,
              "foundationTransactionRewards" .= rsFoundationTransactionRewards,
              "nextPaydayTime" .= rsNextPaydayTime,
              "nextPaydayMintRate" .= rsNextPaydayMintRate,
              "totalStakedCapital" .= rsTotalStakedCapital,
              "protocolVersion" .= rsProtocolVersion
            ]

instance FromJSON RewardStatus where
    parseJSON = withObject "RewardStatus" $ \obj -> do
        rsTotalAmount <- obj .: "totalAmount"
        rsTotalEncryptedAmount <- obj .: "totalEncryptedAmount"
        rsBakingRewardAccount <- obj .: "bakingRewardAccount"
        rsFinalizationRewardAccount <- obj .: "finalizationRewardAccount"
        rsGasAccount <- obj .: "gasAccount"
        rsProtocolVersion <- obj .: "protocolVersion"
        if rsProtocolVersion >= P4
            then do
                rsFoundationTransactionRewards <- obj .: "foundationTransactionRewards"
                rsNextPaydayTime <- obj .: "nextPaydayTime"
                rsNextPaydayMintRate <- obj .: "nextPaydayMintRate"
                rsTotalStakedCapital <- obj .: "totalStakedCapital"
                return RewardStatusV1{..}
            else return RewardStatusV0{..}

-- | Summary of a baker.
data BakerSummary = BakerSummary
    { -- | Baker ID
      bsBakerId :: !BakerId,
      -- | (Approximate) lottery power
      bsBakerLotteryPower :: !Double,
      -- | Baker account (should never be @Nothing@)
      bsBakerAccount :: !(Maybe AccountAddress)
    }
    deriving (Show)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''BakerSummary)

-- | Summary of the birk parameters applicable to a particular block.
data BlockBirkParameters = BlockBirkParameters
    { -- | Baking lottery election difficulty. Only present in protocol versions 1-5.
      bbpElectionDifficulty :: !(Maybe ElectionDifficulty),
      -- | Current leadership election nonce for the lottery
      bbpElectionNonce :: !LeadershipElectionNonce,
      -- | List of the currently eligible bakers
      bbpBakers :: !(Vec.Vector BakerSummary)
    }
    deriving (Show)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''BlockBirkParameters)

-- | The status of a transaction that is present in the transaction table.
data TransactionStatus
    = -- | Transaction was received but is not in any blocks
      Received
    | -- | Transaction was received and is present in some (non-finalized) block(s)
      Committed (Map.Map BlockHash (Maybe TransactionSummary))
    | -- | Transaction has been finalized in a block
      Finalized BlockHash (Maybe TransactionSummary)
    deriving (Show)

instance ToJSON TransactionStatus where
    toJSON Received = object ["status" .= String "received"]
    toJSON (Committed m) =
        object
            [ "status" .= String "committed",
              "outcomes" .= m
            ]
    toJSON (Finalized bh outcome) =
        object
            [ "status" .= String "finalized",
              "outcomes" .= Map.singleton bh outcome
            ]

-- | The status of a transaction with respect to a specified block
data BlockTransactionStatus
    = -- | Either the transaction is not in that block, or that block is not live
      BTSNotInBlock
    | -- | The transaction was received but not known to be in that block
      BTSReceived
    | -- | The transaction is in that (non-finalized) block
      BTSCommitted (Maybe TransactionSummary)
    | -- | The transaction is in that (finalized) block
      BTSFinalized (Maybe TransactionSummary)
    deriving (Show)

instance ToJSON BlockTransactionStatus where
    toJSON BTSNotInBlock = Null
    toJSON BTSReceived = object ["status" .= String "received"]
    toJSON (BTSCommitted outcome) =
        object
            [ "status" .= String "committed",
              "result" .= outcome
            ]
    toJSON (BTSFinalized outcome) =
        object
            [ "status" .= String "finalized",
              "result" .= outcome
            ]

-- | A pending change (if any) to a baker pool.
--
--  The JSON encoding uses a tag "pendingChangeType", which is "NoChange",
--  "ReduceBakerCapital", or "RemovePool". If the tag is "NoChange" there are no
--  additional fields. If the tag is "ReduceBakerCapital" there are two
--  additional fields "bakerEquityCapital" and "effectiveTime". if the tag is
--  "RemovePool" there is an additional field "effectiveTime".
data PoolPendingChange
    = -- | No change is pending.
      PPCNoChange
    | -- | A reduction in baker equity capital is pending.
      PPCReduceBakerCapital
        { -- | New baker equity capital.
          ppcBakerEquityCapital :: !Amount,
          -- | Effective time of the change.
          ppcEffectiveTime :: !UTCTime
        }
    | -- | Removal of the pool is pending.
      PPCRemovePool
        { -- | Effective time of the change.
          ppcEffectiveTime :: !UTCTime
        }
    deriving (Eq, Show)

$( deriveJSON
    defaultOptions
        { fieldLabelModifier = firstLower . dropWhile isLower,
          constructorTagModifier = drop 3,
          sumEncoding =
            TaggedObject
                { tagFieldName = "pendingChangeType",
                  contentsFieldName = "pendingChangeDetails"
                }
        }
    ''PoolPendingChange
 )

-- | Construct a 'PoolPendingChange' from the 'StakePendingChange' of the pool owner.
makePoolPendingChange ::
    -- | Pool owner's pending stake change
    StakePendingChange' Timestamp ->
    PoolPendingChange
makePoolPendingChange NoChange = PPCNoChange
makePoolPendingChange (ReduceStake ppcBakerEquityCapital et) =
    PPCReduceBakerCapital{..}
  where
    ppcEffectiveTime = timestampToUTCTime et
makePoolPendingChange (RemoveStake et) = PPCRemovePool{..}
  where
    ppcEffectiveTime = timestampToUTCTime et

-- | Information about a baker pool's active stake and status. This does not reflect the stake used
--  for the current reward period, but rather the stake that is currently active.
data ActiveBakerPoolStatus = ActiveBakerPoolStatus
    { -- | The equity capital provided by the pool owner.
      abpsBakerEquityCapital :: !Amount,
      -- | The capital delegated to the pool by other accounts.
      abpsDelegatedCapital :: !Amount,
      -- | The maximum amount that may be delegated to the pool, accounting for leverage and
      --  stake limits.
      abpsDelegatedCapitalCap :: !Amount,
      -- | The pool info associated with the pool: open status, metadata URL and commission rates.
      abpsPoolInfo :: !BakerPoolInfo,
      -- | Any pending change to the baker's stake.
      abpsBakerStakePendingChange :: !PoolPendingChange
    }
    deriving (Eq, Show)

$( deriveJSON
    defaultOptions
        { fieldLabelModifier = firstLower . dropWhile isLower
        }
    ''ActiveBakerPoolStatus
 )

-- | Information about the status of a baker pool in the current reward period.
data CurrentPaydayBakerPoolStatus = CurrentPaydayBakerPoolStatus
    { -- | The number of blocks baked in the current reward period.
      bpsBlocksBaked :: !Word64,
      -- | Whether the baker has contributed a finalization proof in the current reward period.
      bpsFinalizationLive :: !Bool,
      -- | The transaction fees accruing to the pool in the current reward period.
      bpsTransactionFeesEarned :: !Amount,
      -- | The effective stake of the baker in the current reward period.
      bpsEffectiveStake :: !Amount,
      -- | The lottery power of the baker in the current reward period.
      bpsLotteryPower :: !Double,
      -- | The effective equity capital of the baker for the current reward period.
      bpsBakerEquityCapital :: !Amount,
      -- | The effective delegated capital to the pool for the current reward period.
      bpsDelegatedCapital :: !Amount,
      -- | The commission rates that apply for the current reward period.
      bpsCommissionRates :: !CommissionRates
    }
    deriving (Eq, Show)

$( deriveJSON
    defaultOptions
        { fieldLabelModifier = firstLower . dropWhile isLower
        }
    ''CurrentPaydayBakerPoolStatus
 )

-- | Status information about a given validator pool.
data BakerPoolStatus = BakerPoolStatus
    { -- | The 'BakerId' of the pool owner.
      psBakerId :: !BakerId,
      -- | The account address of the pool owner.
      psBakerAddress :: !AccountAddress,
      -- | The active status of the pool. This reflects any changes to the pool since
      --  the last snapshot.
      psActiveStatus :: !(Maybe ActiveBakerPoolStatus),
      -- | Status of the pool in the current reward period.
      --  This is a snapshot that is used to calculate the lottery power and reward distribution
      --  for the current reward period.
      psCurrentPaydayStatus :: !(Maybe CurrentPaydayBakerPoolStatus),
      -- | Total capital staked across all pools, including passive delegation.
      psAllPoolTotalCapital :: !Amount
    }
    deriving (Eq, Show)

instance ToJSON BakerPoolStatus where
    toJSON BakerPoolStatus{..} =
        object $
            [ "poolType" .= ("BakerPool" :: Text),
              "bakerId" .= psBakerId,
              "bakerAddress" .= psBakerAddress,
              "currentPaydayStatus" .= psCurrentPaydayStatus,
              "allPoolTotalCapital" .= psAllPoolTotalCapital
            ]
                ++ activeStatusFields
      where
        activeStatusFields = case psActiveStatus of
            Just ActiveBakerPoolStatus{..} ->
                [ "bakerEquityCapital" .= abpsBakerEquityCapital,
                  "delegatedCapital" .= abpsDelegatedCapital,
                  "delegatedCapitalCap" .= abpsDelegatedCapitalCap,
                  "poolInfo" .= abpsPoolInfo,
                  "bakerStakePendingChange" .= abpsBakerStakePendingChange
                ]
            Nothing -> []

instance FromJSON BakerPoolStatus where
    parseJSON = withObject "BakerPoolStatus" $ \obj -> do
        -- Check the pool type is correct
        poolType <- obj .: "poolType"
        unless (poolType == ("BakerPool" :: Text)) $
            fail "Expected poolType to be 'BakerPool'"
        psBakerId <- obj .: "bakerId"
        psBakerAddress <- obj .: "bakerAddress"
        psCurrentPaydayStatus <- obj .: "currentPaydayStatus"
        psAllPoolTotalCapital <- obj .: "allPoolTotalCapital"
        let activeStatusFields = do
                abpsBakerEquityCapital <- obj .: "bakerEquityCapital"
                abpsDelegatedCapital <- obj .: "delegatedCapital"
                abpsDelegatedCapitalCap <- obj .: "delegatedCapitalCap"
                abpsPoolInfo <- obj .: "poolInfo"
                abpsBakerStakePendingChange <- obj .: "bakerStakePendingChange"
                return ActiveBakerPoolStatus{..}
        psActiveStatus <- optional activeStatusFields
        return BakerPoolStatus{..}

-- | Status of the passive delegators.
--
--  Commission rates for the passive delegation provide a basis for comparison with baking pools, however,
--  whereas the commission for baking pools is paid to the pool owner, "commission" is not paid
--  to anyone.  Rather, it is used to determine the level of rewards paid to delegators, so that
--  their earnings are commensurate to delegating to a baking pool with the same commission rates.
data PassiveDelegationStatus = PassiveDelegationStatus
    { -- | The total capital delegated passively.
      pdsDelegatedCapital :: !Amount,
      -- | The passive delegation commission rates.
      pdsCommissionRates :: !CommissionRates,
      -- | The transaction fees accruing to the passive delegators in the current reward period.
      pdsCurrentPaydayTransactionFeesEarned :: !Amount,
      -- | The effective delegated capital of passive delegators for the current reward period.
      pdsCurrentPaydayDelegatedCapital :: !Amount,
      -- | Total capital staked across all pools, including passive delegation.
      pdsAllPoolTotalCapital :: !Amount
    }
    deriving (Eq, Show)

$( deriveJSON
    defaultOptions
        { fieldLabelModifier = firstLower . dropWhile isLower,
          constructorTagModifier = reverse . drop (length ("Status" :: String)) . reverse,
          sumEncoding = TaggedObject{tagFieldName = "poolType", contentsFieldName = "poolStatus"}
        }
    ''PassiveDelegationStatus
 )

-- | Pending chain parameters update effect.
data PendingUpdateEffect
    = -- | Updates to the root keys.
      PUERootKeys !(U.HigherLevelKeys U.RootKeysKind)
    | -- | Updates to the level 1 keys.
      PUELevel1Keys !(U.HigherLevelKeys U.Level1KeysKind)
    | -- | Updates to the level 2 keys.
      PUELevel2KeysV0 !(U.Authorizations 'AuthorizationsVersion0)
    | -- | Updates to the level 2 keys.
      PUELevel2KeysV1 !(U.Authorizations 'AuthorizationsVersion1)
    | -- | Protocol updates.
      PUEProtocol !U.ProtocolUpdate
    | -- | Updates to the election difficulty parameter for chain parameters versions 1-2.
      PUEElectionDifficulty !ElectionDifficulty
    | -- | Updates to the euro:energy exchange rate.
      PUEEuroPerEnergy !ExchangeRate
    | -- | Updates to the CCD:euro exchange rate.
      PUEMicroCCDPerEuro !ExchangeRate
    | -- | Updates to the foundation account.
      PUEFoundationAccount !AccountAddress
    | -- | Updates to the mint distribution.
      PUEMintDistributionV0 !(MintDistribution 'MintDistributionVersion0)
    | -- | Updates to the mint distribution.
      PUEMintDistributionV1 !(MintDistribution 'MintDistributionVersion1)
    | -- | Updates to the transaction fee distribution.
      PUETransactionFeeDistribution !TransactionFeeDistribution
    | -- | Updates to the GAS rewards in CPV0 and CPV1.
      PUEGASRewardsV0 !(GASRewards 'GASRewardsVersion0)
    | -- | Updates to the GAS rewards in CPV2.
      PUEGASRewardsV1 !(GASRewards 'GASRewardsVersion1)
    | -- | Updates pool parameters.
      PUEPoolParametersV0 !(PoolParameters 'ChainParametersV0)
    | PUEPoolParametersV1 !(PoolParameters 'ChainParametersV1)
    | -- | Adds a new anonymity revoker.
      PUEAddAnonymityRevoker !ARS.ArInfo
    | -- | Adds a new identity provider.
      PUEAddIdentityProvider !IPS.IpInfo
    | -- | Updates to cooldown parameters for chain parameters version 1 and later.
      PUECooldownParameters !(CooldownParameters 'ChainParametersV1)
    | -- | Updates to time parameters for chain parameters version 1 and later.
      PUETimeParameters !TimeParameters
    | -- | Updates to the consensus timeouts for chain parameters version 2.
      PUETimeoutParameters !TimeoutParameters
    | -- | Updates to the the minimum time between blocks for chain parameters version 2.
      PUEMinBlockTime !Duration
    | -- | Updates to the block energy limit for chain parameters version 2.
      PUEBlockEnergyLimit !Energy
    | -- | Updates to the finalization committee parameters for chain parameters version 2.
      PUEFinalizationCommitteeParameters !FinalizationCommitteeParameters

-- | Derive a @ToJSON@ instance for @PendingUpdateEffect@. For instance,
--  @print $ toJSON (PUETimeParameters a)@ will output something like:
--  @
--  {
--     "updateType": "TimeParameters"
--     "contents": { ... }
--  }
--  @
--  where @{ ... }@ is a placeholder the JSON object representing @a@.
$( deriveJSON
    defaultOptions
        { constructorTagModifier = drop (length ("PUE" :: String)),
          sumEncoding = TaggedObject{tagFieldName = "updateType", contentsFieldName = "contents"}
        }
    ''PendingUpdateEffect
 )

-- | Next available sequence numbers for updating any of the chain parameters.
data NextUpdateSequenceNumbers = NextUpdateSequenceNumbers
    { -- | Updates to the root keys.
      _nusnRootKeys :: !U.UpdateSequenceNumber,
      -- | Updates to the level 1 keys.
      _nusnLevel1Keys :: !U.UpdateSequenceNumber,
      -- | Updates to the level 2 keys.
      _nusnLevel2Keys :: !U.UpdateSequenceNumber,
      -- | Protocol updates.
      _nusnProtocol :: !U.UpdateSequenceNumber,
      -- | Updates to the election difficulty parameter.
      _nusnElectionDifficulty :: !U.UpdateSequenceNumber,
      -- | Updates to the euro:energy exchange rate.
      _nusnEuroPerEnergy :: !U.UpdateSequenceNumber,
      -- | Updates to the CCD:euro exchange rate.
      _nusnMicroCCDPerEuro :: !U.UpdateSequenceNumber,
      -- | Updates to the foundation account.
      _nusnFoundationAccount :: !U.UpdateSequenceNumber,
      -- | Updates to the mint distribution.
      _nusnMintDistribution :: !U.UpdateSequenceNumber,
      -- | Updates to the transaction fee distribution.
      _nusnTransactionFeeDistribution :: !U.UpdateSequenceNumber,
      -- | Updates to the GAS rewards.
      _nusnGASRewards :: !U.UpdateSequenceNumber,
      -- | Updates pool parameters.
      _nusnPoolParameters :: !U.UpdateSequenceNumber,
      -- | Adds a new anonymity revoker.
      _nusnAddAnonymityRevoker :: !U.UpdateSequenceNumber,
      -- | Adds a new identity provider.
      _nusnAddIdentityProvider :: !U.UpdateSequenceNumber,
      -- | Updates to cooldown parameters for chain parameters version 1 onwards.
      _nusnCooldownParameters :: !U.UpdateSequenceNumber,
      -- | Updates to time parameters for chain parameters version 1 onwards.
      _nusnTimeParameters :: !U.UpdateSequenceNumber,
      -- | Updates to the consensus version 2 timeout parameters.
      _nusnTimeoutParameters :: !U.UpdateSequenceNumber,
      -- | Updates to the consensus version 2 minimum time between blocks.
      _nusnMinBlockTime :: !U.UpdateSequenceNumber,
      -- | Updates to the consensus version 2 block energy limit.
      _nusnBlockEnergyLimit :: !U.UpdateSequenceNumber,
      -- | Updates to the consensus version 2 finalization committee parameters
      _nusnFinalizationCommitteeParameters :: !U.UpdateSequenceNumber
    }
    deriving (Show, Eq)

-- Derive JSON format by removing the `_nusn` prefix and lowercasing the initial letter of field names.
$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . drop (length ("_nusn" :: String))} ''NextUpdateSequenceNumbers)

-- | Build the struct containing all of the next available sequence numbers for updating any of the
-- chain parameters
updateQueuesNextSequenceNumbers :: UQ.PendingUpdates cpv -> NextUpdateSequenceNumbers
updateQueuesNextSequenceNumbers UQ.PendingUpdates{..} =
    NextUpdateSequenceNumbers
        { _nusnRootKeys = UQ._uqNextSequenceNumber _pRootKeysUpdateQueue,
          _nusnLevel1Keys = UQ._uqNextSequenceNumber _pLevel1KeysUpdateQueue,
          _nusnLevel2Keys = UQ._uqNextSequenceNumber _pLevel2KeysUpdateQueue,
          _nusnProtocol = UQ._uqNextSequenceNumber _pProtocolQueue,
          _nusnElectionDifficulty = mNextSequenceNumber _pElectionDifficultyQueue,
          _nusnEuroPerEnergy = UQ._uqNextSequenceNumber _pEuroPerEnergyQueue,
          _nusnMicroCCDPerEuro = UQ._uqNextSequenceNumber _pMicroGTUPerEuroQueue,
          _nusnFoundationAccount = UQ._uqNextSequenceNumber _pFoundationAccountQueue,
          _nusnMintDistribution = UQ._uqNextSequenceNumber _pMintDistributionQueue,
          _nusnTransactionFeeDistribution = UQ._uqNextSequenceNumber _pTransactionFeeDistributionQueue,
          _nusnGASRewards = UQ._uqNextSequenceNumber _pGASRewardsQueue,
          _nusnPoolParameters = UQ._uqNextSequenceNumber _pPoolParametersQueue,
          _nusnAddAnonymityRevoker = UQ._uqNextSequenceNumber _pAddAnonymityRevokerQueue,
          _nusnAddIdentityProvider = UQ._uqNextSequenceNumber _pAddIdentityProviderQueue,
          _nusnCooldownParameters = mNextSequenceNumber _pCooldownParametersQueue,
          _nusnTimeParameters = mNextSequenceNumber _pTimeParametersQueue,
          _nusnTimeoutParameters = mNextSequenceNumber _pTimeoutParametersQueue,
          _nusnMinBlockTime = mNextSequenceNumber _pMinBlockTimeQueue,
          _nusnBlockEnergyLimit = mNextSequenceNumber _pBlockEnergyLimitQueue,
          _nusnFinalizationCommitteeParameters = mNextSequenceNumber _pFinalizationCommitteeParametersQueue
        }
  where
    -- Get the next sequence number or 1, if not supported.
    mNextSequenceNumber :: UQ.OUpdateQueue pt cpv e -> U.UpdateSequenceNumber
    mNextSequenceNumber NoParam = 1
    mNextSequenceNumber (SomeParam q) = UQ._uqNextSequenceNumber q

-- | Information about a registered delegator in a block.
data DelegatorInfo = DelegatorInfo
    { -- | The delegator account address.
      pdiAccount :: !AccountAddress,
      -- | The amount of stake currently staked to the pool.
      pdiStake :: !Amount,
      -- | Pending change to the current stake of the delegator.
      pdiPendingChanges :: !(StakePendingChange' Timestamp)
    }

-- | Information about a fixed delegator in the reward period for a block.
data DelegatorRewardPeriodInfo = DelegatorRewardPeriodInfo
    { -- | The delegator account address.
      pdrpiAccount :: !AccountAddress,
      -- | The amount of stake fixed to the pool in the current reward period.
      pdrpiStake :: !Amount
    }

-- | Information about the finalization record included in a block.
data BlockFinalizationSummary
    = NoSummary
    | Summary !FinalizationSummary

-- | An existentially qualified pair of chain parameters and update keys currently in effect.
data EChainParametersAndKeys = forall (cpv :: ChainParametersVersion).
      (IsChainParametersVersion cpv) =>
    EChainParametersAndKeys
    { ecpParams :: !(ChainParameters' cpv),
      ecpKeys :: !(U.UpdateKeysCollection (AuthorizationsVersionFor cpv))
    }

instance ToJSON EChainParametersAndKeys where
    toJSON (EChainParametersAndKeys (params :: ChainParameters' cpv) keys) =
        case chainParametersVersion @cpv of
            SChainParametersV0 ->
                object
                    [ "version" .= toJSON ChainParametersV0,
                      "parameters" .= toJSON params,
                      "updateKeys" .= toJSON keys
                    ]
            SChainParametersV1 ->
                object
                    [ "version" .= toJSON ChainParametersV1,
                      "parameters" .= toJSON params,
                      "updateKeys" .= toJSON keys
                    ]
            SChainParametersV2 ->
                object
                    [ "version" .= toJSON ChainParametersV2,
                      "parameters" .= toJSON params,
                      "updateKeys" .= toJSON keys
                    ]
            SChainParametersV3 ->
                object
                    [ "version" .= toJSON ChainParametersV3,
                      "parameters" .= toJSON params,
                      "updateKeys" .= toJSON keys
                    ]

-- | The committee information of a node which is configured with
--  baker keys but is somehow is _not_ part of the current baking
--  committee.
data PassiveCommitteeInfo
    = -- | The node is started with baker keys however it is currently not in
      --  the baking committee. The node is _not_ baking.
      NotInCommittee
    | -- | The account is registered as a baker but not in the current @Epoch@.
      --  The node is _not_ baking.
      AddedButNotActiveInCommittee
    | -- | The node has configured invalid baker keys i.e., the configured
      --  baker keys do not match the current keys on the baker account.
      --  The node is _not_ baking.
      AddedButWrongKeys
    deriving (Show)

-- | Status of the baker configured node.
data BakerConsensusInfoStatus
    = -- | The node is currently not baking.
      PassiveBaker !PassiveCommitteeInfo
    | -- | Node is configured with baker keys and active in the current baking committee
      ActiveBaker
    | -- | Node is configured with baker keys and active in the current finalizer
      -- committee (and also baking committee).
      ActiveFinalizer
    deriving (Show)

-- | Consensus info for a node configured with baker keys.
data BakerConsensusInfo = BakerConsensusInfo
    { bakerId :: !BakerId,
      status :: !BakerConsensusInfoStatus
    }
    deriving (Show)

-- | Consensus related details of the peer.
data NodeDetails
    = -- | The node is a bootstrapper and not participating in consensus.
      NodeBootstrapper
    | -- | The node is not running consensus. This is the case only when the node
      --  is not supporting the protocol on the chain. The node does not process
      --  blocks.
      NodeNotRunning
    | -- | Consensus info for a node that is not configured with baker keys.
      -- The node is only processing blocks and relaying blocks and transactions
      -- and responding to catchup messages.
      NodePassive
    | -- | The node is configured with baker credentials and consensus is running.
      NodeActive !BakerConsensusInfo
    deriving (Show)

-- | Network related information of the node.
data NetworkInfo = NetworkInfo
    { -- | The node id.
      nodeId :: !Text,
      -- | Total number of packets sent by the node.
      peerTotalSent :: !Word64,
      -- | Total number of packets received by the node.
      peerTotalReceived :: !Word64,
      -- | Average outbound throughput in bytes per second.
      avgBpsIn :: !Word64,
      -- | Average inbound throughput in bytes per second.
      avgBpsOut :: !Word64
    }
    deriving (Show)

-- | Various information about the node.
data NodeInfo = NodeInfo
    { -- | The version of the node.
      peerVersion :: !Text,
      -- | The local time of the node.
      localTime :: !Timestamp,
      -- | Number of milliseconds that the node has been alive.
      peerUptime :: !Duration,
      -- | Information related to the p2p protocol.
      networkInfo :: !NetworkInfo,
      -- | Consensus related details of the node.
      details :: !NodeDetails
    }
    deriving (Show)

-- | Information about a block which arrived at the node.
data ArrivedBlockInfo = ArrivedBlockInfo
    { -- | Hash of the block.
      abiBlockHash :: !BlockHash,
      -- | Absolute height of the block, where 0 is the height of the genesis block.
      abiBlockHeight :: !AbsoluteBlockHeight
    }
    deriving (Show)

-- | A pending update.
data PendingUpdate = PendingUpdate
    { -- | The effect of the update.
      puEffect :: !PendingUpdateEffect,
      -- | The effective time of the update.
      puEffectiveTime :: TransactionTime
    }

-- | Derive JSON instance for @PendingUpdate@. A JSON object field label is named after its
--  corresponding record field name by stripping the maximal lower-case prefix of the record
--  field name and turning its first character into lower-case. For instance, the @puEffect@
--  record field is turned into the label @effect@ in the corresponding JSON representation
--  of the @PendingUpdate@.
$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''PendingUpdate)

-- | Catchup status of the peer.
data PeerCatchupStatus
    = -- | The peer is a bootstrapper and not participating in consensus.
      Bootstrapper
    | -- | The peer does not have any data unknown to us. If we receive a message
      --  from the peer that refers to unknown data (e.g., an unknown block) the
      --  peer is marked as pending.
      UpToDate
    | -- | The peer might have some data unknown to us. A peer can be in this state
      --  either because it sent a message that refers to data unknown to us, or
      --  before we have established a baseline with it. The latter happens during
      --  node startup, as well as upon protocol updates until the initial catchup
      --  handshake completes.
      Pending
    | -- | The node is currently catching up by requesting blocks from this peer.
      --  There will be at most one peer with this status at a time. Once the peer
      --  has responded to the request, its status will be changed to either @UpToDate@
      --  or @Pending@.
      CatchingUp
    deriving (Show, Eq)

-- | Network statistics for the peer.
data NetworkStats = NetworkStats
    { -- | The number of messages sent to the peer.
      --  Packets are blocks, transactions, catchup messages, finalization records
      --  and network messages such as pings and peer requests.
      packetsSent :: !Word64,
      -- | The number of messages received from the peer.
      --  Packets are blocks, transactions, catchup messages, finalization records
      --  and network messages such as pings and peer requests.
      packetsReceived :: !Word64,
      -- | The connection latency (i.e., ping time) in milliseconds.
      latency :: !Word64
    }
    deriving (Show)

-- | An IP address.
newtype IpAddress = IpAddress {ipAddress :: Text}
    deriving (Show, ToJSON)

-- | An IP port.
newtype IpPort = IpPort {ipPort :: Word16}
    deriving (Show, ToJSON)

-- | A peer. It is represented by its IP address.
type Peer = IpAddress

-- | A pair of an IP address and a port, representing a socket address.
type IpSocketAddress = (IpAddress, IpPort)

-- | Network related peer statistics.
data PeerInfo = PeerInfo
    { -- A string which the peer wishes to be identified by.
      peerId :: !Text,
      -- | The IP and port of the peer.
      socketAddress :: !IpSocketAddress,
      -- | Network related statistics about the peer.
      networkStats :: !NetworkStats,
      -- | Consensus related information about the peer.
      consensusInfo :: !PeerCatchupStatus
    }
    deriving (Show)

-- | A block identifier.
--  A block is either identified via a hash, or as one of the special
--  blocks at a given time (last final or best block). Queries which
--  just need the recent state can use @LastFinal@ or @Best@ to get the
--  result without first establishing what the last final or best block
--  is.
data BlockHashInput = Best | LastFinal | Given !BlockHash | AtHeight !BlockHeightInput

--  deriving (Read)

-- | Input for @getBlocksAtHeight@.
data BlockHeightInput
    = -- | The height of a block relative to a genesis index. This differs from the
      --  absolute block height in that it counts height from the protocol update
      --  corresponding to the provided genesis index.
      Relative
        { -- | Genesis index.
          rGenesisIndex :: !GenesisIndex,
          -- | Block height starting from the genesis block at the genesis index.
          rBlockHeight :: !BlockHeight,
          -- | Whether to return results only from the specified genesis index (@True@),
          --  or allow results from more recent genesis indices as well (@False@).
          rRestrict :: !Bool
        }
    | -- | The absolute height of a block. This is the number of ancestors of a block
      --  since the genesis block. In particular, the chain genesis block has absolute
      --  height 0.
      Absolute
        { aBlockHeight :: !AbsoluteBlockHeight
        }

-- | Information of a baker in a reward period.
data BakerRewardPeriodInfo = BakerRewardPeriodInfo
    { -- | The baker id and public keys.
      brpiBaker :: !BakerInfo,
      -- | The effective stake of the baker pool.
      brpiEffectiveStake :: !Amount,
      -- | The commission rates of the baker.
      brpiCommissionRates :: !CommissionRates,
      -- | The amount staked by the baker itself.
      brpiEquityCapital :: !Amount,
      -- | The total capital delegated to the baker pool.
      brpiDelegatedCapital :: !Amount,
      -- | Whether the baker is part of the finalization committee.
      brpiIsFinalizer :: !Bool
    }
    deriving (Show)

instance ToJSON BakerRewardPeriodInfo where
    toJSON BakerRewardPeriodInfo{..} =
        object
            [ "baker" .= brpiBaker,
              "effectiveStake" .= brpiEffectiveStake,
              "commissionRates" .= brpiCommissionRates,
              "equityCapital" .= brpiEquityCapital,
              "delegatedCapital" .= brpiDelegatedCapital,
              "isFinalizer" .= brpiIsFinalizer
            ]

-- | Input to queries which take an epoch as a parameter.
data EpochRequest
    = -- | Query by genesis index and epoch number.
      SpecifiedEpoch
        { -- | The genesis index to query at. The query is restricted to this genesis index, and
          --  will not return results for other indices even if the epoch number is out of bounds.
          erGenesisIndex :: !GenesisIndex,
          -- | The epoch number to query at.
          erEpoch :: !Epoch
        }
    | -- | Query the epoch of a specified block.
      EpochOfBlock
        { -- | The block whose epoch is to be used for the query.
          erBlock :: !BlockHashInput
        }

-- | Details of which baker won the lottery in a given round in consensus version 1.
data WinningBaker = WinningBaker
    { -- | The round number.
      wbRound :: !Round,
      -- | The baker that won the round.
      wbWinner :: !BakerId,
      -- | 'True' if the baker produced a block in this round on the finalized chain, and
      --  'False' otherwise.
      wbPresent :: !Bool
    }

-- | Derive JSON instance for @WinningBaker@. A JSON object field label is named after its
--  corresponding record field name by stripping the maximal lower-case prefix of the record
--  field name and turning its first character into lower-case. For instance, the @wbRound@
--  record field is turned into the label @round@ in the corresponding JSON representation
--  of the @PendingUpdate@.
$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''WinningBaker)

-- | A failing result of a dry run execution.
data DryRunError
    = -- | The current block state is undefined.
      DryRunErrorNoState
    | -- | The requested block was not found, so its state could not be loaded.
      DryRunErrorBlockNotFound
    | -- | The specified account was not found.
      DryRunErrorAccountNotFound
    | -- | The specified instance was not found.
      DryRunErrorInstanceNotFound
    | -- | The amount to mint would overflow the total CCD supply.
      DryRunErrorAmountOverLimit {dreMaximumMintAmount :: !Amount}
    | -- | The balance of the sender account is not sufficient to pay for the operation.
      DryRunErrorBalanceInsufficient {dreRequiredAmount :: !Amount, dreAvailableAmount :: !Amount}
    | -- | The energy supplied for the transaction is not sufficient to check the transaction
      -- header.
      DryRunErrorEnergyInsufficient {dreEnergyRequired :: !Energy}

-- | A successful result of a dry run execution.
-- These do not cover all successful results, just ones where the protobuf encoding cannot fail.
data DryRunSuccess
    = -- | The block state was loaded.
      DryRunSuccessBlockStateLoaded
        { -- | Current timestamp (taken from the block).
          drsCurrentTimestamp :: !Timestamp,
          -- | Block hash of the block the state was loaded from.
          drsBlockHash :: !BlockHash,
          -- | The protocol version determined by the block.
          drsProtocolVersion :: !ProtocolVersion
        }
    | -- | The account info was successfully retrieved.
      DryRunSuccessAccountInfo {drsAccountInfo :: !AccountInfo}
    | -- | The smart contract instance info was successfully retrieved.
      DryRunSuccessInstanceInfo {drsInstanceInfo :: !Wasm.InstanceInfo}
    | -- | The current timestamp was successfully set.
      DryRunSuccessTimestampSet
    | -- | The requested amount was minted to the account.
      DryRunSuccessMintedToAccount

-- | A wrapper type used to provide 'ToProto' instances that target DryRunResponse.
data DryRunResponse a = DryRunResponse
    { -- | The result of the operation.
      drrResponse :: !a,
      -- | The remaining energy after executing the operation.
      drrQuotaRemaining :: !Energy
    }
    deriving (Eq)

-- | Indicates that an account is pending -- either a scheduled release or a cooldown, depending on
--  the context -- and when the first release or cooldown will elapse.
data AccountPending = AccountPending
    { -- | Index of the account with pending scheduled release/cooldown.
      apAccountIndex :: !AccountIndex,
      -- | Timestamp of the first pending event for the account.
      apFirstTimestamp :: !Timestamp
    }
    deriving (Eq)
