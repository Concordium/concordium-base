{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}

-- |Types for representing the results of consensus queries.
module Concordium.Types.Queries where

import Data.Aeson
import Data.Aeson.TH
import Data.Aeson.Types (Parser)
import Data.Char (isLower)
import qualified Data.Map as Map
import qualified Data.Sequence as Seq
import Data.Time (UTCTime)
import qualified Data.Vector as Vec

import Concordium.Types
import Concordium.Types.Block
import Concordium.Types.Execution (TransactionSummary)
import Concordium.Types.Transactions (SpecialTransactionOutcome)
import Concordium.Types.UpdateQueues (Updates)
import Concordium.Utils

-- |Result type for @getConsensusStatus@ queries.  A number of fields are not defined when no blocks
-- have so far been received, verified or finalized. In such cases, the values will be 'Nothing'.
--
-- The JSON serialization of this structure is as an object, with fields named as in the record,
-- but without the "cs" prefix, and the first letter in lowercase.
data ConsensusStatus = ConsensusStatus
    { -- |Hash of the current best block
      csBestBlock :: !BlockHash,
      -- |Hash of the (original) genesis block
      csGenesisBlock :: !BlockHash,
      -- |Time of the (original) genesis block
      csGenesisTime :: !UTCTime,
      -- |(Current) slot duration in milliseconds
      csSlotDuration :: !Duration,
      -- |(Current) epoch duration in milliseconds
      csEpochDuration :: !Duration,
      -- |Hash of the last finalized block
      csLastFinalizedBlock :: !BlockHash,
      -- |Absolute height of the best block
      csBestBlockHeight :: !AbsoluteBlockHeight,
      -- |Absolute height of the last finalized block
      csLastFinalizedBlockHeight :: !AbsoluteBlockHeight,
      -- |Total number of blocks received
      csBlocksReceivedCount :: !Int,
      -- |The last time a block was received
      csBlockLastReceivedTime :: !(Maybe UTCTime),
      -- |Moving average latency between a block's slot time and received time
      csBlockReceiveLatencyEMA :: !Double,
      -- |Standard deviation of moving average latency between a block's slot time and received time
      csBlockReceiveLatencyEMSD :: !Double,
      -- |Moving average time between receiving blocks
      csBlockReceivePeriodEMA :: !(Maybe Double),
      -- |Standard deviation of moving average time between receiving blocks
      csBlockReceivePeriodEMSD :: !(Maybe Double),
      -- |Total number of blocks received and verified
      csBlocksVerifiedCount :: !Int,
      -- |The last time a block was verified (added to the tree)
      csBlockLastArrivedTime :: !(Maybe UTCTime),
      -- |Moving average latency between a block's slot time and its arrival
      csBlockArriveLatencyEMA :: !Double,
      -- |Standard deviation of moving average latency between a block's slot time and its arrival
      csBlockArriveLatencyEMSD :: !Double,
      -- |Moving average time between block arrivals
      csBlockArrivePeriodEMA :: !(Maybe Double),
      -- |Standard deviation of moving average time between block arrivals
      csBlockArrivePeriodEMSD :: !(Maybe Double),
      -- |Moving average number of transactions per block
      csTransactionsPerBlockEMA :: !Double,
      -- |Standard deviation of moving average number of transactions per block
      csTransactionsPerBlockEMSD :: !Double,
      -- |Number of finalizations
      csFinalizationCount :: !Int,
      -- |Time of last verified finalization
      csLastFinalizedTime :: !(Maybe UTCTime),
      -- |Moving average time between finalizations
      csFinalizationPeriodEMA :: !(Maybe Double),
      -- |Standard deviation of moving average time between finalizations
      csFinalizationPeriodEMSD :: !(Maybe Double),
      -- |Currently active protocol version.
      csProtocolVersion :: !ProtocolVersion,
      -- |The number of chain restarts via a protocol update. An effected
      -- protocol update instruction might not change the protocol version
      -- specified in the previous field, but it always increments the genesis
      -- index.
      csGenesisIndex :: !GenesisIndex,
      -- |Block hash of the genesis block of current era, i.e., since the last protocol update.
      -- Initially this is equal to 'csGenesisBlock'.
      csCurrentEraGenesisBlock :: !BlockHash,
      -- |Time when the current era started.
      csCurrentEraGenesisTime :: !UTCTime
    }
    deriving (Show)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''ConsensusStatus)

-- |Result type for @getBranches@ query. A 'Branch' consists of the hash of a block and 'Branch'es
-- for each child of the block.
data Branch = Branch
    { -- |Block hash
      branchBlockHash :: !BlockHash,
      -- |Child branches
      branchChildren :: ![Branch]
    }
    deriving (Eq, Ord, Show)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''Branch)

-- |Result type for @getNextAccountNonce@ query.
-- If all account transactions are finalized then this information is reliable.
-- Otherwise this is the best guess, assuming all other transactions will be
-- committed to blocks and eventually finalized.
data NextAccountNonce = NextAccountNonce
    { -- |The next account nonce
      nanNonce :: !Nonce,
      -- |True if all transactions on the account are finalized
      nanAllFinal :: !Bool
    }
    deriving (Show)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''NextAccountNonce)

-- |Result type for @getBlockInfo@ query.
data BlockInfo = BlockInfo
    { -- |The block hash
      biBlockHash :: !BlockHash,
      -- |The parent block hash. For a re-genesis block, this will be the terminal block of the
      -- previous chain. For the initial genesis block, this will be the hash of the block itself.
      biBlockParent :: !BlockHash,
      -- |The last finalized block when this block was baked
      biBlockLastFinalized :: !BlockHash,
      -- |The height of this block
      biBlockHeight :: !AbsoluteBlockHeight,
      -- |The genesis index for this block. This counts the number of protocol updates that have
      -- preceded this block, and defines the era of the block.
      biGenesisIndex :: !GenesisIndex,
      -- |The height of this block relative to the (re)genesis block of its era.
      biEraBlockHeight :: !BlockHeight,
      -- |The time the block was received
      biBlockReceiveTime :: !UTCTime,
      -- |The time the block was verified
      biBlockArriveTime :: !UTCTime,
      -- |The slot number in which the block was baked
      biBlockSlot :: !Slot,
      -- |The time of the slot in which the block was baked
      biBlockSlotTime :: !UTCTime,
      -- |The identifier of the block baker, or @Nothing@ for a
      -- genesis block.
      biBlockBaker :: !(Maybe BakerId),
      -- |Whether the block is finalized
      biFinalized :: !Bool,
      -- |The number of transactions in the block
      biTransactionCount :: !Int,
      -- |The energy cost of the transaction in the block
      biTransactionEnergyCost :: !Energy,
      -- |The size of the transactions
      biTransactionsSize :: !Int,
      -- |The hash of the block state
      biBlockStateHash :: !StateHash
    }
    deriving (Show)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''BlockInfo)

-- |Details of a party in a finalization.
data FinalizationSummaryParty = FinalizationSummaryParty
    { -- |The identity of the baker
      fspBakerId :: !BakerId,
      -- |The party's relative weight in the committee
      fspWeight :: !Integer,
      -- |Whether the party's signature is present
      fspSigned :: !Bool
    }
    deriving (Show)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''FinalizationSummaryParty)

-- |Details of a finalization record.
data FinalizationSummary = FinalizationSummary
    { -- |Hash of the finalized block
      fsFinalizationBlockPointer :: !BlockHash,
      -- |Index of the finalization
      fsFinalizationIndex :: !FinalizationIndex,
      -- |Finalization delay value
      fsFinalizationDelay :: !BlockHeight,
      -- |The finalization committee
      fsFinalizers :: !(Vec.Vector FinalizationSummaryParty)
    }
    deriving (Show)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''FinalizationSummary)

-- |Detailed information about a block.
data BlockSummary = forall pv.
      IsProtocolVersion pv =>
    BlockSummary
    { -- |Details of transactions in the block
      bsTransactionSummaries :: !(Vec.Vector TransactionSummary),
      -- |Details of special events in the block
      bsSpecialEvents :: !(Seq.Seq SpecialTransactionOutcome),
      -- |Details of the finalization record in the block (if any)
      bsFinalizationData :: !(Maybe FinalizationSummary),
      -- |Details of the update queues and chain parameters as of the block
      bsUpdates :: !(Updates pv)
    }

instance Show BlockSummary where
    showsPrec prec BlockSummary{bsUpdates = bsUpdates :: Updates pv, ..} = do
        showParen (prec > 11) $
            showString "BlockSummary @"
                . showsPrec 11 (demoteProtocolVersion (protocolVersion @pv))
                . showString " {bsTransactionSummaries = "
                . showsPrec 0 bsTransactionSummaries
                . showString ",bsSpecialEvents = "
                . showsPrec 0 bsSpecialEvents
                . showString ",bsFinalizationData = "
                . showsPrec 0 bsFinalizationData
                . showString ",bsUpdates = "
                . showsPrec 0 bsUpdates
                . showString "}"

instance ToJSON BlockSummary where
    toJSON BlockSummary{bsUpdates = bsUpdates :: Updates pv, ..} =
        object
            [ "transactionSummaries" .= bsTransactionSummaries,
              "specialEvents" .= bsSpecialEvents,
              "finalizationData" .= bsFinalizationData,
              "updates" .= bsUpdates,
              "protocolVersion" .= demoteProtocolVersion (protocolVersion @pv)
            ]

instance FromJSON BlockSummary where
    parseJSON =
        withObject "BlockSummary" $ \v -> do
            version <- v .: "protocolVersion"
            case version of
                P1 -> parse SP1 v
                P2 -> parse SP2 v
                P3 -> parse SP3 v
                P4 -> parse SP4 v
      where
        parse :: forall pv. IsProtocolVersion pv => SProtocolVersion pv -> Object -> Parser BlockSummary
        parse _ v =
            BlockSummary
                <$> v .: "transactionSummaries"
                <*> v .: "specialEvents"
                <*> v .: "finalizationData"
                <*> (v .: "updates" :: Parser (Updates pv))

data RewardStatus = RewardStatus
    { -- |The total GTU in existence
      rsTotalAmount :: !Amount,
      -- |The total GTU in encrypted balances
      rsTotalEncryptedAmount :: !Amount,
      -- |The amount in the baking reward account
      rsBakingRewardAccount :: !Amount,
      -- |The amount in the finalization reward account
      rsFinalizationRewardAccount :: !Amount,
      -- |The amount in the GAS account
      rsGasAccount :: !Amount
    }
    deriving (Show)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''RewardStatus)

-- |Summary of a baker.
data BakerSummary = BakerSummary
    { -- |Baker ID
      bsBakerId :: !BakerId,
      -- |(Approximate) lottery power
      bsBakerLotteryPower :: !Double,
      -- |Baker account (should never be @Nothing@)
      bsBakerAccount :: !(Maybe AccountAddress)
    }
    deriving (Show)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''BakerSummary)

-- |Summary of the birk parameters applicable to a particular block.
data BlockBirkParameters = BlockBirkParameters
    { -- |Baking lottery election difficulty
      bbpElectionDifficulty :: !ElectionDifficulty,
      -- |Current leadership election nonce for the lottery
      bbpElectionNonce :: !LeadershipElectionNonce,
      -- |List of the currently eligible bakers
      bbpBakers :: !(Vec.Vector BakerSummary)
    }
    deriving (Show)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''BlockBirkParameters)

-- |The status of a transaction that is present in the transaction table.
data TransactionStatus
    = -- |Transaction was received but is not in any blocks
      Received
    | -- |Transaction was received and is present in some (non-finalized) block(s)
      Committed (Map.Map BlockHash (Maybe TransactionSummary))
    | -- |Transaction has been finalized in a block
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

-- |The status of a transaction with respect to a specified block
data BlockTransactionStatus
    = -- |Either the transaction is not in that block, or that block is not live
      BTSNotInBlock
    | -- |The transaction was received but not known to be in that block
      BTSReceived
    | -- |The transaction is in that (non-finalized) block
      BTSCommitted (Maybe TransactionSummary)
    | -- |The transaction is in that (finalized) block
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
