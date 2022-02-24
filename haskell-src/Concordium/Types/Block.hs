{-# LANGUAGE DerivingStrategies #-}
-- |Types related to blocks
module Concordium.Types.Block where

import Data.Aeson
import Data.Hashable (Hashable)
import Data.Proxy
import Data.Word
import Database.Persist.Class
import Database.Persist.Sql
import qualified Data.Serialize as S

-- *Types that are morally part of the consensus, but need to be exposed in
-- other parts of the system as well, e.g., in smart contracts.

newtype Slot = Slot {theSlot :: Word64} deriving newtype (Eq, Ord, Num, Real, Enum, Integral, Show, Read, S.Serialize, FromJSON, ToJSON)

-- |The slot number of the genesis block (0).
genesisSlot :: Slot
genesisSlot = 0

type EpochLength = Slot

-- |Index of an epoch, or number of epochs.
type Epoch = Word64

-- |Length of a reward period in epochs.
newtype RewardPeriodLength = RewardPeriodLength {rewardPeriodEpochs :: Epoch}
  deriving newtype (Eq, Ord, Num, Real, Enum, Integral, Show, Read, S.Serialize, FromJSON, ToJSON)

-- |Block height relative to the genesis block on the block's chain.
-- In the event of a protocol update, a new chain is created with the new genesis block having
-- 'BlockHeight' 0.
newtype BlockHeight = BlockHeight {theBlockHeight :: Word64}
  deriving newtype (Eq, Ord, Num, Real, Enum, Integral, Read, Show, Hashable, FromJSON, ToJSON, PersistField)

instance PersistFieldSql BlockHeight where
  sqlType _ = sqlType (Proxy :: Proxy Word64)

instance S.Serialize BlockHeight where
  put = S.putWord64be . theBlockHeight
  get = BlockHeight <$> S.getWord64be

-- |Block height relative to the initial genesis block.
-- In the event of a protocol update, the regenesis block will have absolute height 1 greater than
-- the last finalized block of the preceding chain.
newtype AbsoluteBlockHeight = AbsoluteBlockHeight {theAbsoluteBlockHeight :: Word64}
  deriving newtype (Eq, Ord, Num, Real, Enum, Integral, Read, Show, Hashable, FromJSON, ToJSON, PersistField)

instance PersistFieldSql AbsoluteBlockHeight where
  sqlType _ = sqlType (Proxy :: Proxy Word64)

instance S.Serialize AbsoluteBlockHeight where
  put = S.putWord64be . theAbsoluteBlockHeight
  get = AbsoluteBlockHeight <$> S.getWord64be

-- |Convert a 'BlockHeight' to an 'AbsoluteBlockHeight' given the height of the genesis block.
localToAbsoluteBlockHeight ::
  AbsoluteBlockHeight
  -- ^Genesis block height
  -> BlockHeight
  -- ^Block height relative to genesis
  -> AbsoluteBlockHeight
localToAbsoluteBlockHeight genesisHeight bh = genesisHeight + fromIntegral bh

-- |Convert an 'AbsoluteBlockHeight' to a 'BlockHeight' given the height of the genesis block.
-- This returns 'Nothing' if the height of the block is less than the height of the genesis block.
absoluteToLocalBlockHeight ::
  AbsoluteBlockHeight
  -- ^Genesis block height
  -> AbsoluteBlockHeight
  -- ^Block height
  -> Maybe BlockHeight
absoluteToLocalBlockHeight genesisHeight abh
  | genesisHeight <= abh = Just $ absoluteToLocalBlockHeightUnchecked genesisHeight abh
  | otherwise = Nothing

-- |Convert an 'AbsoluteBlockHeight' to a 'BlockHeight' given the height of the genesis block.
-- This does not check that the height of the block is less than the height of the genesis block,
-- and the result is invalid if that check fails.
absoluteToLocalBlockHeightUnchecked ::
  AbsoluteBlockHeight
  -- ^Genesis block height
  -> AbsoluteBlockHeight
  -- ^Block height
  -> BlockHeight
absoluteToLocalBlockHeightUnchecked genesisHeight abh = fromIntegral (abh - genesisHeight)

-- |Limit on the number of credentials that may occur in a block.
type CredentialsPerBlockLimit = Word16
