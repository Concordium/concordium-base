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

-- |Index of an epoch.
type Epoch = Word64

newtype BlockHeight = BlockHeight {theBlockHeight :: Word64}
  deriving newtype (Eq, Ord, Num, Real, Enum, Integral, Read, Show, Hashable, FromJSON, ToJSON, PersistField)

instance PersistFieldSql BlockHeight where
  sqlType _ = sqlType (Proxy :: Proxy Word64)

instance S.Serialize BlockHeight where
  put = S.putWord64be . theBlockHeight
  get = BlockHeight <$> S.getWord64be

-- |Limit on the number of credentials that may occur in a block.
type CredentialsPerBlockLimit = Word16
