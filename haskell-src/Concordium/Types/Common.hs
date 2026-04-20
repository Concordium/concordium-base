{-# LANGUAGE DerivingVia #-}

module Concordium.Types.Common (
    TransactionTime (..),
    TransactionExpiryTime,
    getTransactionTime,
    utcTimeToTransactionTime,
    transactionTimeToTimestamp,
    transactionExpired,
) where

import Concordium.Common.Time
import Data.Aeson (FromJSON, ToJSON)
import Data.Time (UTCTime, getCurrentTime)
import Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)
import Data.Word
import qualified Data.Serialize as S
import qualified Data.Serialize.Get as G
import qualified Data.Serialize.Put as P

-- | Time in seconds since the unix epoch
newtype TransactionTime = TransactionTime {ttsSeconds :: Word64}
    deriving (Show, Read, Eq, Num, Ord, Real, FromJSON, ToJSON, Enum, Integral) via Word64

instance S.Serialize TransactionTime where
    put = P.putWord64be . ttsSeconds
    get = TransactionTime <$> G.getWord64be

-- | Get time in seconds since the unix epoch.
getTransactionTime :: IO TransactionTime
getTransactionTime = utcTimeToTransactionTime <$> getCurrentTime

utcTimeToTransactionTime :: UTCTime -> TransactionTime
utcTimeToTransactionTime = floor . utcTimeToPOSIXSeconds

-- | Expiry time of a transaction in seconds since the epoch
type TransactionExpiryTime = TransactionTime

-- | Convert a 'TransactionTime' (seconds since epoch) to a
-- 'Timestamp' (milliseconds since epoch).
transactionTimeToTimestamp :: TransactionTime -> Timestamp
transactionTimeToTimestamp (TransactionTime x) = Timestamp (1000 * x)

-- | Check if a transaction expiry time precedes a given timestamp.
transactionExpired :: TransactionExpiryTime -> Timestamp -> Bool
transactionExpired (TransactionTime x) (Timestamp t) = 1000 * x < t
