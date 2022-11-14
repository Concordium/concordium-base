{-# LANGUAGE DerivingStrategies #-}

module Concordium.Common.Time where

import Control.Monad
import Data.Aeson
import Data.Proxy
import Data.Ratio ((%))
import qualified Data.Serialize as S
import qualified Data.Text as Text
import qualified Data.Text.Read as Text
import Data.Time
import Data.Time.Clock.POSIX
import Data.Word
import Database.Persist.Class
import Database.Persist.Sql

-- |YearMonth used store expiry (validTo) and creation (createdAt).
-- The year is in Gregorian calendar and months are numbered from 1, i.e.,
-- 1 is January, ..., 12 is December.
-- Year must be a 4 digit year, i.e., between 1000 and 9999.
data YearMonth = YearMonth
    { ymYear :: !Word16,
      ymMonth :: !Word8
    }
    deriving (Eq, Ord)

-- Show in compressed form of YYYYMM
instance Show YearMonth where
    show YearMonth{..} = show ymYear ++ (if ymMonth < 10 then ("0" ++ show ymMonth) else (show ymMonth))

instance S.Serialize YearMonth where
    put YearMonth{..} =
        S.putWord16be ymYear
            <> S.putWord8 ymMonth
    get = do
        ymYear <- S.getWord16be
        unless (ymYear >= 1000 && ymYear < 10000) $ fail "Year must be 4 digits exactly."
        ymMonth <- S.getWord8
        unless (ymMonth >= 1 && ymMonth <= 12) $ fail "Month must be between 1 and 12 inclusive."
        return YearMonth{..}

instance ToJSON YearMonth where
    toJSON ym = String (Text.pack (show ym))

instance FromJSON YearMonth where
    parseJSON = withText "YearMonth" $ \v -> do
        unless (Text.length v == 6) $ fail "YearMonth value must be exactly 6 characters."
        let (year, month) = Text.splitAt 4 v
        let eyear = Text.decimal year
        let emonth = Text.decimal month
        case eyear of
            Left err -> fail $ "Year not a valid numeric value: " ++ err
            Right (ymYear, rest) -> do
                unless (Text.null rest && ymYear >= 1000 && ymYear <= 10000) $ fail "Year not valid."
                case emonth of
                    Left err -> fail $ "Month not a valid numeric value: " ++ err
                    Right (ymMonth, rest') -> do
                        unless (Text.null rest' && ymMonth >= 1 && ymMonth <= 12) $ fail "Month not within range."
                        return YearMonth{..}

-- | Time in milliseconds since the epoch
newtype Timestamp = Timestamp {tsMillis :: Word64}
    deriving newtype (Show, Read, Eq, Num, Ord, Real, Enum, S.Serialize, FromJSON, ToJSON, Integral, PersistField)

instance PersistFieldSql Timestamp where
    {-# INLINE sqlType #-}
    sqlType Proxy = sqlType (Proxy :: Proxy Word64)

-- | Time duration in milliseconds
newtype Duration = Duration {durationMillis :: Word64}
    deriving newtype (Show, Read, Eq, Num, Ord, Real, Enum, Bounded, S.Serialize, FromJSON, ToJSON)

-- | Convert a 'Timestamp' to a 'UTCTime'
timestampToUTCTime :: Timestamp -> UTCTime
timestampToUTCTime ts = posixSecondsToUTCTime $ fromIntegral (tsMillis ts) / 1000

-- | Covert a 'UTCTime' to a 'Timestamp'.
-- This rounds down to the nearest millisecond.
utcTimeToTimestamp :: UTCTime -> Timestamp
utcTimeToTimestamp = Timestamp . truncate . (* 1000) . utcTimeToPOSIXSeconds

-- | Convert a 'Timestamp' to seconds since the epoch, rounding down
timestampToSeconds :: Timestamp -> Word64
timestampToSeconds ts = tsMillis ts `div` 1000

durationToNominalDiffTime :: Duration -> NominalDiffTime
durationToNominalDiffTime dur = fromRational (toInteger (durationMillis dur) % 1000)

addDuration :: Timestamp -> Duration -> Timestamp
addDuration (Timestamp ts) (Duration d) = Timestamp (ts + d)

-- | Time duration in seconds
newtype DurationSeconds = DurationSeconds {durationSeconds :: Word64}
    deriving newtype (Show, Read, Eq, Num, Ord, Real, Enum, Bounded, S.Serialize, FromJSON, ToJSON)

addDurationSeconds :: Timestamp -> DurationSeconds -> Timestamp
addDurationSeconds (Timestamp ts) (DurationSeconds d) = Timestamp (ts + d * 1000)

-- |Check if whether the given timestamp is no greater than the end of the day
-- of the given year and month.
isTimestampBefore :: Timestamp -> YearMonth -> Bool
isTimestampBefore ts ym =
    utcTs < utcYearMonthExpiryTs
  where
    utcTs = timestampToUTCTime ts
    utcYearMonthExpiryTs = UTCTime expiryDay 0
      where
        year = toInteger (ymYear ym)
        month = fromIntegral (ymMonth ym)
        expiryYear = if month == 12 then year + 1 else year
        expiryMonth = if month == 12 then 1 else month + 1 -- (month % 12) + 1
        expiryDay = fromGregorian expiryYear expiryMonth 1 -- unchecked, always valid
