{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}

module Concordium.Types.Accounts.CooldownQueue where

import qualified Data.Bits as Bits
import Data.Bool.Singletons
import qualified Data.Map.Strict as Map
import Data.Maybe
import Data.Serialize
import Data.Word

import Concordium.Types

-- | Records when a cooldown will expire.
data CooldownTime
    = -- | In active cooldown. Timestamp must be less than 2^63
      CooldownTimestamp !Timestamp
    | -- | Will enter cooldown at next epoch, with the specified cooldown expiry timestamp.
      --  Timestamp must be less than 2^62 - 1
      PreCooldownTS !Timestamp
    | -- | Will enter cooldown at next epoch, with the cooldown determined by the cooldown duration.
      PreCooldown
    | -- | Will enter cooldown at payday after next epoch, with the specified cooldown expiry
      --  timestamp. Timestamp must be less than 2^62 - 1
      PrePreCooldownTS !Timestamp
    | -- | Will enter cooldown at payday after next epoch, with the cooldown determined by the
      -- cooldown duration.
      PrePreCooldown
    deriving (Eq, Ord, Show)

-- | This type encodes a `CooldownTime` as a 64-bit integer. The encoding is designed to preserve
--  the ordering. Note that not all timestamps are representable, but it should be over a hundred
--  million years before that becomes relevant.  The table below shows the coding:
--
--   +-----------------------+-----------------------------------------+
--   | @theCooldownTimeCode@ | `CooldownTime`                          |
--   +=======================+=========================================+
--   | @0x0000000000000000@  | @CooldownTimestamp 0x0000000000000000@  |
--   +-----------------------+-----------------------------------------+
--   | ...                   | ...                                     |
--   +-----------------------+-----------------------------------------+
--   | @0x7fffffffffffffff@  | @CooldownTimestamp 0x7fffffffffffffff@  |
--   +-----------------------+-----------------------------------------+
--   | @0x8000000000000000@  | @PreCooldownTS 0x0000000000000000@      |
--   +-----------------------+-----------------------------------------+
--   | ...                   | ...                                     |
--   +-----------------------+-----------------------------------------+
--   | @0xbffffffffffffffe@  | @PreCooldownTS 0x3ffffffffffffffe@      |
--   +-----------------------+-----------------------------------------+
--   | @0xbfffffffffffffff@  | @PreCooldown@                           |
--   +-----------------------+-----------------------------------------+
--   | @0xc000000000000000@  | @PrePreCooldownTS 0x0000000000000000@   |
--   +-----------------------+-----------------------------------------+
--   | ...                   | ...                                     |
--   +-----------------------+-----------------------------------------+
--   | @0xfffffffffffffffe@  | @PrePreCooldownTS 0x3ffffffffffffffe@   |
--   +-----------------------+-----------------------------------------+
--   | @0xffffffffffffffff@  | @PrePreCooldown@                        |
--   +-----------------------+-----------------------------------------+
newtype CooldownTimeCode = CooldownTimeCode {theCooldownTimeCode :: Word64}
    deriving (Eq, Ord, Show)

-- | The highest 'CooldownTimeCode' that corresponds to a 'CooldownTimestamp'.
--  All lower codes will also correspond to 'CooldownTimestamp's.
maxCooldownTimestampCode :: CooldownTimeCode
maxCooldownTimestampCode = CooldownTimeCode 0x7fffffffffffffff

-- | Convert a 'CooldownTime' into the corresponding cooldown time.
--  This can result in an error if the 'CooldownTime' does not fall in the representable range.
encodeCooldownTime :: CooldownTime -> CooldownTimeCode
encodeCooldownTime (CooldownTimestamp ts)
    | ts < 0x8000000000000000 = CooldownTimeCode $ tsMillis ts
encodeCooldownTime (PreCooldownTS ts)
    | ts < 0x3fffffffffffffff = CooldownTimeCode $ tsMillis ts Bits..|. 0x8000000000000000
encodeCooldownTime PreCooldown = CooldownTimeCode 0xbfffffffffffffff
encodeCooldownTime (PrePreCooldownTS ts)
    | ts < 0x3fffffffffffffff = CooldownTimeCode $ tsMillis ts Bits..|. 0xc000000000000000
encodeCooldownTime PrePreCooldown = CooldownTimeCode 0xffffffffffffffff
encodeCooldownTime _ = error "CooldownTime is not representable"

-- | Convert a 'CooldownTimeCode' into the corresponding 'CooldownTime'.
decodeCooldownTime :: CooldownTimeCode -> CooldownTime
decodeCooldownTime (CooldownTimeCode code) =
    if Bits.testBit code 63
        then
            if Bits.testBit code 62
                then
                    if code == 0xffffffffffffffff
                        then PrePreCooldown
                        else PrePreCooldownTS . Timestamp $! code Bits..&. 0x3fffffffffffffff
                else
                    if code == 0xbfffffffffffffff
                        then PreCooldown
                        else PreCooldownTS . Timestamp $! code Bits..&. 0x3fffffffffffffff
        else CooldownTimestamp (Timestamp code)

instance Serialize CooldownTime where
    put = putWord64be . theCooldownTimeCode . encodeCooldownTime
    get = decodeCooldownTime . CooldownTimeCode <$> getWord64be

-- | A 'CooldownQueue' records the inactive stake amounts that are due to be released in future.
--  Note that prior to account version 3 (protocol version 7), the only value is the empty cooldown
--  queue.
data CooldownQueue (av :: AccountVersion) where
    -- | The empty cooldown queue.
    EmptyCooldownQueue :: CooldownQueue av
    -- | A non-empty cooldown queue.
    CooldownQueue ::
        (SupportsFlexibleCooldown av ~ 'True) =>
        -- | Entries in the map must be non-zero amounts, and the map must be non-empty.
        Map.Map CooldownTimeCode Amount ->
        CooldownQueue av

deriving instance Show (CooldownQueue av)
deriving instance Eq (CooldownQueue av)

instance forall av. (IsAccountVersion av) => Serialize (CooldownQueue av) where
    put = case sSupportsFlexibleCooldown (accountVersion @av) of
        SFalse -> const (return ())
        STrue -> \case
            EmptyCooldownQueue -> undefined
            CooldownQueue queue -> undefined
    get = undefined

emptyCooldownQueue :: CooldownQueue av
emptyCooldownQueue = EmptyCooldownQueue

-- | Process all cooldowns that expire at or before the given timestamp.
--  If there are no such cooldowns, then 'Nothing' is returned.
--  Otherwise, the total amount exiting cooldown and the remaining queue are returned.
processCooldowns :: Timestamp -> CooldownQueue av -> Maybe (Amount, CooldownQueue av)
processCooldowns _ EmptyCooldownQueue = Nothing
processCooldowns ts (CooldownQueue queue)
    | freeAmount == 0 = Nothing
    | otherwise = Just (freeAmount, remainder)
  where
    freeAmount = sum free + sum bonus
    (free, bonus, keep) = Map.splitLookup (encodeCooldownTime (CooldownTimestamp ts)) queue
    remainder
        | null keep = EmptyCooldownQueue
        | otherwise = CooldownQueue keep

-- | Move all pre-cooldowns into cooldown state. Where the pre-cooldown has a timestamp set, that
-- is used. Otherwise, the timestamp is used. This returns 'Nothing' if the queue would not be
-- changed, i.e. there are no pre-cooldowns.
-- Note, this will predominantly be used when there is at most one pre-cooldown, and it has no
-- timestamp set. Thus, this is not particularly optimized for other cases.
processPreCooldown :: Timestamp -> CooldownQueue av -> Maybe (CooldownQueue av)
processPreCooldown _ EmptyCooldownQueue = Nothing
processPreCooldown ts (CooldownQueue queue)
    | null precooldowns = Nothing
    | otherwise = Just . CooldownQueue $ Map.unionsWith (+) [cooldowns, newCooldowns, preprecooldowns]
  where
    (cooldowns, rest) = Map.spanAntitone (<= maxCooldownTimestampCode) queue
    (precooldowns, preprecooldowns) = Map.spanAntitone (<= encodeCooldownTime PreCooldown) rest
    newCooldowns = Map.mapKeysWith (+) f precooldowns
    f c@(CooldownTimeCode code)
        | c == encodeCooldownTime PreCooldown = CooldownTimeCode $ tsMillis ts
        | otherwise = CooldownTimeCode (Bits.clearBit code 63)

-- | Check if a 'CooldownQueue' is empty.
isCooldownQueueEmpty :: CooldownQueue av -> Bool
isCooldownQueueEmpty EmptyCooldownQueue = True
isCooldownQueueEmpty _ = False

-- | Get the next timestamp (if any) at which a cooldown is scheduled to elapse.
nextCooldownTime :: CooldownQueue av -> Maybe Timestamp
nextCooldownTime EmptyCooldownQueue = Nothing
nextCooldownTime (CooldownQueue queue) = case decodeCooldownTime minEntry of
    CooldownTimestamp ts -> Just ts
    _ -> Nothing
  where
    -- This is safe because 'CooldownQueue' requires @queue@ to be non-empty.
    (minEntry, _) = Map.findMin queue

-- | Check if a 'CooldownQueue' has any pre-cooldown entries.
hasPreCooldown :: CooldownQueue av -> Bool
hasPreCooldown EmptyCooldownQueue = False
hasPreCooldown (CooldownQueue queue) = case Map.lookupGT maxCooldownTimestampCode queue of
    Just (x, _) -> x <= encodeCooldownTime PreCooldown
    Nothing -> False

-- | Check if a 'CooldownQueue' has any pre-pre-cooldown entries.
hasPrePreCooldown :: CooldownQueue av -> Bool
hasPrePreCooldown EmptyCooldownQueue = False
hasPrePreCooldown (CooldownQueue queue) = isJust $ Map.lookupGT (encodeCooldownTime PreCooldown) queue
