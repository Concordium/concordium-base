{-# LANGUAGE TemplateHaskell #-}

-- |Types related to account releases
module Concordium.Types.Accounts.Releases where

import Data.Aeson
import Data.Aeson.TH
import Data.Char (isLower)

import Concordium.Types
import Concordium.Utils (firstLower)

-- |A 'ScheduledRelease' is an amount that will be made available on a given account at a given
-- time, together with the hashes of the transactions that contribute to the release.  A
-- 'ScheduledRelease' combines releases from multiple scheduled transfers if they occur at the
-- same instant.
data ScheduledRelease = ScheduledRelease
    { -- |The moment at which the amount is considered released.
      releaseTimestamp :: !Timestamp,
      -- |The amount to release.
      releaseAmount :: !Amount,
      -- |The transactions that contribute to this release.
      releaseTransactions :: ![TransactionHash]
    }
    deriving (Eq, Show)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''ScheduledRelease)

-- |A list of scheduled releases. The releases should be in order of increasing timestamp, and there
-- should be no more than one release at each timestamp. 'releaseTotal' should equal the sum of all
-- scheduled release amounts, i.e.
--
-- prop> releaseTotal == sum (releaseAmount <$> releaseSchedule)
data AccountReleaseSummary = AccountReleaseSummary
    { -- |The total locked amount.
      releaseTotal :: !Amount,
      -- |The scheduled releases.
      releaseSchedule :: ![ScheduledRelease]
    }
    deriving (Eq, Show)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . dropWhile isLower} ''AccountReleaseSummary)
