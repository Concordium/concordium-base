module Concordium.Genesis.Data.Base where

import Concordium.Types
import Concordium.Types.Parameters

-- |A class that provides access to fields of genesis data that
-- are expected to be stable across versions.
class BasicGenesisData gd where
    -- |The genesis time.
    gdGenesisTime :: gd -> Timestamp

    -- |The duration of a slot.
    gdSlotDuration :: gd -> Duration

    -- |The maximum energy per block.
    gdMaxBlockEnergy :: gd -> Energy

    -- |The finalization parameters.
    gdFinalizationParameters :: gd -> FinalizationParameters

    -- |The epoch length in slots
    gdEpochLength :: gd -> EpochLength
