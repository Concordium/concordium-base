module Concordium.Types.Queries.Locks (
    LockInfo (..),
) where

import qualified Data.ByteString as BS

-- | Result of a `GetLockInfo` query.
-- The payload is the raw CBOR encoding of the `lock-info` structure.
data LockInfo = LockInfo
    { -- | The CBOR encoded lock-info payload.
      liLockInfo :: !BS.ByteString
    }
