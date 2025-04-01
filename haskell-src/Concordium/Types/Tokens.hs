module Concordium.Types.Tokens where

import Data.Word
import qualified Data.Map.Strict as M 
import qualified Data.ByteString as B
import qualified Data.ByteString.Short as BS

-- The index in the account token table.
newtype TokenIndex = TokenIndex Word64

-- A token amount. The encoding is  VLQ/ULEB128 (TODO: tbd)
newtype TokenAmount = TokenAmount Word64

-- The token state at the account level. 
data TokenState = TokenState {
  tsSymbol :: !BS.ShortByteString,
  tsBalance :: !TokenAmount,
  tsKVMap :: !(M.Map B.ByteString B.ByteString) 
}
