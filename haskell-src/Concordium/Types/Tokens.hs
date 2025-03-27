-- | Types for protocol level tokens (PLT).
module Concordium.Types.Tokens where

import qualified Data.Text as T
import Data.Word

-- | The unique token identifier. This is given as a symbol unique across the
--  whole chain.
newtype TokenId = TokenId {symbol :: T.Text} deriving (Eq, Show)

-- | The token amount representation.
--  The amount is computed as `amount = digits * 10^(-nrDecimals)`.
data TokenAmount = TokenAmount
    { digits :: !Word64,
      nrDecimals :: !Word32
    }
    deriving (Eq, Show)

-- | Protocol level token.
data Token = Token
    { -- | The unique token identifier.
      tokenId :: !TokenId,
      -- | The account level state of the token.
      tokenAccountState :: !TokenAccountState
    }
    deriving (Eq, Show)

-- | The account level state of a token.
data TokenAccountState = TokenAccountState
    { -- | The available token balance.
      balance :: !TokenAmount,
      -- | Whether the account is a member of the allow list of the token.
      -- If present, tokens can be transferred only, if both sender and receiver are
      -- members of the allow list of the token.
      memberAllowList :: !Bool,
      -- | Whether the account is a member of the deny list of the token.
      -- If present, tokens can be transferred only, if neither sender or receiver
      -- are members of the deny list.
      memberDenyList :: !Bool
    }
    deriving (Eq, Show)
