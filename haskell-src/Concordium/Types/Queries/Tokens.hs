-- | Types for protocol level tokens (PLT).
module Concordium.Types.Queries.Tokens (
    TokenAmount (..),
    Token (..),
    TokenAccountState (..),
    TokenState (..),
    TokenInfo (..),
) where

import qualified Data.ByteString as BS
import Data.Word

import Concordium.Types
import Concordium.Types.Tokens

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

-- | The global token state.
data TokenState = TokenState
    { -- | The reference of the module implementing the token.
      tsTokenModuleRef :: !TokenModuleRef,
      -- | The governance account for the token.
      tsIssuer :: !AccountAddress,
      -- | The number of decimals in the token representation.
      tsDecimals :: !Word8,
      -- | The total available token supply.
      tsTotalSupply :: !TokenAmount,
      -- | CBOR-encoded module-specific state.
      tsModuleState :: !BS.ByteString
    }
    deriving (Eq, Show)

-- | The global info about a protocol-level token.
data TokenInfo = TokenInfo
    { -- | The symbol uniquely identifying the protocol-level token.
      tiTokenId :: TokenId,
      -- | The global state of the token.
      tiTokenState :: TokenState
    }
    deriving (Eq, Show)
