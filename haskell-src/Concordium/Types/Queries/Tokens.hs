{-# LANGUAGE OverloadedStrings #-}

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
import Data.Aeson (FromJSON (..), ToJSON (..), object, withObject, (.:), (.=))

-- | Protocol level token.
data Token = Token
    { -- | The unique token identifier.
      tokenId :: !TokenId,
      -- | The account level state of the token.
      tokenAccountState :: !TokenAccountState
    }
    deriving (Eq, Show)

-- | JSON instances for Token
instance ToJSON Token where
    toJSON (Token tid state) =
        object
            [ "tokenId" .= tid,
              "tokenAccountState" .= state
            ]

instance FromJSON Token where
    parseJSON = withObject "Token" $ \o -> do
        tokenId <- o .: "tokenId"
        tokenAccountState <- o .: "tokenAccountState"
        return Token{..}

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

-- | JSON instances for TokenAccountState
instance ToJSON TokenAccountState where
    toJSON (TokenAccountState balance inAllowList inDenyList) =
        object
            [ "balance" .= balance,
              "inAllowList" .= inAllowList,
              "inDenyList" .= inDenyList
            ]

instance FromJSON TokenAccountState where
    parseJSON = withObject "TokenAccountState" $ \o -> do
        balance <- o .: "balance"
        memberAllowList <- o .: "inAllowList"
        memberDenyList <- o .: "inDenyList"
        return TokenAccountState{..}

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
