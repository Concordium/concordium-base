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
import Data.Maybe (catMaybes)
import Data.Word

import Concordium.Crypto.ByteStringHelpers
import Concordium.Types
import Concordium.Types.Tokens
import Data.Aeson

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
      -- | The token-module specific state for the account.
      --  This is CBOR-encoded.
      moduleAccountState :: !(Maybe BS.ByteString)
    }
    deriving (Eq, Show)

-- | JSON instances for TokenAccountState
instance ToJSON TokenAccountState where
    toJSON (TokenAccountState balance moduleAccountState) =
        object $
            catMaybes
                [ Just ("balance" .= balance),
                  ("state" .=) . ByteStringHex <$> moduleAccountState
                ]

instance FromJSON TokenAccountState where
    parseJSON = withObject "TokenAccountState" $ \o -> do
        balance <- o .: "balance"
        moduleAccountState <- fmap hex <$> o .:? "state"
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

-- | JSON instances for TokenState
instance ToJSON TokenState where
    toJSON (TokenState tsTokenModuleRef tsIssuer tsDecimals tsTotalSupply tsModuleState) =
        object
            [ "tokenModuleRef" .= tsTokenModuleRef,
              "issuer" .= tsIssuer,
              "decimals" .= tsDecimals,
              "totalSupply" .= tsTotalSupply,
              "moduleState" .= ByteStringHex tsModuleState
            ]

instance FromJSON TokenState where
    parseJSON = withObject "TokenState" $ \o -> do
        tsTokenModuleRef <- o .: "tokenModuleRef"
        tsIssuer <- o .: "issuer"
        tsDecimals <- o .: "decimals"
        tsTotalSupply <- o .: "totalSupply"
        (ByteStringHex tsModuleState) <- o .: "moduleState"
        return TokenState{..}

-- | The global info about a protocol-level token.
data TokenInfo = TokenInfo
    { -- | The symbol uniquely identifying the protocol-level token.
      tiTokenId :: TokenId,
      -- | The global state of the token.
      tiTokenState :: TokenState
    }
    deriving (Eq, Show)

-- | JSON instances for TokenInfo
instance ToJSON TokenInfo where
    toJSON (TokenInfo tiTokenId tiTokenState) =
        object
            [ "tokenId" .= tiTokenId,
              "tokenState" .= tiTokenState
            ]

instance FromJSON TokenInfo where
    parseJSON = withObject "TokenInfo" $ \o -> do
        tiTokenId <- o .: "tokenId"
        tiTokenState <- o .: "tokenState"
        return TokenInfo{..}
