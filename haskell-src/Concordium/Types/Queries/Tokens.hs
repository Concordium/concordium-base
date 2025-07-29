{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}

-- | Types for protocol level tokens (PLT).
module Concordium.Types.Queries.Tokens (
    TokenAmount (..),
    Token (..),
    TokenAccountState (..),
    TokenState (..),
    TokenInfo (..),
) where

import Data.Aeson as AE
import qualified Data.ByteString as BS
import Data.Maybe (catMaybes)
import Data.Word

import Concordium.Crypto.ByteStringHelpers
import Concordium.Types
import qualified Concordium.Types.ProtocolLevelTokens.CBOR as CBOR
import Concordium.Types.Tokens

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

-- | A wrapper type for (de)-serializing a CBOR-encoded 'TokenModuleAccountState'
--  to/from JSON. This can parse either a JSON object representation of 'TokenModuleAccountState'
--  (which is then re-encoded as CBOR) or a hex-encoded byte string. When rendering JSON,
--  it will render as a JSON object if the contents can be decded to a 'TokenModuleAccountState', or
--  otherwise as the hex-encoded byte string.
newtype EncodedTokenModuleAccountState = EncodedTokenModuleAccountState
    { encodedTokenModuleAccountState :: BS.ByteString
    }

instance ToJSON EncodedTokenModuleAccountState where
    toJSON (EncodedTokenModuleAccountState bs) =
        case CBOR.tokenModuleAccountStateFromBytes (BS.fromStrict bs) of
            Right state -> toJSON state
            Left _ -> toJSON (ByteStringHex bs)

instance FromJSON EncodedTokenModuleAccountState where
    parseJSON o@(Object _) = do
        state <- parseJSON o
        return $ EncodedTokenModuleAccountState $ CBOR.tokenModuleAccountStateToBytes state
    parseJSON val = do
        ByteStringHex bs <- parseJSON val
        return $ EncodedTokenModuleAccountState bs

-- | JSON instances for TokenAccountState
instance ToJSON TokenAccountState where
    toJSON (TokenAccountState balance moduleAccountState) =
        object $
            catMaybes
                [ Just ("balance" .= balance),
                  ("state" .=) . EncodedTokenModuleAccountState <$> moduleAccountState
                ]

instance FromJSON TokenAccountState where
    parseJSON = withObject "TokenAccountState" $ \o -> do
        balance <- o .: "balance"
        moduleAccountState <- fmap encodedTokenModuleAccountState <$> o .:? "state"
        return TokenAccountState{..}

-- | The global token state.
data TokenState = TokenState
    { -- | The reference of the module implementing the token.
      tsTokenModuleRef :: !TokenModuleRef,
      -- | The number of decimals in the token representation.
      tsDecimals :: !Word8,
      -- | The total available token supply.
      tsTotalSupply :: !TokenAmount,
      -- | CBOR-encoded module-specific state.
      tsModuleState :: !BS.ByteString
    }
    deriving (Eq, Show)

-- | A wrapper type for (de)-serializing a CBOR-encoded token module state to/from JSON.
--  This can parse either a JSON object representation of 'TokenModuleState'
--  (which is then re-encoded as CBOR) or a hex-encoded byte string. When rendering JSON,
--  it will render as a JSON object if the contents can be decoded to a
-- 'TokenModuleState', or otherwise as the hex-encoded byte string.
newtype EncodedTokenModuleState = EncodedTokenModuleState BS.ByteString
    deriving newtype (Eq, Show)

instance AE.ToJSON EncodedTokenModuleState where
    toJSON (EncodedTokenModuleState bytes) =
        case CBOR.tokenModuleStateFromBytes
            (BS.fromStrict bytes) of
            Left _ -> AE.toJSON (ByteStringHex bytes)
            Right v -> AE.toJSON v

instance AE.FromJSON EncodedTokenModuleState where
    parseJSON o@(AE.Object _) = do
        state <- AE.parseJSON o
        return $
            EncodedTokenModuleState $
                CBOR.tokenModuleStateToBytes state
    parseJSON val = do
        ByteStringHex bs <- AE.parseJSON val
        return (EncodedTokenModuleState bs)

-- | JSON instances for TokenState
instance ToJSON TokenState where
    toJSON (TokenState tsTokenModuleRef tsDecimals tsTotalSupply tsModuleState) =
        object
            [ "tokenModuleRef" .= tsTokenModuleRef,
              "decimals" .= tsDecimals,
              "totalSupply" .= tsTotalSupply,
              "moduleState" AE..= EncodedTokenModuleState tsModuleState
            ]

instance FromJSON TokenState where
    parseJSON = withObject "TokenState" $ \o -> do
        tsTokenModuleRef <- o .: "tokenModuleRef"
        tsDecimals <- o .: "decimals"
        tsTotalSupply <- o .: "totalSupply"
        (EncodedTokenModuleState tsModuleState) <- o AE..: "moduleState"
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
