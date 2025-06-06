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
import qualified Data.ByteString.Builder as BSBuilder
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
      -- | Whether the account is a member of the allow list of the token.
      -- If present, tokens can be transferred only, if both sender and receiver are
      -- members of the allow list of the token.
      memberAllowList :: !(Maybe Bool),
      -- | Whether the account is a member of the deny list of the token.
      -- If present, tokens can be transferred only, if neither sender or receiver
      -- are members of the deny list.
      memberDenyList :: !(Maybe Bool)
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

-- | A wrapper type for (de)-serializing an CBOR-encoded token module state to/from JSON.
--  This can parse either an JSON object representation of 'TokenModuleState'
--  (which is then re-encoded as CBOR) or a hex-encoded byte string. When rendering JSON,
--  it will render as a JSON object if the contents can be decoded to a
-- 'TokenModuleState', or otherwise as the hex-encoded byte string.
newtype EncodedTokenModuleState = EncodedTokenModuleState BS.ByteString
    deriving newtype (Eq, Show)

instance AE.ToJSON EncodedTokenModuleState where
    toJSON (EncodedTokenModuleState bytes) =
        case CBOR.tokenModuleStateFromBytes
            (BSBuilder.toLazyByteString $ BSBuilder.byteString bytes) of
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
    toJSON (TokenState tsTokenModuleRef tsIssuer tsDecimals tsTotalSupply tsModuleState) =
        object
            [ "tokenModuleRef" .= tsTokenModuleRef,
              "issuer" .= tsIssuer,
              "decimals" .= tsDecimals,
              "totalSupply" .= tsTotalSupply,
              "moduleState" AE..= EncodedTokenModuleState tsModuleState
            ]

instance FromJSON TokenState where
    parseJSON = withObject "TokenState" $ \o -> do
        tsTokenModuleRef <- o .: "tokenModuleRef"
        tsIssuer <- o .: "issuer"
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
