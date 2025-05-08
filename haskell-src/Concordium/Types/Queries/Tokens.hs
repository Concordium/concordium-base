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
import Data.Aeson as AE
import qualified Data.ByteString.Base16 as BS16
import qualified Data.Text.Encoding as Text

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
      tsDecimals :: !Word32,
      -- | The total available token supply.
      tsTotalSupply :: !TokenAmount,
      -- | CBOR-encoded module-specific state.
      tsModuleState :: !BS.ByteString
    }
    deriving (Eq, Show)

-- Nice-to-have: Use a wrapper for dispalying the decoded CBOR representation instead of displaying the bytes as a hex string.
newtype HexByteString = HexByteString {_unHex :: BS.ByteString}

instance ToJSON HexByteString where
    toJSON (HexByteString bs) =
        String (Text.decodeUtf8 (BS16.encode bs))

instance FromJSON HexByteString where
    parseJSON = AE.withText "HexByteString" $ \txt ->
        case BS16.decode (Text.encodeUtf8 txt) of
            Right bs -> pure $ HexByteString bs
            _ -> fail "Invalid Base16 encoding"

-- | JSON instances for TokenState
instance ToJSON TokenState where
    toJSON (TokenState tsTokenModuleRef tsIssuer tsDecimals tsTotalSupply tsModuleState) =
        object
            [ "tokenId" .= tsTokenModuleRef,
              "issuer" .= tsIssuer,
              "decimals" .= tsDecimals,
              "totalSupply" .= tsTotalSupply,
              "moduleState" .= HexByteString tsModuleState
            ]

instance FromJSON TokenState where
    parseJSON = withObject "TokenState" $ \o -> do
        tsTokenModuleRef <- o .: "tokenId"
        tsIssuer <- o .: "issuer"
        tsDecimals <- o .: "decimals"
        tsTotalSupply <- o .: "totalSupply"
        (HexByteString tsModuleState) <- o .: "moduleState"
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
