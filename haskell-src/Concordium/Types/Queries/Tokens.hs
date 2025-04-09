{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Types for protocol level tokens (PLT).
module Concordium.Types.Queries.Tokens where

import qualified Concordium.Crypto.ByteStringHelpers as ByteStringHelpers
import qualified Concordium.Crypto.SHA256 as SHA256
import qualified Concordium.Types as Types
import qualified Concordium.Types.HashableTo as HashableTo
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Types as Aeson
import qualified Data.ByteString.Short as BS
import qualified Data.Hashable as Hashable
import qualified Data.Serialize as Serialize
import qualified Data.Text.Encoding as Text
import Data.Word

-- | The unique token identifier. This is given as a symbol unique across the
--  whole chain.
newtype TokenId = TokenId {symbol :: BS.ShortByteString} deriving (Eq, Show)

instance Aeson.ToJSON TokenId where
    -- decodeUtf8 will throw an exception if it fails, but we should be safe since the TokenId
    -- should enforce valid UTF-8.
    toJSON TokenId{..} = Aeson.String $ Text.decodeUtf8 $ BS.fromShort symbol

instance Aeson.FromJSON TokenId where
    parseJSON (Aeson.String text) = return $ TokenId $ BS.toShort $ Text.encodeUtf8 text
    parseJSON invalid = Aeson.prependFailure "parsing TokenId failed" (Aeson.typeMismatch "String" invalid)

instance Serialize.Serialize TokenId where
    get = do
        len <- Serialize.getWord8
        TokenId <$> Serialize.getShortByteString (fromIntegral len)
    put (TokenId symbol) = do
        Serialize.putWord8 (fromIntegral (BS.length symbol))
        Serialize.putShortByteString symbol

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

-- | Parameter for a Token module.
newtype TokenParameter = TokenParameter {parameterBytes :: BS.ShortByteString}
    deriving (Eq)
    deriving (Aeson.ToJSON, Aeson.FromJSON, Show) via ByteStringHelpers.ByteStringHex

instance Serialize.Serialize TokenParameter where
    get = do
        len <- Serialize.getWord16be
        TokenParameter <$> Serialize.getShortByteString (fromIntegral len)
    put (TokenParameter parameter) = do
        Serialize.putWord16be (fromIntegral (BS.length parameter))
        Serialize.putShortByteString parameter

-- | Module reference for a token module.
newtype TokenModuleRef = TokenModuleRef {tokenModuleRef :: SHA256.Hash}
    deriving (Eq, Ord, Hashable.Hashable)
    deriving (Aeson.FromJSON, Aeson.ToJSON, Read, Show, Serialize.Serialize) via SHA256.Hash

-- | Update payload for creating a new protocol-level token.
data CreatePLT = CreatePLT
    { -- | The symbol of the token.
      tokenSymbol :: !TokenId,
      -- | A SHA256 hash that identifies the token module implementation.
      tokenModule :: !TokenModuleRef,
      -- | The address of the account that will govern the token.
      governanceAccount :: !Types.AccountAddress,
      -- | The number of decimal places used in the representation of amounts of this token. This determines the smallest representable fraction of the token.
      decimals :: !Word8,
      -- | The initialization parameters of the token, encoded in CBOR. This consists of the remaining bytes of the update payload.
      initializationParameters :: !TokenParameter
    }
    deriving (Eq, Show)

instance HashableTo.HashableTo SHA256.Hash CreatePLT where
    getHash = SHA256.hash . Serialize.encode

instance (Monad m) => HashableTo.MHashableTo m SHA256.Hash CreatePLT

instance Serialize.Serialize CreatePLT where
    put CreatePLT{..} = do
        Serialize.put tokenSymbol
        Serialize.put tokenModule
        Serialize.put governanceAccount
        Serialize.put decimals
        Serialize.put initializationParameters
    get = do
        tokenSymbol <- Serialize.get
        tokenModule <- Serialize.get
        governanceAccount <- Serialize.get
        decimals <- Serialize.get
        initializationParameters <- Serialize.get
        return CreatePLT{..}

instance Aeson.ToJSON CreatePLT where
    toJSON CreatePLT{..} =
        Aeson.object
            [ "tokenSymbol" Aeson..= tokenSymbol,
              "tokenModule" Aeson..= tokenModule,
              "governanceAccount" Aeson..= governanceAccount,
              "decimals" Aeson..= decimals,
              "initializationParameters" Aeson..= initializationParameters
            ]

instance Aeson.FromJSON CreatePLT where
    parseJSON = Aeson.withObject "CreatePLT" $ \o -> do
        tokenSymbol <- o Aeson..: "tokenSymbol"
        tokenModule <- o Aeson..: "tokenModule"
        governanceAccount <- o Aeson..: "governanceAccount"
        decimals <- o Aeson..: "decimals"
        initializationParameters <- o Aeson..: "initializationParameters"
        return CreatePLT{..}
