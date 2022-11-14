{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}

module Concordium.Crypto.SignatureScheme where

import Concordium.Crypto.ByteStringHelpers
import Control.DeepSeq
import Data.Aeson
import Data.Aeson.Types
import Data.Serialize
import Data.Word
import GHC.Generics
import Prelude

import qualified Concordium.Crypto.Ed25519Signature as Ed25519
import Data.ByteString (ByteString)
import Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as BSS

newtype Signature = Signature ShortByteString
    deriving (Eq, Ord)
    deriving newtype (NFData)
    deriving (Show) via ByteStringHex
    deriving (Serialize) via Short65K
    deriving (FromJSON) via Short65K
    deriving (ToJSON) via Short65K

data SchemeId = Ed25519
    deriving (Eq, Show)

signatureSerializedSize :: Signature -> Int
signatureSerializedSize (Signature s) = 2 + BSS.length s

-- |The reason for these enumerations is to support multiple different signature
-- schemes in the future.
newtype VerifyKey = VerifyKeyEd25519 Ed25519.VerifyKey
    deriving (Eq, Ord, Show, Generic)
    deriving newtype (NFData)

verifyKeyToJSONPairs :: VerifyKey -> [Pair]
verifyKeyToJSONPairs (VerifyKeyEd25519 vfKey) =
    [ "schemeId" .= Ed25519,
      "verifyKey" .= vfKey
    ]

instance ToJSON VerifyKey where
    toJSON = object . verifyKeyToJSONPairs

instance FromJSON VerifyKey where
    parseJSON (Object obj) = do
        schemeId <- obj .:? "schemeId" .!= Ed25519
        case schemeId of
            Ed25519 -> VerifyKeyEd25519 <$> obj .: "verifyKey"
    parseJSON v@(String _) = VerifyKeyEd25519 <$> parseJSON v -- default Ed25519 signature scheme
    parseJSON v = typeMismatch "Expecting either an object or base16 string encoding." v

-- Serialize the key as well as the scheme
instance Serialize VerifyKey where
    put (VerifyKeyEd25519 vfKey) = put Ed25519 <> put vfKey
    get = do
        schemeId <- get
        case schemeId of
            Ed25519 -> VerifyKeyEd25519 <$> get

-- |NB: The Eq instance should only be used for testing, it is not guaranteed to
-- be side-channel resistant.
data KeyPair = KeyPairEd25519
    { signKey :: !Ed25519.SignKey,
      verifyKey :: !Ed25519.VerifyKey
    }
    deriving (Eq, Show, Generic)

instance NFData KeyPair

correspondingVerifyKey :: KeyPair -> VerifyKey
correspondingVerifyKey KeyPairEd25519{..} = VerifyKeyEd25519 verifyKey

instance ToJSON SchemeId where
    toJSON Ed25519 = String "Ed25519"

instance FromJSON SchemeId where
    parseJSON v = do
        name <- parseJSON v
        case name of
            "Ed25519" -> return Ed25519
            err -> fail $ "Unknown signature scheme '" ++ err ++ "'."

instance Serialize SchemeId where
    put x = putWord8 (fromIntegral (fromEnum x))
    get = do
        e <- getWord8
        case toScheme e of
            Just s -> return s
            Nothing -> fail "Unknown signature scheme."

instance Serialize KeyPair where
    put KeyPairEd25519{..} = put Ed25519 <> put signKey <> put verifyKey
    get =
        get >>= \case
            Ed25519 -> do
                signKey <- get
                verifyKey <- get
                return KeyPairEd25519{..}

keyPairToJSONPairs :: KeyPair -> [Pair]
keyPairToJSONPairs KeyPairEd25519{..} =
    [ "schemeId" .= Ed25519,
      "signKey" .= signKey,
      "verifyKey" .= verifyKey
    ]

instance ToJSON KeyPair where
    toJSON = object . keyPairToJSONPairs

instance FromJSON KeyPair where
    parseJSON = withObject "KeyPair" $ \obj -> do
        schemeId <- obj .:? "schemeId" .!= Ed25519
        case schemeId of
            Ed25519 -> do
                signKey <- obj .: "signKey"
                verifyKey <- obj .: "verifyKey"
                return KeyPairEd25519{..}

instance Enum SchemeId where
    toEnum n = case toScheme (fromIntegral n) of
        Just x -> x
        Nothing -> error "SchemeId.toEnum: bad argument"
    fromEnum Ed25519 = 0

toScheme :: Word8 -> Maybe SchemeId
toScheme n
    | n == 0 = Just Ed25519
    | otherwise = Nothing

sign :: KeyPair -> ByteString -> Signature
sign KeyPairEd25519{..} = Signature . Ed25519.sign signKey verifyKey

verify :: VerifyKey -> ByteString -> Signature -> Bool
verify (VerifyKeyEd25519 vfKey) bs (Signature s) = Ed25519.verify vfKey bs s

newKeyPair :: SchemeId -> IO KeyPair
newKeyPair Ed25519 = do
    (signKey, verifyKey) <- Ed25519.newKeyPair
    return KeyPairEd25519{..}
