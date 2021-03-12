{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-deprecations #-}
-- abstraction layer for block signatures
module Concordium.Crypto.BlockSignature where

import qualified Concordium.Crypto.Ed25519Signature as Ed25519
import           Data.ByteString
import qualified Data.ByteString.Short as BSS
import Concordium.Crypto.ByteStringHelpers
import Data.Serialize
import Data.Aeson

type SignKey = Ed25519.SignKey
type VerifyKey = Ed25519.VerifyKey
data KeyPair = KeyPair {
  signKey :: !SignKey,
  verifyKey :: !VerifyKey
  } deriving(Eq, Show)

instance Serialize KeyPair where
  put KeyPair{..} = put signKey <> put verifyKey
  get = do
    signKey <- get
    verifyKey <- get
    return KeyPair{..}

instance FromJSON KeyPair where
    parseJSON = withObject "Baker block signature key" $ \obj -> do
      signKey <- obj .: "signatureSignKey"
      verifyKey <- obj .: "signatureVerifyKey"
      return KeyPair{..}

newtype Signature = Signature BSS.ShortByteString
    deriving (Eq, Ord)
    deriving Show via ByteStringHex
    deriving FromJSON via Short65K
    deriving ToJSON via Short65K

-- NB: Serialize instance does not record its own length
instance Serialize Signature where
  put (Signature s) = putShortByteString s
  get = Signature <$> getShortByteString Ed25519.signatureSize

signatureLength :: Int
signatureLength = Ed25519.signatureSize

sign :: KeyPair -> ByteString -> Signature
sign KeyPair{..} = Signature . Ed25519.sign signKey verifyKey

verify :: VerifyKey -> ByteString -> Signature -> Bool
verify vfKey bs (Signature s) = Ed25519.verify vfKey bs s

newKeyPair :: IO KeyPair
newKeyPair = uncurry KeyPair <$> Ed25519.newKeyPair
