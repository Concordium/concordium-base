{-# LANGUAGE TypeFamilies, ExistentialQuantification, FlexibleContexts, FlexibleInstances, DerivingVia #-}
module Concordium.Crypto.SignatureScheme where
import Data.Word
import Data.Serialize
import Data.Aeson hiding (encode)
import Concordium.Crypto.ByteStringHelpers
import Data.Text hiding (drop)
import Prelude hiding (drop)

import Data.ByteString (ByteString)
import Data.ByteString.Short (ShortByteString)

newtype SignKey = SignKey ShortByteString
    deriving (Eq)
    deriving Show via ByteStringHex
    deriving Serialize via Short65K
    deriving FromJSON via Short65K
    deriving ToJSON via Short65K

newtype VerifyKey = VerifyKey ShortByteString
    deriving (Eq, Ord)
    deriving Show via ByteStringHex
    deriving Serialize via Short65K
    deriving FromJSON via Short65K
    deriving ToJSON via Short65K

newtype Signature = Signature ShortByteString
    deriving (Eq, Ord)
    deriving Show via ByteStringHex
    deriving Serialize via Short65K
    deriving FromJSON via Short65K
    deriving ToJSON via Short65K

data SchemeId = Ed25519
    deriving (Eq, Show)

instance ToJSON SchemeId where
  toJSON Ed25519 = object [pack "schemeId" .= "Ed25519"]

instance FromJSON SchemeId where
  parseJSON v = do
    name <- parseJSON v
    case name of
      "Ed25519" -> return Ed25519
      err -> fail err

data KeyPair = KeyPair {
      signKey :: !SignKey,
      verifyKey :: !VerifyKey
 } deriving (Eq, Show)

instance Serialize SchemeId where
    put x = putWord8 (fromIntegral (fromEnum x))
    get = do e <- getWord8 
             return $  toEnum (fromIntegral e)

instance Serialize KeyPair where
    put (KeyPair sk vk) = put sk <> put vk
    get = KeyPair <$> get <*> get

instance Enum SchemeId where 
    toEnum n = case toScheme (fromIntegral n) of 
                 Just x -> x
                 Nothing -> errorWithoutStackTrace "SchemeId.toEnum: bad argument"
    fromEnum Ed25519 = 1

toScheme :: Word8 -> Maybe SchemeId
toScheme n | n == 1 = Just Ed25519
           | otherwise = Nothing

data SignatureScheme = SigScheme {schemeId :: SchemeId,
                                  sign :: KeyPair-> ByteString -> Signature ,
                                  verify :: VerifyKey -> ByteString -> Signature -> Bool,
                                  newPrivateKey :: IO SignKey,
                                  publicKey :: SignKey -> VerifyKey
                                 }
