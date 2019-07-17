{-# LANGUAGE TypeFamilies, ExistentialQuantification, FlexibleContexts, FlexibleInstances, DerivingVia #-}
module Concordium.Crypto.SignatureScheme where
import Data.ByteString (ByteString)
import Data.Word
import Data.Serialize
import qualified Data.Serialize as S
import Data.Aeson hiding (encode)
import Concordium.Crypto.ByteStringHelpers
import Data.Text hiding (drop)
import qualified  Data.Text.Encoding as TE
import Prelude hiding (drop)
import qualified Data.ByteString.Base16              as BS16

import qualified Data.ByteString as BS

newtype SignKey = SignKey ByteString
    deriving (Eq)
    deriving Show via ByteStringHex
    deriving Serialize via Short65K

newtype VerifyKey = VerifyKey ByteString
    deriving (Eq, Ord)
    deriving Show via ByteStringHex
    deriving Serialize via Short65K

instance ToJSON VerifyKey where
  toJSON v = object [pack "verifyKey" .= show v]

-- Length + data (serializes with `put :: Bytestring -> Put`)
instance FromJSON VerifyKey where
  parseJSON v = do
    verifKey <- parseJSON v
    let plainBs = fst . BS16.decode . TE.encodeUtf8 $ verifKey
    case S.decode . flip BS.append plainBs $
         S.encode (fromIntegral . BS.length $ plainBs :: Word16) of
      Left e  -> fail e
      Right n -> return n

newtype Signature = Signature ByteString
    deriving (Eq, Ord)
    deriving Show via ByteStringHex
    deriving Serialize via Short65K

data SchemeId = Ed25519 | CL
    deriving (Eq, Show)

instance ToJSON SchemeId where
  toJSON Ed25519 = object [pack "schemeId" .= "Ed25519"]
  toJSON CL = object [pack "schemeId" .= "CL"]

instance FromJSON SchemeId where
  parseJSON v = do
    name <- parseJSON v
    case name of
      "Ed25519" -> return Ed25519
      "CL" -> return CL
      _ -> fail "e"

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
    fromEnum CL = 0
    fromEnum Ed25519= 1

toScheme :: Word8 -> Maybe SchemeId
toScheme n | n == 0 = Just CL
           | n == 1 = Just Ed25519
           | otherwise = Nothing

data SignatureScheme = SigScheme {schemeId :: SchemeId,
                                  sign :: KeyPair-> ByteString -> Signature ,
                                  verify :: VerifyKey -> ByteString -> Signature -> Bool,
                                  newPrivateKey :: IO SignKey,
                                  publicKey :: SignKey -> VerifyKey
                                 }
