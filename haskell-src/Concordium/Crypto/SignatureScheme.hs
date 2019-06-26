{-# LANGUAGE TypeFamilies, ExistentialQuantification, FlexibleContexts, FlexibleInstances, DerivingVia #-}
module Concordium.Crypto.SignatureScheme where
import           Data.ByteString (ByteString) 
import           Data.Word
import           Data.Serialize
import Concordium.Crypto.ByteStringHelpers

newtype SignKey = SignKey ByteString
    deriving (Eq)
    deriving Show via ByteStringHex

newtype VerifyKey = VerifyKey ByteString
    deriving (Eq, Ord)
    deriving Show via ByteStringHex

newtype Signature = Signature ByteString
    deriving (Eq)
    deriving Show via ByteStringHex

data SchemeId = Ed25519 | CL
    deriving (Eq, Show)
data KeyPair = KeyPair {
      signKey :: !SignKey,
      verifyKey :: !VerifyKey
 } deriving (Eq, Show)

instance Serialize SchemeId where
    put x = putWord8 (fromIntegral (fromEnum x))
    get = do e <- getWord8 
             return $  toEnum (fromIntegral e)

instance Serialize SignKey where
    put (SignKey sk) = put sk
    get = SignKey <$> get

instance Serialize VerifyKey where
    put (VerifyKey sk) = put sk
    get = VerifyKey <$> get

instance Serialize KeyPair where
    put (KeyPair sk vk) = put sk <> put vk
    get = KeyPair <$> get <*> get

instance Serialize Signature where
    put (Signature b) = put b
    get = Signature <$> get

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
