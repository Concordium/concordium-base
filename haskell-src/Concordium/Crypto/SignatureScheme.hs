{-# LANGUAGE TypeFamilies, ExistentialQuantification, FlexibleContexts, FlexibleInstances #-}
module Concordium.Crypto.SignatureScheme where
import           Data.ByteString (ByteString) 
import           Concordium.Crypto.ByteStringHelpers
import           Data.Word
import qualified Data.FixedByteString as FBS
import           Data.Serialize
import           Data.Serialize.Put
import           Data.Serialize.Get
import qualified Data.ByteString as B
import           Data.Typeable
import           System.IO.Unsafe
import           Test.QuickCheck (Arbitrary(..))
import           System.Random

 


newtype SignKey = SignKey ByteString
    deriving (Eq, Show)
newtype VerifyKey = VerifyKey ByteString
    deriving (Eq, Show, Ord)
newtype Signature = Signature ByteString
    deriving (Eq, Show)
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
    toEnum n | n == 0    = CL
             | n == 1    = Ed25519
             | otherwise = errorWithoutStackTrace "SchemeId.toEnum: bad argument"
    fromEnum CL = 0
    fromEnum Ed25519= 1


data SignatureScheme = SigScheme {schemeId :: SchemeId,
                                  sign :: KeyPair-> ByteString -> Signature ,
                                  verify :: VerifyKey -> ByteString -> Signature -> Bool,
                                  newPrivateKey :: IO SignKey,
                                  publicKey :: SignKey -> VerifyKey
                                 }
