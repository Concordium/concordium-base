{-# LANGUAGE TypeFamilies, ExistentialQuantification, FlexibleContexts, FlexibleInstances #-}
module Concordium.Crypto.SignatureScheme where
import           Data.ByteString (ByteString) 
import           Concordium.Crypto.ByteStringHelpers
import           Data.Word
import qualified Data.FixedByteString as FBS
import           Data.Serialize
import qualified Data.ByteString as B
import           Data.Typeable
import           System.IO.Unsafe
import           Test.QuickCheck (Arbitrary(..))
import           System.Random

 


data SignKey = SignKey ByteString
    deriving (Eq, Show)
data VerifyKey = VerifyKey ByteString
    deriving (Eq, Show)
data Signature = Signature ByteString
    deriving (Eq, Show)
data SchemeId = Ed25519 | CL
    deriving (Eq, Show)
data KeyPair = KeyPair {
      signKey :: SignKey,
      verifyKey :: VerifyKey
 } deriving (Eq, Show)

instance Serialize SchemeId where
    put x = put (fromEnum x)
    get = do e <- get 
             return $  toEnum e

instance Serialize SignKey where
    put (SignKey sk) = put sk
    get = SignKey <$> get

instance Serialize VerifyKey where
    put (VerifyKey sk) = put sk
    get = VerifyKey <$> get

instance Serialize KeyPair where
    put (KeyPair sk vk) = put sk >> put vk
    get = do
        sk <- get
        vk <- get
        return $ KeyPair sk vk


instance Serialize Signature where
    put (Signature b) = put b
    get = Signature <$> get

instance Enum SchemeId where 
    toEnum n | n == 1    = CL
             | n == 2    = Ed25519
             | otherwise = errorWithoutStackTrace "SchemeId.toEnum: bad argument"
    fromEnum CL = 1
    fromEnum Ed25519= 2 


data SignatureScheme = SigScheme {schemeId :: SchemeId,
                                  sign :: KeyPair-> ByteString -> Signature ,
                                  verify :: VerifyKey -> ByteString -> Signature -> Bool,
                                  newPrivateKey :: IO SignKey,
                                  publicKey :: SignKey -> VerifyKey
                                 }
              
                                  
{-
instance Serialize SchemeId where
      put (s) = put $ schemeCode s
      get  = Id <$> get
-}

