{-# LANGUAGE TypeFamilies, ExistentialQuantification, FlexibleContexts, FlexibleInstances #-}
module Concordium.Crypto.SignatureScheme where
import           Data.ByteString (ByteString) 
import           Concordium.Crypto.ByteStringHelpers
import           Data.Word
import qualified Data.FixedByteString as FBS
import           Data.Serialize
import qualified Concordium.Crypto.Signature as S
import qualified Data.ByteString as B
import           Data.Typeable
import           System.IO.Unsafe

data SchemeIdName = Schnorr | CL

schemeNameFromId (SchemeId x) | x == fromIntegral 2  = Schnorr
                              | x == fromIntegral 1 = CL

newtype SchemeId = SchemeId Word8  
    deriving (Eq, Show)

instance Serialize SchemeId where
      put (SchemeId s) = put s
      get  = SchemeId <$> get

class SignatureScheme_ scheme where
    data VerifyKey scheme :: * 
    data SignKey scheme :: *
    data Signature scheme :: *
    generatePrivateKey ::  SignKey scheme
    publicKey :: SignKey scheme -> VerifyKey scheme
    sign ::  SignKey scheme -> VerifyKey scheme -> ByteString -> Signature scheme
    verify :: VerifyKey scheme -> ByteString -> Signature scheme -> Bool
    schemeId :: VerifyKey scheme -> SchemeId
    toByteString :: VerifyKey scheme -> ByteString 
    fromByteString :: ByteString -> VerifyKey scheme 


data SignatureScheme = forall a. SignatureScheme_ a => SignatureScheme a

-- A setup takes a scheme id and returns an element of the corresponding signature scheme
--setup :: (SignatureScheme a) => [SecurityParam] -> SchemeId -> a

instance (SignatureScheme_ a) => Serialize (VerifyKey a) where
    put  = put . toByteString
    get = fromByteString <$> get


data Ed25519

instance SignatureScheme_ Ed25519 where
    data VerifyKey Ed25519    = Ed25519_PK (FBS.FixedByteString S.VerifyKeySize) deriving (Typeable)
    data SignKey Ed25519      = Ed25519_SK (FBS.FixedByteString S.SignKeySize)
    data Signature Ed25519    = Ed25519_Sig (FBS.FixedByteString S.SignatureSize)
    generatePrivateKey        = unsafePerformIO $ do (S.SignKey x) <- S.newPrivKey
                                                     return (Ed25519_SK x)
    publicKey (Ed25519_SK x) = unsafePerformIO $ do (S.VerifyKey y) <- S.pubKey (S.SignKey x)
                                                    return (Ed25519_PK y)
    sign (Ed25519_SK x) (Ed25519_PK y) b = let (S.Signature s ) = S.sign S.KeyPair{S.signKey=(S.SignKey x), S.verifyKey=(S.VerifyKey y)} b
                                           in (Ed25519_Sig s)
    verify (Ed25519_PK x) b (Ed25519_Sig s) = S.verify (S.VerifyKey x) b (S.Signature s)
    schemeId _ = SchemeId (fromIntegral 2)
    toByteString (Ed25519_PK s) =  FBS.toByteString s
    fromByteString bs = Ed25519_PK $ FBS.fromByteString  bs



instance Show (VerifyKey Ed25519) where
    show (Ed25519_PK pk) = byteStringToHex $ FBS.toByteString pk


data CL

instance SignatureScheme_ CL where
    data VerifyKey CL    = CL_PK ByteString
    data SignKey CL      = CL_SK ByteString
    data Signature CL    = CL_Sig ByteString
    generatePrivateKey        = CL_SK B.empty
    publicKey (CL_SK x) = CL_PK x
    sign (CL_SK x) (CL_PK y) b = CL_Sig b
    verify (CL_PK x) b s = True
    schemeId _ = SchemeId (fromIntegral 3)
    toByteString (CL_PK s) =  s
    fromByteString bs  = CL_PK bs
