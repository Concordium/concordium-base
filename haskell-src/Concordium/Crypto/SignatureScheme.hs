{-# LANGUAGE TypeFamilies, ExistentialQuantification #-}
module Concordium.Crypto.SignatureScheme where
import           Data.ByteString (ByteString) 
import           Data.Word
import           Data.Serialize
import qualified Data.ByteString as B

data SchemeIdName = Schnorr | CL


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
    schemeId :: scheme -> SchemeId
    putVerifyKey :: Putter (VerifyKey scheme)
    getVerifyKey :: Get (VerifyKey scheme)
    putSignKey :: Putter (SignKey scheme)
    getSignKey :: Get (SignKey scheme)
    signKeyEq :: SignKey scheme -> SignKey scheme -> Bool
    verifyKeyEq :: VerifyKey scheme -> VerifyKey scheme -> Bool


data SignatureScheme = forall a. SignatureScheme_ a => SignatureScheme a
-- A setup takes a scheme id and returns an element of the corresponding signature scheme
--setup :: (SignatureScheme a) => [SecurityParam] -> SchemeId -> a

instance (SignatureScheme_ a) => Eq (SignKey a) where
    a == b = signKeyEq a b

instance (SignatureScheme_ a) => Eq (VerifyKey a) where
    a == b = verifyKeyEq a b
    

instance (SignatureScheme_ a) => Serialize (SignKey a) where
    put = putSignKey
    get = getSignKey

instance (SignatureScheme_ a) => Serialize (VerifyKey a) where
    put = putVerifyKey
    get = getVerifyKey


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
    putVerifyKey (CL_PK s) = put s
    getVerifyKey  = CL_PK <$> get 
    putSignKey (CL_SK s) = put s
    getSignKey  =  CL_SK <$> get 
    signKeyEq (CL_SK sk0) (CL_SK sk1) = sk0 == sk1
    verifyKeyEq (CL_PK pk0) (CL_PK pk1) = pk0 == pk1
