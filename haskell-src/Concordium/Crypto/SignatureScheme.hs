{-# LANGUAGE TypeFamilies, ExistentialQuantification #-}
module Concordium.Crypto.SignatureScheme where
import           Data.ByteString (ByteString) 
import           Data.Word
import qualified Data.ByteString as B


newtype SchemeId = SchemeId Word8
class SignatureScheme_ scheme where
    data VerifyKey scheme :: *
    data SignKey scheme :: *
    data Signature scheme :: *
    generatePrivateKey ::  SignKey scheme
    publicKey :: SignKey scheme -> VerifyKey scheme
    sign ::  SignKey scheme -> VerifyKey scheme -> ByteString -> Signature scheme
    verify :: VerifyKey scheme -> ByteString -> Signature scheme -> Bool
    schemeId :: scheme -> SchemeId


data SignatureScheme = forall a. SignatureScheme_ a => SignatureScheme a
-- A setup takes a scheme id and returns an element of the corresponding signature scheme
--setup :: (SignatureScheme a) => [SecurityParam] -> SchemeId -> a

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
