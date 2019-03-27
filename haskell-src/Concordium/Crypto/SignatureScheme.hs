{-# LANGUAGE TypeFamilies #-}
module Concordium.Crypto.SignatureScheme where
import           Data.ByteString (ByteString) 
import qualified Data.ByteString as B


data SchemeID = Schnorr | CamenischeLysyanskaya | EDDSA_Ed25519

class SignatureScheme scheme where
    data VerifyKey scheme :: *
    data SignKey scheme :: *
    data Signature scheme :: *
    generatePrivateKey ::  SignKey scheme
    publicKey :: SignKey scheme -> VerifyKey scheme
    sign ::  SignKey scheme -> VerifyKey scheme -> ByteString -> Signature scheme
    verify :: VerifyKey scheme -> ByteString -> Signature scheme -> Bool


-- A setup takes a scheme id and returns an element of the corresponding signature scheme
-- e.g. setup CamenischeLysyanskaya would return a pair (q, G, G', e) where q is the oder of G (G')
--  and e : G x G -> G' a bilnear map (note G and G' are not types)
--  SecurityParam is yet to be defined. e.g. in CL we need a bit length as a parameter
--setup :: (SignatureScheme a) => [SecurityParam] -> SchemeId -> a

-- Example the signature scheme CamenischeLysyanskaya 
-- FiniteGroup is just and identifier G (g, p) where g is a generator and p is the order
-- What shoudl BinlinearMap be???
--data CL = (Int, FiniteGroup, FiniteGroup, BilinearMap)
--

--data Ed25519
data CL

    {-
instance SignatureScheme Ed25519 where
    data VerifyKey Ed25519    = Ed25519_PK ByteString
    data SignKey Ed25519      = Ed25519_SK ByteString
    data Signature Ed25519    = Ed25519_Sig ByteString
    generatePrivateKey        = unsafePerfomIO $ do (Ed25519.SignKey x) <- Ed25519.newPrivKey 
                                                    return (Ed25519_SK x)
    publicKey (Ed25519_SK x) = unsafePerformIO $ do (Ed25519.VerifyKey y) <- pubKey (Ed25519.SignKey y) 
                                                    return (Ed25519_PK y)
    sign (Ed25519_SK x) (Ed25519_PK y) b = Ed25519_Sig b
    verify (Ed25519_PK x) b s = True
-}
instance SignatureScheme CL where
    data VerifyKey CL    = CL_PK ByteString
    data SignKey CL      = CL_SK ByteString
    data Signature CL    = CL_Sig ByteString
    generatePrivateKey        = CL_SK B.empty
    publicKey (CL_SK x) = CL_PK x
    sign (CL_SK x) (CL_PK y) b = CL_Sig b
    verify (CL_PK x) b s = True
