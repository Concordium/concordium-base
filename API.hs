module Concordiun.Crypto.Hash where  
	{--we could add the particular Hash protocol as an argument--}
--non incremental
--input: list of Parameters, e.g. Hash family, digest length..etc 
--input: message to hash
--output: hash digest
hash :: [HashParam] -> ByteString -> ByteString

--incremental
--initialized a hash context
-- input: list of Parameters, e.g. Hash family, digest length...etc
-- output: Hash context
init     :: [HashParams]-> Ctx
--hashes the bytestring into the context and returns a new context
update   :: Ctx -> ByteString -> Ctx
--returns the hash digest and flushes the memory
finalize :: Ctx -> ByteString 

module Concordium.Crypto.Util where

--Random Oracle Replacement
hRO :: ByteString -> ByteString

-- returns a pair (privateKey, publicKey)
-- publicKey = g^privateKey
genkeyPair :: (RandomGen a)  => a ->  (ByteString, ByteString)

-- take a passphrase and returns a pair (IdCredSec, IdCredPub)
-- where IdCredSec is encrypted with the passphrase
genKeyPairdwPass :: (RandomGen a) => a -> String -> (ByteString, ByteString)

-- scheme identifiers
Data SchemeID = Schnorr | CamenischeLysyanskaya

-- Class of signature schemes
class SignatureScheme scheme where
	schemeID :: SchemeID 
	data VerifKey scheme :: *
	data SignKey scheme :: *
	data Signature scheme :: *
	generateKeys ::  (RandomGen a) => a -> scheme -> (SignKey scheme, VerifKey scheme)
	sign :: SignKey scheme -> ByteString -> ByteString
        verify :: VerifKey scheme -> ByteString -> Signature scheme -> Bool

-- A setup takes a scheme id and returns an element of the corresponding signature scheme
-- e.g. setup CamenischeLysyanskaya would return a pair (q, G, G', e) where q is the oder of G (G')
--  and e : G x G -> G' a bilnear map (note G and G' are not types)
--  SecurityParam is yet to be defined. e.g. in CL we need a bit length as a parameter
setup :: (SignatureScheme a) => [SecurityParam] -> SchemeId -> a

-- Example the signature scheme CamenischeLysyanskaya 
-- FiniteGroup is just and identifier G (g, p) where g is a generator and p is the order
-- What shoudl BinlinearMap be???
data CL = (Int, FiniteGroup, FiniteGroup, BilinearMap)

-- Example instance CL signature scheme
-- Scheme B in Camenische-Lysyanskaya 04 paper
instance SignatureScheme CL where
	schemeID = CamenischeLysyanskaya
        data VerifKey CL = VK { order :: Int, group :: FiniteGroupd, group' :: FiniteGroup, e :: BilinearMap, _X :: Int, _Y :: Int, _Z :: Int}
        data SignKey CL = SK { x :: Int, y :: Int, z :: Int}
            .....

module Concordium.Id.User
import Concordium.Crypto.Util
-- Example: Elgamal PublicKey g is a group G(g,p) and h is g^h
data PublicKey = PK {_G :: FiniteGroup, h :: Int} 
data PrivateKey = Int

genIdCred :: (RandomGen a) => a -> FiniteGroup -> (PrivateKey, PublicKey)

-- take a passphrase and returns a pair (IdCredSec, IdCredPub)
-- where IdCredSec is encrypted with the passphrase
-- internally uses genKeyPairwPass
genIdCredwPass :: (RandomGen a) => a -> String -> FiniteGroup -> (PrivateKey, PublicKey)

-- a method to encode publicKey as a string for publishing
formatePublicKey :: Format -> PublicKey -> ByteString


module Concordium.Id.Account
import Concordium.Crypto.Util
import Concordium.Crypto.User

-- calls setup with default security params
genSignatureScheme :: (SignatureScheme a) => SchemeId -> a   

-- signing and verifying
sign_acc :: (SignatureScheme a) => SignKey a -> ByteString -> Signature a

verify_acc :: (SignatureScheme a) => VerifKey a -> ByteString -> Signature a -> bool

-- From 
fromByteString :: (SignatureScheme a) -> SchemeID -> ByteString -> Signature a




module Concrodium.Id.Ip
import Concordium.Crypto.Util

genSignatureScheme :: (SignatureScheme a) => SchemeId -> a   






























{--| basic tools--}




-- | hash function
-- we'll also need an incremental hash function (init+update+finalize)
h :: ByteString -> ByteString 

--Random oracle replacement
h_ro :: ByteString -> ByteString
h_ro = h




--Groups
class  Group a where
	....
class (Group a) => CyclicGroup a

class (Group a) => FiniteGroup a


--Finite fields
class (Group a) => Ring a where
	...

class (Ring a) => Field a where
	...

class FiniteField c where
	order :: Int
	char :: Int
        primPow :: Int
        + :: Int -> Int -> Int
       ...

type F = ..

instance FiniteField F where
	....

--EllipticCurves over a finite field given by the coefficients a,b in y^2 = x^3 + a x + b
data EllipticCurves =  C {a::Int, b::Int}



--generating BLS curve from list of parameters 
blscurve :: (Finite field a) =>  [a] -> EllipticCurve a 


type Name = F
type Credential =  F

type Attribute = F

data AHI = AHI {id_ah:: Name, id_cred_pub :: Credential, id_cred_sec:: Credential, key:: F, attributes:: [Attribute]} 

data AHC = AHC {id_ip: Name, ahi:

