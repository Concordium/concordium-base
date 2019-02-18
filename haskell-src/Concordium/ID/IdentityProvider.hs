module Concordium.ID.IdentityProvider where

import           Concordium.Crypto.SignatureScheme
import           Concordium.Crypto.Elgamal
import qualified Data.ByteString as B

--newtype PublicKey = PK B.ByteString
newtype ZKP = ZKP B.ByteString
newtype Commitment = Cmt B.ByteString

type Attribute = String

type AL = [Attribute]

type IdAH =  String
--type IdCredPub = AHPK ByteString
--type IdCred = AHPK ByteString
--data AHI = AHI IdAH IdCredPub IdCredSec PrfKey AL --stored by AH
--data AHC = AHC IdIP AHI Signature
-- Signature on (IdCredSec, k, AL)
--data ACI = -- on the chain
data IPIAH = IPIAH {ipiah_AhId                      ::  IdAH, 
                    ipiah_AhAttrList                ::  AL  , 
                    ipiah_AhIdCredPub               ::  PublicKey,
                    ipiah_AhPrfKeyCommitment        ::  Commitment, 
                    ipiah_ZkpOfPrfKeyAndIdCredSec   ::  ZKP,
                    ipiah_ERegId                    ::  [(AR, [Cipher])],
                    ipiah_zkpOfMatchingPrfKey       ::  ZKP 
                   }

type IdAR = String
data AR = AR IdAR PublicKey

type REASON = String
data CertificationOutcome = SUCCESS (Signature CL) | FAILURE REASON 


-- | The commitment is a commitment to PRF key
--  the ZKP object contains a proof of knowledge of PRF key and 
--  secret key corresponding to the public key
verifyKeys :: Commitment -> PublicKey-> ZKP -> Bool
verifyKeys = undefined

verifyMatchingPrfKeyCommitment:: Commitment -> [(AR,[Cipher])] -> ZKP -> Bool 
verifyMatchingPrfKeyCommitment  = undefined

certifyAH :: SignKey CL-> VerifyKey CL -> IPIAH -> CertificationOutcome 
certifyAH signK verifyK ipiah = if (not b) 
                                  then FAILURE "Verification of keys failed" 
                               else if (not b') 
                                  then FAILURE "Verification of AR data failed"
                               else SUCCESS (sign signK verifyK B.empty)
                    where
                        prfKeyCommitment = ipiah_AhPrfKeyCommitment ipiah
                        ahPubKey         = ipiah_AhIdCredPub ipiah
                        prfKeys          = ipiah_ZkpOfPrfKeyAndIdCredSec ipiah
                        eRegId           = ipiah_ERegId ipiah
                        prfMatching      =  ipiah_zkpOfMatchingPrfKey ipiah
                        b = verifyKeys prfKeyCommitment ahPubKey prfKeys
                        b' = verifyMatchingPrfKeyCommitment prfKeyCommitment eRegId prfMatching
                
               
              
             
                                                  


