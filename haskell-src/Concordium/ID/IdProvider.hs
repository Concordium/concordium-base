module Concrodium.Crypto.ID.IdProvider

class SignatureScheme s where
    sign    :: SignKey-> VerifyKey -> ByteString -> s
    verify  :: VerifyKey -> ByteString -> s -> Bool
      

data AHI = AHI IdAH IdCredPub IdCredSec PrfKey AL --stored by AH
data AHC = AHC IdIP AHI Signature
-- Signature on (IdCredSec, k, AL)
data ACI = -- on the chain
data IPIAH = IPIAH {ipiah_AhId                      ::  IdAH, 
                    ipiah_AhAttrList                ::  AL  , 
                    ipiah_AhIdCredPub               ::  PublicKey,
                    ipiah_AhPrfKeyCommitment        ::  Commitment, 
                    ipiah_ZkpOfPrfKeyAndIdCredSec   ::  ZKP,
                    ipiah_ERegID                    ::  [(AR, [Cipher])],
                    ipiah_zkpOfMatchingPrfKey       ::  ZKP 

newtype AR = AR IdAR PublicKey

type REASON = String
data CertificationOutcome = SUCCESS Signature | FALIURE REASON 


-- | The commitment is a commitment to PRF key
--  the ZKP object contains a proof of knowledge of PRF key and 
--  secret key corresponding to the public key
verifyKeys :: Commitment -> PublicKey-> ZKP -> Bool
verifyKeys = undefined

verifyMatchingPrfKeyCommitment:: Commitment -> [(AR,[Cipher])] -> ZKP -> Bool 
verifyMatchingPrfKeyCommitment  = undefined

certifyAH :: SignKey-> VerifyKey -> IPIAH -> CertificationOutcome 
cerifyAH signK verifyK ipiah = if (not b) 
                                  then FAILURE "Verification of keys failed" 
                               else if (not b') 
                                  then FAILURE "Verification of AR data failed"
                               else SUCCESS (sign signK verifyK..)
                    where
                        prfKeyCommitment = ipiah_AhPrfKeyCommitment ipiah
                        ahPubKey         = ipiah_AhIdCredPub ipiah
                        prfKeys          = ipiah_ZkpOfPrfKeyAndIdCredSec ipiah
                        eRegId           = ipiah_ERegId ipiah
                        prfMatching      =  ipiah_zkpOfMatchingPrfKey ipiah
                        b = verifyKey prfKeyCommitment ahPubKey prfKeys
                        b' = verifyMatchingPrfKeyCommitment prfKeyCommitment eRegId prfMatching
                
               
              
             
                                                  


