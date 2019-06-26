{-# LANGUAGE DeriveGeneric #-}
module Concordium.ID.Account where

import Concordium.ID.Types
import Data.ByteString.Char8
import GHC.Word
import Data.ByteString.Random.MWC
import System.IO.Unsafe
import Concordium.Crypto.SignatureScheme
import Concordium.Crypto.PRF
import Concordium.ID.Attributes
import qualified Concordium.Crypto.SHA224 as SHA224
import qualified Concordium.Crypto.SHA256 as SHA256
import qualified Data.ByteString as BS
import qualified Data.FixedByteString as FBS
import Data.Base58String.Bitcoin

import Data.Serialize



-- This is an evolving module for testing
-- Account related functionality
-- 1. account creation
-- 2. credential deployment
-- 3. transaction initiation (client)


-- protocol to take part between Credential Holder and Idenity provider
-- input CredentialHolderInformation
-- output CredentialHolderCertificate 
-- note that CredentialHolderInformation has some private data that are not sent to 
-- the IP
-- For now the answer comes with random arbitrary CredentialDeploymentInformation
registerCredentialHolder:: CredentialHolderInformation -> IO CredentialHolderCertificate
registerCredentialHolder chi = return $ CHC {
                                    chc_ipId = gcpib, 
                                    chc_ipPk = gcpibPubKey,
                                    chc_chi  = chi,
                                    chc_sig  = fakeSignCred (chi_sk chi, chi_prfKey chi, chi_attributeList chi)
                                    }
--deploy credentials: Protocol takes place between account holder and the chain
--the object CredentialDeploymentInformation is sent on the chain for verification
deployCredential :: SignKey -> VerifyKey ->  SignatureScheme -> Policy ->  
    CredentialHolderInformation -> CredentialHolderCertificate -> Word8 -> IO CredentialDeploymentInformation
deployCredential sk vk sch p chi chc n = return $ CDI {
                                            cdi_verifKey = vk,
                                            cdi_sigScheme = schemeId sch,
                                            cdi_regId = regId,
                                            cdi_arData = arData,
                                            cdi_ipId  = chc_ipId chc,
                                            cdi_policy = p,
                                            cdi_auxData = aux,
                                            cdi_proof = proof
                                            }
               where regId = let (PrfObj x) = prf (chi_prfKey chi) n
                               in RegIdCred . FBS.toByteString $ x

                                            
verifyCredential :: CredentialDeploymentInformation -> Bool
verifyCredential _ = True

                                     
registrationId = (random (fromIntegral 48)) >>= (return . RegIdCred)
    
base58decodeAddr :: Base58String -> AccountAddress
base58decodeAddr bs = AccountAddress (FBS.fromByteString (toBytes bs))


accountScheme :: AccountAddress -> Maybe SchemeId
accountScheme (AccountAddress s) = toScheme (FBS.getByte s 0)


-- |Compute the account address from account's (public) verification key and the signature scheme identifier.
-- The address is computed by the following algorithm
--
--  * compute SHA-224 hash of the verification key
--  * take the first 20 bytes of the resulting string
--  * and prepend a one byte identifier of the signature scheme.
accountAddress :: AccountVerificationKey -> SchemeId -> AccountAddress 
accountAddress (VerifyKey x) y =  AccountAddress (FBS.fromByteString $ BS.cons sch (BS.take (accountAddressSize - 1) bs))
    where 
        (SHA224.Hash r) = SHA224.hash x
        bs = FBS.toByteString r
        sch:: Word8
        sch = fromIntegral $ fromEnum y

ar :: AnonimityRevoker
ar = AR (AR_ID $ pack "Gotham City Police Department") (AR_PK $ unsafePerformIO $ random (fromIntegral 48))

--Identity Provider
gcpib = IP_ID $ pack "Gotham City Post Industrial Bank"
gcpibPubKey =  let (SHA256.Hash x) = SHA256.hash $ pack "Gotham City Post Industrial Bank"
                      in  IP_PK (FBS.toByteString x)


arData :: [(AnonimityRevokerIdentity, SecretShare)]
arData = [(AR_ID $ pack "Gotham City Police Department", Share $ unsafePerformIO $ random (fromIntegral 48))]

regId :: CredentialRegistrationID
regId = RegIdCred $ unsafePerformIO $ random (fromIntegral 48)

scheme :: SchemeId
scheme = Ed25519 


encKey :: AccountEncryptionKey
encKey = EncKeyAcc ( unsafePerformIO $ random (fromIntegral 48))

policy :: Policy
policy = Conj (AtomicBD AgeOver18) (AtomicCitizenship EU) 

aux :: ByteString
aux = pack "aux"

proof :: ZKProof
proof = Proof $ pack "proof of bot"

fakeSign::ByteString -> ByteString
fakeSign x = SHA256.hashToByteString (SHA256.hash x)

fakeSignCred:: (CredentialHolderSecretKey, PrfKey, AttributeList) -> Signature
fakeSignCred (x, y, z) = Signature $ fakeSign $ BS.concat[runPut (put x), runPut (put y), runPut (put  z)]
