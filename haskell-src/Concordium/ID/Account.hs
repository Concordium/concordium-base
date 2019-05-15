{-# LANGUAGE DeriveGeneric #-}
module Concordium.ID.Account where

import GHC.Generics
import Concordium.ID.Types
import Data.ByteString.Char8
import GHC.Word
import Data.ByteString.Random.MWC
import System.IO.Unsafe
import qualified  Concordium.Crypto.Ed25519Signature  as S
import Concordium.Crypto.SignatureScheme
import Concordium.Crypto.PRF
import Concordium.ID.Attributes
import qualified Concordium.Crypto.SHA224 as SHA224
import qualified Concordium.Crypto.SHA256 as SHA256
import qualified Data.ByteString as BS
import qualified Data.FixedByteString as FBS
import Data.Base58String.Bitcoin

import Foreign.Storable(peek)
import Foreign.Ptr(castPtr)
import Data.Serialize
import Data.Hashable



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
deployCredentials :: SignKey -> VerifyKey ->  SignatureScheme -> Policy ->  
    CredentialHolderInformation -> CredentialHolderCertificate -> Word8 -> IO CredentialDeploymentInformation
deployCredentials sk vk sch p chi chc n = return $ CDI {
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

                                            


                                     

-- input : Account Signature Key Pair + signature scheme
-- input : Account Encryption PK
newAccount:: SignKey-> VerifyKey -> SignatureScheme -> AccountEncryptionKey -> IO AccountCreationInformation
newAccount sk pk sch enc =  return $ 
                           ACI {
                                        aci_sigScheme = sch',
                                        aci_verifKey = pk,
                                        aci_encKey = enc,
                                        aci_accAddress = accountAddress' pk sch' ,
                                        aci_proof =  p
                                }
            where
                p = let (EncKeyAcc x) = enc
                        SHA256.Hash y = SHA256.hash x in 
                        Proof $ FBS.toByteString y
                sch' = schemeId sch

                                        
                                            {-
prove :: Policy -> AccountHolderInformation -> AccountHolderCertificate -> IO ZKProof
prove _ _ _ = random (fromIntegral 80) >>= (return . Proof)
-}

registrationId = (random (fromIntegral 32)) >>= (return . RegIdCred)
    
createAccount :: VerifyKey -> AccountCreationInformation  
createAccount ahc = ACI { 
                          aci_sigScheme = scheme,
                          aci_verifKey = ahc,
                          aci_encKey = encKey,
                          aci_accAddress = accountAddress' ahc scheme,
                          aci_proof = proof
                        }

accountAddress :: AccountCreationInformation-> AccountAddress
accountAddress aci =  accountAddress' vk sc
    where vk = aci_verifKey aci
          sc = aci_sigScheme aci


base58decodeAddr :: Base58String -> AccountAddress
base58decodeAddr bs = AccountAddress (FBS.fromByteString (toBytes bs))


accountScheme :: AccountAddress -> Maybe SchemeId
accountScheme (AccountAddress s) = toScheme (FBS.getByte s 0)


accountAddress' :: AccountVerificationKey -> SchemeId -> AccountAddress 
accountAddress' (VerifyKey x) y =  AccountAddress (FBS.fromByteString $ BS.cons sch (BS.take (accountAddressSize - 1) bs))
    where 
        (SHA224.Hash r) = SHA224.hash x
        bs = FBS.toByteString r
        sch:: Word8
        sch = fromIntegral $ fromEnum y
      
          {-
verifyAccount :: AccountCreationInformation -> Bool 
verifyAccount _ = True
-}


ar :: AnonimityRevoker
ar = AR (AR_ID $ pack "Gotham City Police Department") (AR_PK $ unsafePerformIO $ random (fromIntegral 48))

--Identity Provider
gcpib = IP_ID $ pack "Gotham City Post Industrial Bank"
gcpibPubKey =  let (SHA256.Hash x) = SHA256.hash $ pack "Gotham City Post Industrial Bank"
                      in  IP_PK (FBS.toByteString x)


arData = [(AR_ID $ pack "Gotham City Police Department", Share $ unsafePerformIO $ random (fromIntegral 48))]

regId = RegIdCred $ unsafePerformIO $ random (fromIntegral 48)

scheme = Ed25519 


encKey = EncKeyAcc ( unsafePerformIO $ random (fromIntegral 48))

policy = Conj (AtomicBD AgeOver18) (AtomicCitizenship EU) 

aux = pack "aux"

proof = Proof $ pack "proof of bot"

    {-
randomAcc = unsafePerformIO $ do keypair <- S.newKeyPair
                                 return $ createAccount (verifyKey keypair)
-}

fakeSign::ByteString -> ByteString
fakeSign x = SHA256.hashToByteString (SHA256.hash x)

fakeSignCred:: (CredentialHolderSecretKey, PrfKey, AttributeList) -> Signature
fakeSignCred (x, y, z) = Signature $ fakeSign $ BS.concat[runPut (put x), runPut (put y), runPut (put  z)]
