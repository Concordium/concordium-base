module Concordium.ID.AccountHolder where

import Concordium.ID.Types
import Data.ByteString.Char8
import Data.ByteString.Random.MWC
import System.IO.Unsafe
import qualified  Concordium.Crypto.Signature as S
import Concordium.Crypto.SignatureScheme
import Concordium.ID.Attributes





-- This is a dummy module for testing
--

createAccount :: S.VerifyKey -> AccountCreationInformation  
createAccount ahc = ACI { aci_regId = regId, 
                          aci_arData = ardata, 
                          aci_ipId = ip, 
                          aci_sigScheme = scheme,
                          aci_verifKey = ahc,
                          aci_encKey = encKey, 
                          aci_policy = policy,
                          aci_auxData = aux,
                          aci_proof = proof
                        }


verifyAccount :: AccountCreationInformation -> Bool 
verifyAccount _ = True


ar :: AnonimityRevoker
ar = AR (AR_ID $ pack "superman") (AR_PK $ unsafePerformIO $ random (fromIntegral 32))

ip = IP_ID $ pack "Mateusz"

ardata = [(AR_ID $ pack "superman", Share $ unsafePerformIO $ random (fromIntegral 32))]

regId = RegIdAcc $ unsafePerformIO $ random (fromIntegral 32)

scheme = SchemeId (fromIntegral 2)


encKey = EncKeyAcc ( unsafePerformIO $ random (fromIntegral 32))

policy = Conj (AtomicBD AgeOver18) (AtomicCitizenship EU) 

aux = pack "aux"

proof = Proof $ pack "proof of bot"


randomAcc = unsafePerformIO $ do keypair <- S.newKeyPair
                                 return $ createAccount (S.verifyKey keypair)


