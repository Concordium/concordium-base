{-# LANGUAGE TypeFamilies #-}
module Concordium.ID.Types where

import qualified Data.ByteString    as BS
import           Data.ByteString    (ByteString)
import           Data.Time
import           Concordium.ID.Attributes
--import           Concoridum.Crypto.Signature

data AccountHolderCertificate 

-- Secret Key of Account Holder
newtype SecretIdenityCredentials = IdCredSec ByteString

-- Public Key of Account Holder
newtype PublicIdenityCredentials = IdCredPub ByteString

-- A secret key to generate Account Registration ID
newtype PseudoRandomFunctionKey   = PRFKey ByteString

-- Public key of Anonimity Revoker (Elgamal)
newtype AnonimityRevokerPublicKey = AR_PK ByteString

-- Private key of Anonimity Revoker (Elgamal)
newtype AnonimityRevokerPrivateKey = AR_SK ByteString

-- Name of Identity Revoker
newtype AnonimityRevokerIdentity  = AR_ID ByteString

data AnonimityRevoker = AR AnonimityRevokerIdentity AnonimityRevokerPublicKey

-- Name of Idenity Provider
newtype IdentityProviderIdentity  = IP_ID ByteString

-- Public key of Identity provider ()
newtype IdentityProviderPublicKey = IP_PK ByteString

-- Private key of Identity provider ()
newtype IdentityProviderSecretKey = IP_SK ByteString

data IdentityProvider = IP IdentityProviderIdentity IdentityProviderPublicKey
                         

-- Signing key for accounts (eddsa key)
newtype AccountSigningKey = SigKeyAcc ByteString

-- Verification key for accounts (eddsa key)
newtype AccountVerificationKey = VerifKeyAcc ByteString


-- decryption key for accounts (Elgamal?)
newtype AccountDecryptionKey = DecKeyAcc ByteString 

-- encryption key for accounts (Elgamal?)
newtype AccountEncryptionKey = EncKeyAcc ByteString 

-- Account Registration ID
newtype AccountRegistrationID = RegIdAcc ByteString

newtype SecretShare = Share ByteString

--AR Data
type AccountAnonimityRevocationData = [(AnonimityRevokerIdentity, SecretShare)] 


-- ZK proofs

data Statement = Statement (ByteString -> Bool)

data Witness = Witness ByteString 

data ZKProof = Proof ByteString

data AccountCreationInformation = ACI { regId     :: AccountRegistrationID,
                                        arData    :: AccountAnonimityRevocationData,
                                        ipId      :: IdentityProviderIdentity, 
                                    --    sigScheme :: 
                                        verifKey ::  AccountVerificationKey,
                                        encKey   :: AccountEncryptionKey,
                                        auxData  :: ByteString,
                                        policy   :: Policy, 
                                        proof    :: ZKProof
                                      }
