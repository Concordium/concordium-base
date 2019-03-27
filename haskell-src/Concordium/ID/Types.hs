{-# LANGUAGE TypeFamilies, ExistentialQuantification #-}
module Concordium.ID.Types where

import qualified Data.ByteString    as BS
import           Data.ByteString    (ByteString)
import           Data.Time
import           Concordium.ID.Attributes
import           Concordium.Crypto.SignatureScheme

newtype AccountHolderIdentity = AH ByteString

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
data AccountSigningKey = forall a. SignatureScheme_ a => AccSignKey (SignKey a)

-- Verification key for accounts (eddsa key)
data AccountVerificationKey = forall a. SignatureScheme_ a => AccVerifyKey (VerifyKey a)


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

data AccountHolderInformation = AHI { ahi_id :: AccountHolderIdentity,
                                      ahi_idCredPub:: PublicIdenityCredentials, 
                                      ahi_idCredSec:: SecretIdenityCredentials, 
                                      ahi_prfKey   :: PseudoRandomFunctionKey, 
                                      ahi_attributeList :: AttributeList 
                                     }


data AccountCreationInformation = ACI { aci_regId     :: AccountRegistrationID,
                                        aci_arData    :: AccountAnonimityRevocationData,
                                        aci_ipId      :: IdentityProviderIdentity, 
                                        aci_sigScheme :: SchemeId,
                                        aci_verifKey  :: AccountVerificationKey,
                                        aci_encKey    :: AccountEncryptionKey,
                                        aci_policy    :: Policy, 
                                        aci_auxData   :: ByteString,
                                        aci_proof     :: ZKProof
                                      }

data AccountHolderCertificate = AHC { ahc_ipId :: IdentityProviderIdentity,
                                      ahc_ahi  :: AccountHolderInformation,
                                      ahc_sig  :: Signature CL
                                     }
