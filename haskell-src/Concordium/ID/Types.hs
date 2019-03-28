{-# LANGUAGE TypeFamilies, ExistentialQuantification, FlexibleContexts, DeriveGeneric #-}
module Concordium.ID.Types where

import qualified Data.ByteString    as BS
import           Data.ByteString    (ByteString)
import           Data.Time
import           Data.Word
import           Concordium.ID.Attributes
import qualified Concordium.Crypto.Signature as S
import           Concordium.Crypto.Signature (Ed25519)
import           Concordium.Crypto.SignatureScheme
import           Data.Serialize
import           GHC.Generics


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
    deriving (Eq)

instance Serialize AnonimityRevokerIdentity  where
    put (AR_ID s) = put s
    get  = AR_ID <$> get 

data AnonimityRevoker = AR AnonimityRevokerIdentity AnonimityRevokerPublicKey

-- Name of Idenity Provider
newtype IdentityProviderIdentity  = IP_ID ByteString
    deriving (Eq)

instance Serialize IdentityProviderIdentity where
    put (IP_ID s) = put s
    get  = IP_ID <$> get

-- Public key of Identity provider ()
newtype IdentityProviderPublicKey = IP_PK ByteString

-- Private key of Identity provider ()
newtype IdentityProviderSecretKey = IP_SK ByteString

data IdentityProvider = IP IdentityProviderIdentity IdentityProviderPublicKey
                         

-- Signing key for accounts (eddsa key)
--data AccountSigningKey = forall a. (SignatureScheme_ a, Serialize (SignKey a), Eq (SignKey a))  => AccSignKey (SignKey a) 
type AccountSigningKey = S.SignKey

-- Verification key for accounts (eddsa key)
--data AccountVerificationKey = forall a. (SignatureScheme_ a, Serialize (VerifyKey a), Eq (VerifyKey a)) => AccVerifyKey (VerifyKey a)
type AccountVerificationKey = S.VerifyKey

    {-
instance Serialize AccountVerificationKey where
      put (AccVerifyKey s) = put s
      get  =  AccVerifyKey <$> (get >>= getAccountVerificationKey)
-}

-- decryption key for accounts (Elgamal?)
newtype AccountDecryptionKey = DecKeyAcc ByteString 

-- encryption key for accounts (Elgamal?)
newtype AccountEncryptionKey = EncKeyAcc ByteString 
    deriving (Eq)

instance Serialize AccountEncryptionKey where
    put (EncKeyAcc b) = putByteString b
    get = EncKeyAcc <$> getByteString accountRegistrationIDSize 

-- Account Registration ID (32 bytes)
newtype AccountRegistrationID = RegIdAcc ByteString 
    deriving (Eq)

accountRegistrationIDSize :: Int 
accountRegistrationIDSize = 32

instance Serialize AccountRegistrationID where
    put (RegIdAcc b) = putByteString b
    get = RegIdAcc <$> getByteString accountRegistrationIDSize 

-- shared public key
newtype SecretShare = Share ByteString
    deriving (Eq)

instance Serialize SecretShare where
      put (Share s) = put s
      get  = Share <$> get

--AR Data
type AccountAnonimityRevocationData = [(AnonimityRevokerIdentity, SecretShare)] 


-- ZK proofs

data Statement = Statement (ByteString -> Bool)

data Witness = Witness ByteString 

data ZKProof = Proof ByteString 
    deriving (Generic)

instance Serialize ZKProof where

data AccountHolderInformation = AHI { ahi_id :: AccountHolderIdentity,
                                      ahi_idCredPub :: PublicIdenityCredentials, 
                                      ahi_idCredSec :: SecretIdenityCredentials, 
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
    deriving (Generic )

instance Serialize AccountCreationInformation where

data AccountHolderCertificate = AHC { ahc_ipId :: IdentityProviderIdentity,
                                      ahc_ahi  :: AccountHolderInformation,
                                      ahc_sig  :: Signature CL
                                     }
