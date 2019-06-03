{-# LANGUAGE TypeFamilies, ExistentialQuantification, FlexibleContexts, DeriveGeneric #-}
module Concordium.ID.Types where

import qualified Data.ByteString    as BS
import           Data.ByteString    (ByteString)
import qualified Data.ByteString.Lazy.Char8 as LC
import           Data.ByteString.Builder(toLazyByteString, byteStringHex)
import           Data.Time
import           Data.Word
import qualified Data.FixedByteString as FBS
import           Concordium.ID.Attributes
import           Concordium.Crypto.SignatureScheme
import           Concordium.Crypto.PRF
import           Data.Serialize
import           GHC.Generics
import           Data.Typeable
import           Data.Hashable
import Foreign.Storable(peek)
import Foreign.Ptr(castPtr)
import Data.Base58String.Bitcoin
import System.IO.Unsafe


accountAddressSize = 21
data AccountAddressSize
instance FBS.FixedLength AccountAddressSize where
    fixedLength _ = accountAddressSize

newtype AccountAddress =  AccountAddress (FBS.FixedByteString AccountAddressSize)
    deriving(Eq, Ord, Generic)

instance Serialize AccountAddress where
    put (AccountAddress h) = putByteString $ FBS.toByteString h
    get = AccountAddress . FBS.fromByteString <$> getByteString accountAddressSize

instance Hashable AccountAddress where
    hashWithSalt s (AccountAddress b) = hashWithSalt s (FBS.toByteString b)
    hash (AccountAddress b) = unsafeDupablePerformIO $ FBS.withPtr b $ \p -> peek (castPtr p)


instance Show AccountAddress where
  show = show . addressToBase58
     where addressToBase58 (AccountAddress x) = fromBytes $ FBS.toByteString x

newtype CredentialHolderIdentity = CH ByteString
    deriving(Eq, Show)

instance Serialize CredentialHolderIdentity where
    put (CH x) = put x 
    get = CH <$> get

-- Secret Key of Credential Holder
newtype CredentialHolderSecretKey = CH_SK ByteString
    deriving(Eq, Show)

instance Serialize CredentialHolderSecretKey where 
    put (CH_SK x) = put x
    get = CH_SK <$> get


-- Public Key of Credential Holder
newtype CredentialHolderPublicKey = CH_PK ByteString
    deriving(Eq, Show)


-- Public key of Anonimity Revoker (Elgamal)
newtype AnonimityRevokerPublicKey = AR_PK ByteString
    deriving(Eq, Show)

-- Private key of Anonimity Revoker (Elgamal)
newtype AnonimityRevokerPrivateKey = AR_SK ByteString
    deriving(Eq, Show)

-- Name of Identity Revoker
newtype AnonimityRevokerIdentity  = AR_ID ByteString 
    deriving (Eq, Show)

instance Serialize AnonimityRevokerIdentity  where
    put (AR_ID s) = put s
    get  = AR_ID <$> get 

data AnonimityRevoker = AR AnonimityRevokerIdentity AnonimityRevokerPublicKey

-- Name of Idenity Provider
newtype IdentityProviderIdentity  = IP_ID ByteString
    deriving (Eq, Show)

instance Serialize IdentityProviderIdentity where
    put (IP_ID s) = put s
    get  = IP_ID <$> get

-- Public key of Identity provider ()
newtype IdentityProviderPublicKey = IP_PK ByteString

-- Private key of Identity provider ()
newtype IdentityProviderSecretKey = IP_SK ByteString

data IdentityProvider = IP IdentityProviderIdentity IdentityProviderPublicKey
                         

-- Signing key for accounts (eddsa key)
type AccountSigningKey = SignKey  

-- Verification key for accounts (eddsa key)
type AccountVerificationKey = VerifyKey 

-- Account signatures (eddsa key)
type AccountSignature = Signature 



-- decryption key for accounts (Elgamal?)
newtype AccountDecryptionKey = DecKeyAcc ByteString 

-- encryption key for accounts (Elgamal?)
newtype AccountEncryptionKey = EncKeyAcc ByteString 
    deriving (Eq, Show)

instance Serialize AccountEncryptionKey where
    put (EncKeyAcc b) = put b
    get = EncKeyAcc <$> get

-- Credential Registration ID (48 bytes)
newtype CredentialRegistrationID = RegIdCred ByteString 
    deriving (Eq, Ord)

instance Show CredentialRegistrationID where
  show (RegIdCred rid) = LC.unpack . toLazyByteString . byteStringHex $ rid

credentialRegistrationIDSize :: Int 
credentialRegistrationIDSize = 48

instance Serialize CredentialRegistrationID where
    put (RegIdCred b) = putByteString b
    get = RegIdCred <$> getByteString credentialRegistrationIDSize 

-- shared public key
newtype SecretShare = Share ByteString
    deriving (Eq, Show)

instance Serialize SecretShare where
      put (Share s) = put s
      get  = Share <$> get

--AR Data
type AnonimityRevocationData = [(AnonimityRevokerIdentity, SecretShare)] 


-- ZK proofs

data Statement = Statement (ByteString -> Bool)

data Witness = Witness ByteString 

data ZKProof = Proof ByteString 
    deriving (Eq, Generic, Show) -- Eq instance only used for testing.

instance Serialize ZKProof where

data CredentialHolderInformation = CHI { chi_id :: CredentialHolderIdentity,
                                         chi_PK :: CredentialHolderPublicKey, 
                                         chi_sk :: CredentialHolderSecretKey, 
                                         chi_prfKey   :: PrfKey, 
                                         chi_attributeList :: AttributeList 
                                     }

    deriving(Generic, Show)

data CredentialDeploymentInformation = CDI { 
                                             cdi_verifKey :: AccountVerificationKey,
                                             cdi_sigScheme :: SchemeId,
                                             cdi_regId     :: CredentialRegistrationID,
                                             cdi_arData    :: AnonimityRevocationData,
                                             cdi_ipId      :: IdentityProviderIdentity, 
                                             cdi_policy    :: Policy, 
                                             cdi_auxData   :: ByteString,
                                             cdi_proof     :: ZKProof
                                            }
                            deriving (Generic, Show)

-- NB: This makes sense for well-formed data only and is consistent with how accounts are identified internally.
instance Eq CredentialDeploymentInformation where
  cdi1 == cdi2 = cdi_verifKey cdi1 == cdi_verifKey cdi2 && cdi_sigScheme cdi1 == cdi_sigScheme cdi2 &&
      cdi_regId cdi1 == cdi_regId cdi2

instance Serialize CredentialDeploymentInformation where

data CredentialHolderCertificate = CHC { chc_ipId :: IdentityProviderIdentity,
                                         chc_ipPk :: IdentityProviderPublicKey,
                                         chc_chi  :: CredentialHolderInformation,
                                         chc_sig  :: Signature 
                                        }
