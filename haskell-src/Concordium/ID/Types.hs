{-# LANGUAGE GeneralizedNewtypeDeriving, RecordWildCards #-}
{-# LANGUAGE TypeFamilies, ExistentialQuantification, FlexibleContexts, DeriveGeneric, DerivingVia #-}
module Concordium.ID.Types where

import Data.Word
import           Data.ByteString    (ByteString, empty)
import qualified Data.FixedByteString as FBS
import           Concordium.Crypto.SignatureScheme
import           Data.Serialize
import           GHC.Generics
import           Data.Hashable
import Foreign.Storable(peek)
import Foreign.Ptr(castPtr)
import Data.Base58String.Bitcoin
import System.IO.Unsafe
import Control.Exception
import Control.Monad
import qualified Data.Text as Text
import Concordium.Crypto.ByteStringHelpers

accountAddressSize :: Int
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
  show = Text.unpack . addressToBase58
     where addressToBase58 (AccountAddress x) = toText . fromBytes $ FBS.toByteString x

-- |Decode an address encoded in base 58. This function is in the IO monad
-- because the library we are using does not support safe parsing.
-- TODO: The library should be replaced.
safeDecodeBase58Address :: ByteString -> IO (Maybe AccountAddress)
safeDecodeBase58Address bs = do
  decoded <- try (evaluate (b58String bs))
  case decoded of
    Left (ErrorCall _) -> return Nothing
    Right dec -> return (Just (AccountAddress . FBS.fromByteString . toBytes $ dec))


newtype CredentialHolderIdentity = CH ByteString
    deriving(Eq, Show)

instance Serialize CredentialHolderIdentity where
    put (CH x) = put x 
    get = CH <$> get

-- Secret Key of Credential Holder
newtype CredentialHolderSecretKey = CH_SK ByteString
    deriving(Eq)
    deriving Show via ByteStringHex

instance Serialize CredentialHolderSecretKey where 
    put (CH_SK x) = put x
    get = CH_SK <$> get

-- Public Key of Credential Holder
newtype CredentialHolderPublicKey = CH_PK ByteString
    deriving(Eq)
    deriving Show via ByteStringHex


-- Public key of Anonimity Revoker (Elgamal)
newtype AnonimityRevokerPublicKey = AR_PK ByteString
    deriving(Eq)
    deriving Show via ByteStringHex

-- Private key of Anonimity Revoker (Elgamal)
newtype AnonimityRevokerPrivateKey = AR_SK ByteString
    deriving(Eq)
    deriving Show via ByteStringHex

-- Name of Identity Revoker
newtype AnonimityRevokerIdentity  = AR_ID ByteString 
    deriving (Eq)
    deriving Show via ByteStringHex

instance Serialize AnonimityRevokerIdentity  where
    put (AR_ID s) = put s
    get  = AR_ID <$> get 

data AnonimityRevoker = AR AnonimityRevokerIdentity AnonimityRevokerPublicKey

-- Name of Identity Provider
newtype IdentityProviderIdentity  = IP_ID ByteString
    deriving (Eq, Hashable)
    deriving Show via ByteStringHex

instance Serialize IdentityProviderIdentity where
    put (IP_ID s) = put s
    get  = IP_ID <$> get

-- Public key of Identity provider ()
newtype IdentityProviderPublicKey = IP_PK ByteString
    deriving(Eq, Hashable)
    deriving Show via ByteStringHex

-- Private key of Identity provider ()
newtype IdentityProviderSecretKey = IP_SK ByteString
    deriving(Eq)
    deriving Show via ByteStringHex


data IdentityProvider = IP IdentityProviderIdentity IdentityProviderPublicKey
                         

-- Signing key for accounts (eddsa key)
type AccountSigningKey = SignKey  

-- Verification key for accounts (eddsa key)
type AccountVerificationKey = VerifyKey 

-- Account signatures (eddsa key)
type AccountSignature = Signature 


-- decryption key for accounts (Elgamal?)
newtype AccountDecryptionKey = DecKeyAcc ByteString 
    deriving(Eq)
    deriving Show via ByteStringHex


-- encryption key for accounts (Elgamal?)
newtype AccountEncryptionKey = EncKeyAcc ByteString 
    deriving (Eq)
    deriving Show via ByteStringHex

instance Serialize AccountEncryptionKey where
    put (EncKeyAcc b) = put b
    get = EncKeyAcc <$> get

-- Credential Registration ID (48 bytes)
newtype CredentialRegistrationID = RegIdCred ByteString 
    deriving (Eq, Ord)
    deriving Show via ByteStringHex


credentialRegistrationIDSize :: Int 
credentialRegistrationIDSize = 48

instance Serialize CredentialRegistrationID where
    put (RegIdCred b) = putByteString b
    get = RegIdCred <$> getByteString credentialRegistrationIDSize 

newtype Proofs = Proofs ByteString
    deriving(Eq)
    deriving(Show) via ByteStringHex

-- |NB: This puts the length information up front, which is possibly not
-- what we want.
instance Serialize Proofs where
  put (Proofs bs) = put bs
  get = Proofs <$> get

-- |Maximum size of an attribute in bytes.
-- This is determined by the field element size.
data AttributeMaxSize

instance FBS.FixedLength AttributeMaxSize where
  fixedLength _ = 31

newtype AttributeValue = AttributeValue (FBS.FixedByteString AttributeMaxSize)
    deriving(Eq)
    deriving(Show) via (FBSHex AttributeMaxSize)
    deriving(Serialize) via (FBSHex AttributeMaxSize)

-- |For the moment the policies we support are simply opening of specific commitments.
data PolicyItem = PolicyItem {
  -- |Variant of the attribute list this policy item belongs to.
  piAttributeListVariant :: Word16,
  -- |What index in the attribute list this belongs to.
  -- NB: Maximum length of attribute list is 2^16
  piIndex :: Word16,
  -- |Value (i.e., opening of the commitment).
  piValue :: AttributeValue
  } deriving(Eq, Show)

newtype Policy = Policy [PolicyItem]
    deriving(Eq, Show)

data CredentialDeploymentValues = CredentialDeploymentValues {
  -- |Signature scheme of the account to which this credential is deployed.
  cdvSigScheme :: SchemeId,
  -- |The verification (public) key of the account to which this credential is
  -- deployed.
  cdvVerifyKey  :: AccountVerificationKey,
  -- |Registration id of __this__ credential.
  cdvRegId     :: CredentialRegistrationID,
  -- |Identity of the identity provider who signed the identity object from which this
  -- credential is derived.
  cdvIpId      :: IdentityProviderIdentity,
  -- |Policy.
  cdvPolicy :: Policy
} deriving(Eq, Show)


getPolicy :: Get Policy
getPolicy = do
  l <- fromIntegral <$> getWord16be
  Policy <$> replicateM l getPolicyItem 

getPolicyItem :: Get PolicyItem
getPolicyItem = do
  piAttributeListVariant <- getWord16be
  piIndex <- getWord16be
  piValue <- get
  return PolicyItem{..}

putPolicy :: Putter Policy
putPolicy (Policy p) =
  let l = length p
  in putWord16be (fromIntegral l) <>
     mapM_ putPolicyItem p

putPolicyItem :: Putter PolicyItem
putPolicyItem PolicyItem{..} = 
   putWord16be piAttributeListVariant <>
   putWord16be piIndex <>
   put piValue


instance Serialize CredentialDeploymentValues where
  get = do
    cdvSigScheme <- get
    cdvVerifyKey <- get
    cdvRegId <- get
    cdvIpId <- get
    cdvPolicy <- getPolicy
    return CredentialDeploymentValues{..}

  put CredentialDeploymentValues{..} =
    put cdvSigScheme <>
    put cdvVerifyKey <>
    put cdvRegId <>
    put cdvIpId <>
    putPolicy cdvPolicy

  
-- |The credential deployment information consists of values deployed and the
-- proofs about them.
data CredentialDeploymentInformation = CredentialDeploymentInformation {
  cdiValues :: CredentialDeploymentValues,
  -- |Proofs of validity of this credential. Opaque from the Haskell side, since
  -- we only pass them to Rust to check.
  cdiProofs :: Proofs
  }
  deriving (Show)

-- |This instance should not be used for transaction handling.
-- It is only here so we can serialize genesis data.
instance Serialize CredentialDeploymentInformation where
  put CredentialDeploymentInformation{..} =
    put cdiValues <> put cdiProofs
  get = CredentialDeploymentInformation <$> get <*> get

-- NB: This makes sense for well-formed data only and is consistent with how accounts are identified internally.
instance Eq CredentialDeploymentInformation where
  cdi1 == cdi2 = cdiValues cdi1 == cdiValues cdi2

-- |Partially deserialize the CDI, leaving the proofs as leftover.
-- Designed to be used with 'runGetPartial'.
getCDIPartial :: Get CredentialDeploymentValues
getCDIPartial = do
  cdvSigScheme <- get
  cdvVerifyKey <- get
  cdvRegId <- get
  cdvIpId <- get
  cdvPolicy <- getPolicy
  return CredentialDeploymentValues{..}

deserializeCDIPartial :: ByteString -> Either String (CredentialDeploymentValues, ByteString)
deserializeCDIPartial bs = loop (runGetPartial getCDIPartial bs)
    where loop (Fail err _) = Left err
          loop (Partial k) = loop (k empty)
          loop (Done r rest) = Right (r, rest)
    
