{-# LANGUAGE GeneralizedNewtypeDeriving, RecordWildCards, OverloadedStrings #-}
{-# LANGUAGE TypeFamilies, ExistentialQuantification, FlexibleContexts, DeriveGeneric, DerivingVia #-}
module Concordium.ID.Types where

import Data.Word
import           Data.ByteString    (ByteString, empty)
import qualified Data.ByteString as BS
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

-- Public key of Anonimity Revoker (Elgamal)
newtype AnonimityRevokerPublicKey = AR_PK ByteString
    deriving(Eq)
    deriving Show via ByteStringHex

-- Name of Identity Revoker
newtype AnonimityRevokerIdentity  = AR_ID ByteString 
    deriving (Eq)
    deriving Show via ByteStringHex
    deriving Serialize via Short65K

-- Name of Identity Provider
newtype IdentityProviderIdentity  = IP_ID ByteString
    deriving (Eq, Hashable)
    deriving Show via ByteStringHex
    deriving Serialize via Short65K

-- Public key of Identity provider
newtype IdentityProviderPublicKey = IP_PK ByteString
    deriving(Eq, Hashable)
    deriving Show via ByteStringHex
    deriving Serialize via Short65K

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
    deriving Serialize via Short65K

-- encryption key for accounts (Elgamal?)
newtype AccountEncryptionKey = EncKeyAcc ByteString 
    deriving (Eq)
    deriving Show via ByteStringHex
    deriving Serialize via Short65K

data RegIdSize

instance FBS.FixedLength RegIdSize where
  fixedLength _ = 48

-- |Credential Registration ID (48 bytes)
newtype CredentialRegistrationID = RegIdCred (FBS.FixedByteString RegIdSize)
    deriving (Eq, Ord)
    deriving Show via (FBSHex RegIdSize)
    deriving Serialize via (FBSHex RegIdSize)

newtype Proofs = Proofs ByteString
    deriving(Eq)
    deriving(Show) via ByteStringHex

-- |NB: This puts the length information up front, which is possibly not what we
-- want.
instance Serialize Proofs where
  put (Proofs bs) = 
    putWord32be (fromIntegral (BS.length bs)) <>
    putByteString bs
  get = do
    l <- fromIntegral <$> getWord32be
    Proofs <$> getByteString l

-- |Maximum size of an attribute in bytes.
-- This is determined by the field element size.
data AttributeSize

instance FBS.FixedLength AttributeSize where
  fixedLength _ = 32

newtype AttributeValue = AttributeValue (FBS.FixedByteString AttributeSize)
    deriving(Eq)
    deriving(Show) via (FBSHex AttributeSize)
    deriving(Serialize) via (FBSHex AttributeSize)

-- |For the moment the policies we support are simply opening of specific commitments.
data PolicyItem = PolicyItem {
  -- |What index in the attribute list this belongs to.
  -- NB: Maximum length of attribute list is 2^16
  piIndex :: Word16,
  -- |Value (i.e., opening of the commitment).
  piValue :: AttributeValue
  } deriving(Eq, Show)

data Policy = Policy {
  -- |Variant of the attribute list this policy belongs to.
  pAttributeListVariant :: Word16,
  -- |Expiry date of this credential. In seconds since unix epoch.
  pExpiry :: Word64,
  -- |List of items in this attribute list.
  pItems :: [PolicyItem]
  } deriving(Eq, Show)

-- |Unique identifier of the anonymity revoker. At most 65k bytes in length.
newtype ARName = ARName ByteString
    deriving(Show, Eq)
    deriving Serialize via Short65K

-- |Encryption of data with anonymity revoker's public key.
newtype AREnc = AREnc ByteString
    deriving(Eq)
    deriving Show via ByteStringHex
    deriving Serialize via Short65K

data AnonymityRevocationData = AnonymityRevocationData {
  -- |Unique identifier of the anonimity revoker.
  ardName :: ARName,
  -- |Encryption of the prf key with the anonymity revoker's public key.
  ardPrfKeyEnc :: AREnc,
  -- |Encryption of the public credentials with the anonymity revoker's public key.
  ardIdCredPubEnc :: AREnc
  } deriving(Eq, Show)

instance Serialize AnonymityRevocationData where
  put AnonymityRevocationData{..} =
    put ardName <>
    put ardPrfKeyEnc <>
    put ardIdCredPubEnc
  get = AnonymityRevocationData <$> get <*> get <*> get


data CredentialDeploymentValues = CredentialDeploymentValues {
  -- |Signature scheme of the account to which this credential is deployed.
  cdvSigScheme :: SchemeId,
  -- |The verification (public) key of the account to which this credential is
  -- deployed.
  cdvVerifyKey  :: AccountVerificationKey,
  -- |Registration id of __this__ credential.
  cdvRegId     :: CredentialRegistrationID,
  -- |Identity of the identity provider who signed the identity object from
  -- which this credential is derived.
  cdvIpId      :: IdentityProviderIdentity,
  -- |Policy. At the moment only opening of specific commitments.
  cdvPolicy :: Policy
} deriving(Eq, Show)


getPolicy :: Get Policy
getPolicy = do
  pAttributeListVariant <- getWord16be
  pExpiry <- getWord64be
  l <- fromIntegral <$> getWord16be
  pItems <- replicateM l getPolicyItem 
  return Policy{..}

getPolicyItem :: Get PolicyItem
getPolicyItem = do
  piIndex <- getWord16be
  piValue <- get
  return PolicyItem{..}

putPolicy :: Putter Policy
putPolicy Policy{..} =
  let l = length pItems
  in putWord16be pAttributeListVariant <>
     putWord64be pExpiry <>
     putWord16be (fromIntegral l) <>
     mapM_ putPolicyItem pItems

putPolicyItem :: Putter PolicyItem
putPolicyItem PolicyItem{..} = 
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
