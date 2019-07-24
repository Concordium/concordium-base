{-# LANGUAGE GeneralizedNewtypeDeriving, RecordWildCards, OverloadedStrings, LambdaCase #-}
{-# LANGUAGE TypeFamilies, ExistentialQuantification, FlexibleContexts, DeriveGeneric, DerivingVia #-}
{-# LANGUAGE TemplateHaskell #-}
module Concordium.ID.Types where

import Data.Word
import Data.ByteString(ByteString)
import Data.ByteString.Short(ShortByteString)
import qualified Data.ByteString.Short as BSS
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as BS16
import qualified Data.FixedByteString as FBS
import Concordium.Crypto.SignatureScheme
import Data.Serialize
import GHC.Generics
import Data.Hashable
import Data.Text.Encoding as Text
import Data.Aeson hiding (encode, decode)
import Data.Base58String.Bitcoin
import Control.Exception
import Control.Monad
import qualified Data.Text as Text
import Concordium.Crypto.ByteStringHelpers
import Concordium.Crypto.FFIDataTypes

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
    hashWithSalt s (AccountAddress b) = hashWithSalt s (FBS.toShortByteString b)
    -- |FIXME: The first byte of the address is mostly the same so this method is not the best.
    hash (AccountAddress b) = fromIntegral (FBS.unsafeReadWord64 b)

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

-- Name of Identity Provider
newtype IdentityProviderIdentity  = IP_ID ShortByteString
    deriving (Eq, Hashable)
    deriving Show via ShortByteString
    deriving Serialize via Short65K

-- Public key of the Identity provider
newtype IdentityProviderPublicKey = IP_PK PsSigKey
    deriving(Eq, Show, Serialize)

instance ToJSON IdentityProviderIdentity where
  toJSON (IP_ID v) = String (Text.decodeUtf8 (BSS.fromShort v))

instance FromJSON IdentityProviderIdentity where
  parseJSON v = IP_ID . BSS.toShort . encodeUtf8 <$> parseJSON v

-- Signing key for accounts (eddsa key)
type AccountSigningKey = SignKey

-- Verification key for accounts (eddsa key)
type AccountVerificationKey = VerifyKey

-- Account signatures (eddsa key)
type AccountSignature = Signature

-- decryption key for accounts (Elgamal?)
newtype AccountDecryptionKey = DecKeyAcc ShortByteString
    deriving(Eq)
    deriving Show via Short65K
    deriving Serialize via Short65K

-- encryption key for accounts (Elgamal?)
newtype AccountEncryptionKey = EncKeyAcc ShortByteString
    deriving (Eq)
    deriving Show via Short65K
    deriving Serialize via Short65K

data RegIdSize

instance FBS.FixedLength RegIdSize where
  fixedLength _ = 48

-- |Credential Registration ID (48 bytes)
newtype CredentialRegistrationID = RegIdCred (FBS.FixedByteString RegIdSize)
    deriving (Eq, Ord)
    deriving Show via (FBSHex RegIdSize)
    deriving Serialize via (FBSHex RegIdSize)

instance ToJSON CredentialRegistrationID where
  toJSON v = String (Text.pack (show v))

-- Data (serializes with `putByteString :: Bytestring -> Put`)
instance FromJSON CredentialRegistrationID where
  parseJSON = withText "Credential registration ID in base16" deserializeBase16

newtype Proofs = Proofs ShortByteString
    deriving(Eq)
    deriving(Show) via ByteStringHex
    deriving(ToJSON) via ByteStringHex
    deriving(FromJSON) via ByteStringHex

-- |NB: This puts the length information up front, which is possibly not what we
-- want.
instance Serialize Proofs where
  put (Proofs bs) =
    putWord32be (fromIntegral (BSS.length bs)) <>
    putShortByteString bs
  get = do
    l <- fromIntegral <$> getWord32be
    Proofs <$> getShortByteString l

data AttributeValue =
  ATWord8 !Word8
  | ATWord16 !Word16
  | ATWord32 !Word32
  | ATWord64 !Word64
  deriving(Show, Eq)

instance Serialize AttributeValue where
    put (ATWord8 w) = putWord8 0 <> putWord8 w
    put (ATWord16 w) = putWord8 1 <> putWord16be w
    put (ATWord32 w) = putWord8 2 <> putWord32be w
    put (ATWord64 w) = putWord8 3 <> putWord64be w

    get = getWord8 >>= \case
      0 -> ATWord8 <$> getWord8
      1 -> ATWord16 <$> getWord16be
      2 -> ATWord32 <$> getWord32be
      3 -> ATWord64 <$> getWord64be
      _ -> fail "Uknown attribute type."

instance ToJSON AttributeValue where
  toJSON v = String (serializeBase16 v)

instance FromJSON AttributeValue where
  parseJSON = withText "AttributeValue" deserializeBase16

-- |For the moment the policies we support are simply opening of specific commitments.
data PolicyItem = PolicyItem {
  -- |What index in the attribute list this belongs to.
  -- NB: Maximum length of attribute list is 2^16
  piIndex :: Word16,
  -- |Value (i.e., opening of the commitment).
  piValue :: AttributeValue
  } deriving(Eq, Show)

instance ToJSON PolicyItem where
  toJSON PolicyItem{..} =
    object [
    "index" .= piIndex,
    "piValue" .= piValue
    ]

instance FromJSON PolicyItem where
  parseJSON = withObject "PolicyItem" $ \v -> do
    piIndex <- v .: "index"
    piValue <- v .: "value"
    return PolicyItem{..}

data Policy = Policy {
  -- |Variant of the attribute list this policy belongs to.
  pAttributeListVariant :: Word16,
  -- |Expiry date of this credential. In seconds since unix epoch.
  pExpiry :: Word64,
  -- |List of items in this attribute list.
  pItems :: [PolicyItem]
  } deriving(Eq, Show)

instance ToJSON Policy where
  toJSON (Policy{..}) = object [
    "variant" .= pAttributeListVariant,
    "expiry" .= pExpiry,
    "revealedItems" .= toJSON pItems
    ]

instance FromJSON Policy where
  parseJSON = withObject "Policy" $ \v -> do
    pAttributeListVariant <- v .: "variant"
    pExpiry <- v .: "expiry"
    pItems <- v .: "revealedItems"
    return Policy{..}

-- |Unique identifier of the anonymity revoker. At most 65k bytes in length.
newtype ARName = ARName ShortByteString
    deriving(Eq)
    deriving Serialize via Short65K
    deriving Show via ShortByteString

-- |Public key of an anonymity revoker.
newtype AnonymityRevokerPublicKey = AnonymityRevokerPublicKey ElgamalPublicKey
    deriving(Eq, Serialize)
    deriving Show via ElgamalPublicKey

instance ToJSON ARName where
  toJSON (ARName v) = String (Text.decodeUtf8 . BSS.fromShort $ v)

-- |NB: This just reads the string. No decoding.
instance FromJSON ARName where
  parseJSON v = ARName . BSS.toShort . Text.encodeUtf8 <$> parseJSON v

-- |Encryption of data with anonymity revoker's public key.
newtype AREnc = AREnc ElgamalCipher
    deriving(Eq, Serialize)
    deriving Show via ElgamalCipher
    deriving ToJSON via AREnc 

instance FromJSON AREnc where
  parseJSON v = AREnc <$> parseJSON v

-- |Data needed on-chain to revoke anonymity of the account holder.
data AnonymityRevocationData = AnonymityRevocationData {
  -- |Unique identifier of the anonimity revoker.
  ardName :: ARName,
  -- |Encryption of the public credentials with the anonymity revoker's public key.
  ardIdCredPubEnc :: AREnc
  } deriving(Eq, Show)


instance ToJSON AnonymityRevocationData where
  toJSON (AnonymityRevocationData{..}) = object [
    "arName" .= ardName,
    "idCredPubEnc" .= ardIdCredPubEnc
    ]

instance FromJSON AnonymityRevocationData where
  parseJSON = withObject "AnonymityRevocationData" $ \v -> do
    ardName <- v .: "arName"
    ardIdCredPubEnc <- v .: "idCredPubEnc"
    return AnonymityRevocationData{..}

instance Serialize AnonymityRevocationData where
  put AnonymityRevocationData{..} =
    put ardName <>
    put ardIdCredPubEnc
  get = AnonymityRevocationData <$> get <*> get


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
  -- |Anonymity revocation data associated with this credential.
  cdvArData :: AnonymityRevocationData,
  -- |Policy. At the moment only opening of specific commitments.
  cdvPolicy :: Policy
} deriving(Eq, Show)

instance ToJSON CredentialDeploymentValues where
  toJSON CredentialDeploymentValues{..} =
    object [
    "schemeId" .= cdvSigScheme,
    "verifyKey" .= cdvVerifyKey,
    "regId" .= cdvRegId,
    "ipIdentity" .= cdvIpId,
    "arData" .= cdvArData,
    "policy" .= cdvPolicy
    ]

instance FromJSON CredentialDeploymentValues where
  parseJSON = withObject "CredentialDeploymentValues" $ \v -> do
    cdvSigScheme <- v .: "schemeId"
    cdvVerifyKey <- v .: "verifyKey"
    cdvRegId <- v .: "regId"
    cdvIpId <- v .: "ipIdentity"
    cdvArData <- v .: "arData"
    cdvPolicy <- v .: "policy"
    return CredentialDeploymentValues{..}

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
    cdvArData <- get
    cdvPolicy <- getPolicy
    return CredentialDeploymentValues{..}

  put CredentialDeploymentValues{..} =
    put cdvSigScheme <>
    put cdvVerifyKey <>
    put cdvRegId <>
    put cdvIpId <>
    put cdvArData <>
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

-- |NB: This must match the one defined in rust. In particular the
-- proof is serialized with 4 byte length.
instance Serialize CredentialDeploymentInformation where
  put CredentialDeploymentInformation{..} =
    put cdiValues <> put cdiProofs
  get = CredentialDeploymentInformation <$> get <*> get

-- |NB: This makes sense for well-formed data only and is consistent with how accounts are identified internally.
instance Eq CredentialDeploymentInformation where
  cdi1 == cdi2 = cdiValues cdi1 == cdiValues cdi2

instance FromJSON CredentialDeploymentInformation where
  parseJSON = withObject "CredentialDeploymentInformation" $ \v -> do
    cdiValues <- parseJSON (Object v)
    proofsText <- v .: "proofs"
    return CredentialDeploymentInformation{cdiProofs = Proofs (BSS.toShort . fst . BS16.decode . Text.encodeUtf8 $ proofsText),
                                           ..}

-- |Partially deserialize the CDI, leaving the proofs as leftover.
-- Designed to be used with 'runGetPartial'.
getCDIPartial :: Get CredentialDeploymentValues
getCDIPartial = do
  cdvSigScheme <- get
  cdvVerifyKey <- get
  cdvRegId <- get
  cdvIpId <- get
  cdvArData <- get
  cdvPolicy <- getPolicy
  return CredentialDeploymentValues{..}

deserializeCDIPartial :: ByteString -> Either String (CredentialDeploymentValues, ByteString)
deserializeCDIPartial bs = loop (runGetPartial getCDIPartial bs)
    where loop (Fail err _) = Left err
          loop (Partial k) = loop (k BS.empty)
          loop (Done r rest) = Right (r, rest)
