{-# LANGUAGE GeneralizedNewtypeDeriving, RecordWildCards, OverloadedStrings, LambdaCase #-}
{-# LANGUAGE TypeFamilies, ExistentialQuantification, FlexibleContexts, DeriveGeneric, DerivingVia, DeriveDataTypeable #-}
{-# LANGUAGE TemplateHaskell #-}
module Concordium.ID.Types where

import Data.Word
import Data.Data(Data, Typeable)
import Data.ByteString(ByteString)
import Data.ByteString.Short(ShortByteString)
import qualified Data.ByteString.Short as BSS
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as BS16
import qualified Data.FixedByteString as FBS
import Concordium.Crypto.SignatureScheme
import Data.Bits
import Data.Serialize
import qualified Data.Serialize.Put as Put
import qualified Data.Serialize.Get as Get
import GHC.Generics
import Data.Hashable
import qualified Data.Text.Read as Text
import Data.Text.Encoding as Text
import Data.Aeson hiding (encode, decode)
import Control.Monad
import qualified Data.Text as Text
import Concordium.Crypto.ByteStringHelpers
import Concordium.Crypto.FFIDataTypes
import Control.DeepSeq

import Data.Scientific

import Data.Base58Encoding

accountAddressSize :: Int
accountAddressSize = 21
data AccountAddressSize
   deriving(Data, Typeable)
instance FBS.FixedLength AccountAddressSize where
    fixedLength _ = accountAddressSize

newtype AccountAddress =  AccountAddress (FBS.FixedByteString AccountAddressSize)
    deriving(Eq, Ord, Generic, Data, Typeable)

instance Serialize AccountAddress where
    put (AccountAddress h) = putByteString $ FBS.toByteString h
    get = AccountAddress . FBS.fromByteString <$> getByteString accountAddressSize

instance Hashable AccountAddress where
    hashWithSalt s (AccountAddress b) = hashWithSalt s (FBS.toShortByteString b)
    -- |FIXME: The first byte of the address is mostly the same so this method is not the best.
    hash (AccountAddress b) = fromIntegral (FBS.unsafeReadWord64 b)

-- |Show the address in base58check format.
instance Show AccountAddress where
  show (AccountAddress x) = show . base58CheckEncode . FBS.toByteString $ x

-- |FIXME: Probably make sure the input size is not too big before doing base58check.
instance FromJSON AccountAddress where
  parseJSON v = do
    b58 <- parseJSON v
    case base58CheckDecode b58 of
      Nothing -> fail "Base 58 checksum invalid."
      Just x | BS.length x == accountAddressSize ->
               return (AccountAddress (FBS.fromByteString x))
             | otherwise -> fail "Address of incorrect length."

instance ToJSON AccountAddress where
  toJSON (AccountAddress v) = toJSON (base58CheckEncode (FBS.toByteString v))

addressFromText :: Text.Text -> Maybe AccountAddress
addressFromText text =
  case fromJSON (String text) of
    Error _ -> Nothing
    Success r -> Just r

-- |Take bytes which are presumed valid base58 encoding, and try to deserialize
-- an address.
addressFromBytes :: BS.ByteString -> Maybe AccountAddress
addressFromBytes bs =
  if checkValidBase58 bs then
    case base58CheckDecode' bs of 
      Nothing -> Nothing
      Just x | BS.length x == accountAddressSize -> Just (AccountAddress (FBS.fromByteString x))
             | otherwise -> Nothing
  else Nothing

-- |Name of Identity Provider
newtype IdentityProviderIdentity  = IP_ID Word32
    deriving (Eq, Hashable)
    deriving Show via Word32

instance Serialize IdentityProviderIdentity where
  put (IP_ID w) = Put.putWord32be w

  get = IP_ID <$> Get.getWord32be

-- Public key of the Identity provider
newtype IdentityProviderPublicKey = IP_PK PsSigKey
    deriving(Eq, Show, Serialize, NFData)

instance ToJSON IdentityProviderIdentity where
  toJSON (IP_ID v) = toJSON v

instance FromJSON IdentityProviderIdentity where
  parseJSON v = IP_ID <$> parseJSON v

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

-- |We assume an non-negative integer.
newtype AttributeValue = AttributeValue Integer
  deriving(Show, Eq)

-- |Unroll a positive integer into little-endian bytes.
unroll :: Integer -> [Word8]
unroll v | v < 0 = error "Negative integer, precondition violated."
         | v == 0 = [0]
         | otherwise = go v
  where go 0 = []
        go n = let (d, m) = divMod n 256
               in fromIntegral m : go d

instance Serialize AttributeValue where
    put (AttributeValue i) =
        let bytes = unroll i in
          putWord8 (fromIntegral (length bytes)) <>
          mapM_ putWord8 (reverse bytes)

    get = do
      l <- getWord8
      if l <= 31 then do
        bytes <- replicateM (fromIntegral l) getWord8
        return . AttributeValue $! foldl (\acc b -> acc `shiftL` 8 + fromIntegral b) 0 bytes
      else fail "Attribute malformed. Must fit into 31 bytes."

instance ToJSON AttributeValue where
  toJSON (AttributeValue v) = String (Text.pack (show v))

instance FromJSON AttributeValue where
  parseJSON (String s) =
    case Text.decimal s of
      Left err -> fail err
      Right (i, rest)
          | Text.null rest -> do
              if i >= 0 && i < 2^(248 :: Word) then
                return (AttributeValue i)
              else fail "Input out of range."
          | otherwise -> fail $ "Input malformed, remaining input: " ++ Text.unpack rest

  parseJSON (Number n) = do
    case toBoundedInteger n :: Maybe Word64 of
      Just x -> return (AttributeValue (fromIntegral x))
      Nothing -> fail "Not an integer in correct range."

  parseJSON _ = fail "Attribute value must be either a string or an int."

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
  toJSON Policy{..} = object [
    "variant" .= pAttributeListVariant,
    "expiry" .= pExpiry,
    "revealedItems" .= pItems
    ]

instance FromJSON Policy where
  parseJSON = withObject "Policy" $ \v -> do
    pAttributeListVariant <- v .: "variant"
    pExpiry <- v .: "expiry"
    pItems <- v .: "revealedItems"
    return Policy{..}

-- |Unique identifier of the anonymity revoker.
newtype ARName = ARName Word32
    deriving(Eq)
    deriving Show via Word32

instance Serialize ARName where
  put (ARName n) = Put.putWord32be n
  get = ARName <$> Get.getWord32be

-- |Public key of an anonymity revoker.
newtype AnonymityRevokerPublicKey = AnonymityRevokerPublicKey ElgamalPublicKey
    deriving(Eq, Serialize, NFData)
    deriving Show via ElgamalPublicKey

instance ToJSON ARName where
  toJSON (ARName v) = toJSON v

-- |NB: This just reads the string. No decoding.
instance FromJSON ARName where
  parseJSON v = ARName <$> parseJSON v

-- |Encryption of data with anonymity revoker's public key.
newtype AREnc = AREnc ElgamalCipher
    deriving(Eq, Serialize)
    deriving Show via ElgamalCipher
    deriving ToJSON via ElgamalCipher

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
    "arIdentity" .= ardName,
    "idCredPubEnc" .= ardIdCredPubEnc
    ]

instance FromJSON AnonymityRevocationData where
  parseJSON = withObject "AnonymityRevocationData" $ \v -> do
    ardName <- v .: "arIdentity"
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
