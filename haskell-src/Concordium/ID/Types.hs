{-# LANGUAGE GeneralizedNewtypeDeriving, RecordWildCards, OverloadedStrings, LambdaCase #-}
{-# LANGUAGE TypeFamilies, ExistentialQuantification, FlexibleContexts, DeriveGeneric, DerivingVia, DeriveDataTypeable #-}
module Concordium.ID.Types where

import Data.Word
import Data.Data(Data, Typeable)
import Data.ByteString(ByteString)
import Data.ByteString.Short(ShortByteString)
import qualified Data.ByteString.Short as BSS
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Base16 as BS16
import Concordium.Crypto.SignatureScheme
import Data.Bits
import Data.Serialize as S
import GHC.Generics
import Data.Hashable
import qualified Data.Text.Read as Text
import Data.Text.Encoding as Text
import Data.Aeson hiding (encode, decode)
import Control.Monad
import Control.Monad.Fail hiding(fail)
import qualified Control.Monad.Fail as MF
import qualified Data.Text as Text
import Control.DeepSeq
import Data.Scientific
import System.Random
import qualified Data.HashMap.Strict as HM

import Data.Base58Encoding
import qualified Data.FixedByteString as FBS
import Concordium.Crypto.ByteStringHelpers
import Concordium.Crypto.FFIDataTypes
import qualified Concordium.Crypto.SHA256 as SHA256


accountAddressSize :: Int
accountAddressSize = 32
data AccountAddressSize
   deriving(Data, Typeable)
instance FBS.FixedLength AccountAddressSize where
    fixedLength _ = accountAddressSize

newtype AccountAddress =  AccountAddress (FBS.FixedByteString AccountAddressSize)
    deriving(Eq, Ord, Generic, Data, Typeable)

{-# WARNING randomAccountAddress "DO NOT USE IN PRODUCTION." #-}
randomAccountAddress :: RandomGen g => g -> (AccountAddress, g)
randomAccountAddress g =
  let (g1, g2) = split g
  in (AccountAddress (FBS.pack (take accountAddressSize (randoms g1))), g2)


instance Serialize AccountAddress where
    put (AccountAddress h) = putByteString $ FBS.toByteString h
    get = AccountAddress . FBS.fromByteString <$> getByteString accountAddressSize

instance Hashable AccountAddress where
    hashWithSalt s (AccountAddress b) = hashWithSalt s (FBS.toShortByteString b)
    hash (AccountAddress b) = fromIntegral (FBS.unsafeReadWord64 b)

-- |Show the address in base58check format.
instance Show AccountAddress where
  show = BS8.unpack . addressToBytes

-- |FIXME: Probably make sure the input size is not too big before doing base58check.
instance FromJSON AccountAddress where
  parseJSON v = addressFromText =<< parseJSON v

instance ToJSON AccountAddress where
  toJSON a = String (Text.decodeUtf8 (addressToBytes a))

addressFromText :: MonadFail m => Text.Text -> m AccountAddress
addressFromText = addressFromBytes . Text.encodeUtf8

-- |Convert an address to valid Base58 bytes.
-- Uses version byte 1 for the base58check encoding.
addressToBytes :: AccountAddress -> ByteString
addressToBytes (AccountAddress v) = raw (base58CheckEncode (BS.cons 1 bs))
    where bs = FBS.toByteString v


-- |Take bytes which are presumed valid base58 encoding, and try to deserialize
-- an address.
addressFromBytes :: MonadFail m => BS.ByteString -> m AccountAddress
addressFromBytes bs =
      case base58CheckDecode' bs of
        Nothing -> MF.fail "Base 58 checksum invalid."
        Just x | BS.length x == accountAddressSize + 1 ->
                 let version = BS.head x
                 in if version == 1 then return (AccountAddress (FBS.fromByteString (BS.tail x)))
                    else fail "Unknown base58 check version byte."
               | otherwise -> MF.fail "Wrong address length."


addressFromRegId :: CredentialRegistrationID -> AccountAddress
addressFromRegId (RegIdCred fbs) = AccountAddress (FBS.FixedByteString addr) -- NB: This only works because the sizes are the same
  where SHA256.Hash (FBS.FixedByteString addr) = SHA256.hashShort (FBS.toShortByteString fbs)



-- |Index of the account key needed to determine what key the signature should
-- be checked with.
newtype KeyIndex = KeyIndex Word8
    deriving(Eq, Ord, Show, Enum, Num, Real, Integral)
    deriving S.Serialize via Word8
    deriving FromJSON via Word8
    deriving FromJSONKey via Word8
    deriving ToJSON via Word8
    deriving ToJSONKey via Word8
    deriving Hashable via Word8

data AccountKeys = AccountKeys {
  akKeys :: HM.HashMap KeyIndex VerifyKey,
  akThreshold :: SignatureThreshold
  } deriving(Eq, Show, Ord)

makeAccountKeys :: [VerifyKey] -> SignatureThreshold -> AccountKeys
makeAccountKeys keys akThreshold =
  AccountKeys{
    akKeys = HM.fromList (zip [0..] keys),
    ..
    }

makeSingletonAC :: VerifyKey -> AccountKeys
makeSingletonAC key = makeAccountKeys [key] 1

instance S.Serialize AccountKeys where
  put AccountKeys{..} = do
    S.putWord8 (fromIntegral (length akKeys))
    forM_ (HM.toList akKeys) $ \(idx, key) -> S.put idx <> S.put key
    S.put akThreshold
  get = do
    len <- S.getWord8
    when (len == 0) $ fail "Number of keys out of bounds."
    akKeys <- HM.fromList <$> replicateM (fromIntegral len) (S.getTwoOf S.get S.get)
    akThreshold <- S.get
    return AccountKeys{..}

instance FromJSON AccountKeys where
  parseJSON = withObject "AccountKeys" $ \v -> do
    akThreshold <- v .: "threshold"
    akKeys <- v .: "keys"
    return AccountKeys{..}

{-# INLINE getAccountKey #-}
getAccountKey :: KeyIndex -> AccountKeys -> Maybe VerifyKey
getAccountKey idx keys = HM.lookup idx (akKeys keys)

-- |Name of Identity Provider
newtype IdentityProviderIdentity  = IP_ID Word32
    deriving (Eq, Hashable)
    deriving Show via Word32

instance Serialize IdentityProviderIdentity where
  put (IP_ID w) = S.putWord32be w

  get = IP_ID <$> S.getWord32be

-- Public key of the Identity provider
newtype IdentityProviderPublicKey = IP_PK PsSigKey
    deriving(Eq, Show, Serialize, NFData)

instance ToJSON IdentityProviderIdentity where
  toJSON (IP_ID v) = toJSON v

instance FromJSON IdentityProviderIdentity where
  parseJSON v = IP_ID <$> parseJSON v

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

-- |Expiry time of a credential.
type CredentialExpiryTime = Word64

data Policy = Policy {
  -- |Variant of the attribute list this policy belongs to.
  pAttributeListVariant :: Word16,
  -- |Expiry date of this credential. In seconds since unix epoch.
  pExpiry :: CredentialExpiryTime,
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
  put (ARName n) = S.putWord32be n
  get = ARName <$> S.getWord32be

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

newtype ShareNumber = ShareNumber Word32
    deriving (Eq, Show, Ord)
    deriving (FromJSON, ToJSON) via Word32

instance Serialize ShareNumber where
  put (ShareNumber n) = S.putWord32be n
  get = ShareNumber <$> S.getWord32be

newtype Threshold = Threshold Word32
    deriving (Eq, Show, Ord)
    deriving (FromJSON, ToJSON) via Word32

instance Serialize Threshold where
  put (Threshold n) = S.putWord32be n
  get = Threshold <$> S.getWord32be


-- |Data needed on-chain to revoke anonymity of the account holder.
data ChainArData = ChainArData {
  -- |Unique identifier of the anonimity revoker.
  ardName :: !ARName,
  -- |Encrypted share of id cred pub
  ardIdCredPubShare :: !AREnc,
  -- |The share number of this share.
  ardIdCredPubShareNumber :: !ShareNumber
  } deriving(Eq, Show)


instance ToJSON ChainArData where
  toJSON (ChainArData{..}) = object [
    "arIdentity" .= ardName,
    "encIdCredPubShare" .=  ardIdCredPubShare,
    "idCredPubShareNumber" .= ardIdCredPubShareNumber
    ]

instance FromJSON ChainArData where
  parseJSON = withObject "ChainArData" $ \v -> do
    ardName <- v .: "arIdentity"
    ardIdCredPubShare <- v .: "encIdCredPubShare"
    ardIdCredPubShareNumber <- v .: "idCredPubShareNumber"
    return ChainArData{..}

instance Serialize ChainArData where
  put ChainArData{..} =
    put ardName <>
    put ardIdCredPubShare <>
    put ardIdCredPubShareNumber
  get = ChainArData <$> get <*> get <*> get

type AccountVerificationKey = VerifyKey

-- |The number of keys required to sign the message.
-- The value is at least 1 and at most 255.
newtype SignatureThreshold = SignatureThreshold Word8
    deriving(Eq, Ord, Show, Enum, Num, Real, Integral)
    deriving Serialize via Word8

instance ToJSON SignatureThreshold where
  toJSON (SignatureThreshold x) = toJSON x

instance FromJSON SignatureThreshold where
  parseJSON v = do
    x <- parseJSON v
    unless (x <= (255::Word) || x >= 1) $ fail "Signature threshold out of bounds."
    return $! SignatureThreshold (fromIntegral x)

-- |Data about which account this credential belongs to.
data CredentialAccount =
  ExistingAccount !AccountAddress
  -- | Create a new account. The list of keys must be non-empty and no longer
  -- than 255 elements.
  | NewAccount ![AccountVerificationKey] !SignatureThreshold
  deriving(Eq, Show)

instance ToJSON CredentialAccount where
  toJSON (ExistingAccount x) = toJSON x
  toJSON (NewAccount keys threshold) = object [
    "keys" .= keys,
    "threshold" .= threshold
    ]

instance FromJSON CredentialAccount where
  parseJSON (Object obj) = do
    keys <- obj .: "keys"
    when (null keys) $ fail "The list of keys must be non-empty."
    let len = length keys
    unless (len <= 255) $ fail "The list of keys must be no longer than 255 elements."
    threshold <- obj .:? "threshold" .!= fromIntegral (length keys) -- default to all the keys as a threshold
    return $! NewAccount keys threshold
  parseJSON v = ExistingAccount <$> parseJSON v

instance Serialize CredentialAccount where
  put (ExistingAccount x) = S.putWord8 0 <> S.put x
  put (NewAccount keys threshold) = S.putWord8 1 <> do
      S.putWord8 (fromIntegral (length keys))
      mapM_ S.put keys
      S.put threshold

  get =
    S.getWord8 >>= \case
      0 -> ExistingAccount <$> S.get
      1 -> do
        len <- S.getWord8
        unless (len >= 1) $ fail "The list of keys must be non-empty and at most 255 elements long."
        keys <- replicateM (fromIntegral len) S.get
        threshold <- S.get
        return $! NewAccount keys threshold
      _ -> fail "Input must be either an existing account or a new account with a list of keys and threshold."

data CredentialDeploymentValues = CredentialDeploymentValues {
  -- |Either an address of an existing account, or the list of keys the newly
  -- created account should have, together with a threshold for how many are needed
  -- Its address is derived from the registration id of this credential.
  cdvAccount :: !CredentialAccount,
  -- |Registration id of __this__ credential.
  cdvRegId     :: !CredentialRegistrationID,
  -- |Identity of the identity provider who signed the identity object from
  -- which this credential is derived.
  cdvIpId      :: !IdentityProviderIdentity,
  -- |Revocation threshold. Any set of this many anonymity revokers can reveal IdCredPub.
  cdvThreshold :: !Threshold,
  -- |Anonymity revocation data associated with this credential.
  cdvArData :: ![ChainArData],
  -- |Policy. At the moment only opening of specific commitments.
  cdvPolicy :: !Policy
} deriving(Eq, Show)

credentialAccountAddress :: CredentialDeploymentValues -> AccountAddress
credentialAccountAddress cdv =
  case cdvAccount cdv of
    ExistingAccount addr -> addr
    _ -> addressFromRegId (cdvRegId cdv)

instance ToJSON CredentialDeploymentValues where
  toJSON CredentialDeploymentValues{..} =
    object [
    "account" .= cdvAccount,
    "regId" .= cdvRegId,
    "ipIdentity" .= cdvIpId,
    "revocationThreshold" .= cdvThreshold,
    "arData" .= cdvArData,
    "policy" .= cdvPolicy
    ]

instance FromJSON CredentialDeploymentValues where
  parseJSON = withObject "CredentialDeploymentValues" $ \v -> do
    cdvAccount <- v .: "account"
    cdvRegId <- v .: "regId"
    cdvIpId <- v .: "ipIdentity"
    cdvThreshold <- v.: "revocationThreshold"
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
    cdvAccount <- get
    cdvRegId <- get
    cdvIpId <- get
    cdvThreshold <- get
    l <- S.getWord16be
    cdvArData <- replicateM (fromIntegral l) get
    cdvPolicy <- getPolicy
    return CredentialDeploymentValues{..}

  put CredentialDeploymentValues{..} =
    put cdvAccount <>
    put cdvRegId <>
    put cdvIpId <>
    put cdvThreshold <>
    S.putWord16be (fromIntegral (length cdvArData)) <>
    mapM_ put cdvArData <>
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
