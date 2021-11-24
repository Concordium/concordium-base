{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}

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
import Data.Serialize as S
import GHC.Generics
import Data.Hashable
import qualified Text.Read as Text
import Data.Text.Encoding as Text
import Data.Aeson hiding (encode, decode)
import Data.Aeson.Types(toJSONKeyText, Pair)
import Data.Maybe(fromMaybe)
import qualified Data.Set as Set
import Control.Monad
import Control.Monad.Except
import qualified Data.Text as Text
import Control.DeepSeq
import System.Random
import qualified Data.Map.Strict as Map
import Data.Function

import Data.Base58Encoding

import qualified Data.FixedByteString as FBS
import Concordium.Crypto.ByteStringHelpers
import Concordium.Crypto.FFIDataTypes
import Concordium.ID.Parameters
import Concordium.Common.Time
import qualified Concordium.Crypto.SHA256 as SHA256

accountAddressSize :: Int
accountAddressSize = 32
data AccountAddressSize
   deriving(Data, Typeable)
instance FBS.FixedLength AccountAddressSize where
    fixedLength _ = accountAddressSize

newtype AccountAddress =  AccountAddress (FBS.FixedByteString AccountAddressSize)
    deriving(Eq, Ord, Generic, Data, Typeable)

instance ToJSONKey AccountAddress where
  toJSONKey = toJSONKeyText (Text.decodeUtf8 . addressToBytes)

instance FromJSONKey AccountAddress where
  fromJSONKey = FromJSONKeyTextParser ((\case
                                           Left e -> fail e
                                           Right v -> return v) . addressFromBytes . Text.encodeUtf8)

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
  parseJSON v = do
    r <- addressFromText <$> parseJSON v
    case r of
      Left err -> fail err
      Right a -> return a

instance ToJSON AccountAddress where
  toJSON a = String (Text.decodeUtf8 (addressToBytes a))

addressFromText :: MonadError String m => Text.Text -> m AccountAddress
addressFromText = addressFromBytes . Text.encodeUtf8

-- |Convert an address to valid Base58 bytes.
-- Uses version byte 1 for the base58check encoding.
addressToBytes :: AccountAddress -> ByteString
addressToBytes (AccountAddress v) = raw (base58CheckEncode (BS.cons 1 bs))
    where bs = FBS.toByteString v


-- |Take bytes which are presumed valid base58 encoding, and try to deserialize
-- an address.
addressFromBytes :: MonadError String m => BS.ByteString -> m AccountAddress
addressFromBytes bs =
      case base58CheckDecode' bs of
        Nothing -> throwError "Base 58 checksum invalid."
        Just x | BS.length x == accountAddressSize + 1 ->
                 let version = BS.head x
                 in if version == 1 then return (AccountAddress (FBS.fromByteString (BS.tail x)))
                    else throwError "Unknown base58 check version byte."
               | otherwise -> throwError "Wrong address length."


addressFromRegId :: CredentialRegistrationID -> AccountAddress
addressFromRegId (RegIdCred fbs) = AccountAddress (FBS.FixedByteString addr) -- NB: This only works because the sizes are the same
  where SHA256.Hash (FBS.FixedByteString addr) = SHA256.hash (encode fbs)


-- |Index of the credential key needed to determine what key the signature should
-- be checked with.
newtype KeyIndex = KeyIndex Word8
    deriving (Eq, Ord, Enum, Num, Real, Integral)
    deriving (Hashable, Show, Read, S.Serialize, FromJSON, FromJSONKey, ToJSON, ToJSONKey) via Word8

-- |The public credential keys belonging to a credential holder
data CredentialPublicKeys = CredentialPublicKeys {
  credKeys :: !(Map.Map KeyIndex VerifyKey),
  credThreshold :: !SignatureThreshold
  } deriving(Eq, Show, Ord)

-- |Get the number of keys that are part of the credential.
credNumKeys :: CredentialPublicKeys -> Int
credNumKeys CredentialPublicKeys{..} = Map.size credKeys

-- |Indices of the credentials linked to an account
newtype CredentialIndex = CredentialIndex Word8
    deriving (Eq, Ord, Enum, Num, Real, Integral)
    deriving (Hashable, Show, Read, S.Serialize, FromJSON, FromJSONKey, ToJSON, ToJSONKey) via Word8

-- |The credential index of the initial credential on an account (0).
-- This credential is special as it can never be modified or removed,
-- and is used to derive the account address and account encryption key.
initialCredentialIndex :: CredentialIndex
initialCredentialIndex = 0

-- |The information about an account's credentials necessary for verifying the signature(s) on
-- a transaction. Namely, the account threshold, and for each credential, its threshold and
-- public keys.
data AccountInformation = AccountInformation {
  aiCredentials :: !(Map.Map CredentialIndex CredentialPublicKeys),
  aiThreshold :: !AccountThreshold 
} deriving(Eq, Show, Ord)

getCredentialPublicKeys :: AccountCredential -> CredentialPublicKeys
getCredentialPublicKeys (InitialAC icdv) = icdvAccount icdv
getCredentialPublicKeys (NormalAC cdv _) = cdvPublicKeys cdv

getAccountInformation :: AccountThreshold -> Map.Map CredentialIndex AccountCredential -> AccountInformation
getAccountInformation threshold credentials = AccountInformation {
  aiCredentials = fmap getCredentialPublicKeys credentials,
  aiThreshold = threshold
}

instance S.Serialize AccountInformation where
  put AccountInformation{..} = do
    S.putWord8 (fromIntegral (length aiCredentials))
    forM_ (Map.toAscList aiCredentials) $ \(idx, key) -> S.put idx <> S.put key
    S.put aiThreshold
  get = do
    len <- S.getWord8
    when (len == 0) $ fail "Number of credentials out of bounds."
    aiCredentials <- safeFromAscList =<< replicateM (fromIntegral len) (S.getTwoOf S.get S.get)
    aiThreshold <- S.get
    return AccountInformation{..}

{-# INLINE getCredentialKeys #-}
getCredentialKeys :: CredentialIndex -> AccountInformation -> Maybe CredentialPublicKeys
getCredentialKeys idx ai = Map.lookup idx (aiCredentials ai)

makeCredentialPublicKeys :: [VerifyKey] -> SignatureThreshold -> CredentialPublicKeys
makeCredentialPublicKeys keys credThreshold =
  CredentialPublicKeys{
    credKeys = Map.fromAscList (zip [0..] keys), -- NB: fromAscList does not check preconditions
    ..
    }

makeSingletonAC :: VerifyKey -> CredentialPublicKeys
makeSingletonAC key = makeCredentialPublicKeys [key] 1

-- Build a map from an ascending list.
safeFromAscList :: (MonadFail m, Ord k) => [(k,v)] -> m (Map.Map k v)
safeFromAscList = go Map.empty Nothing
    where go mp _ [] = return mp
          go mp Nothing ((k,v):rest) = go (Map.insert k v mp) (Just k) rest
          go mp (Just k') ((k,v):rest)
              | k' < k = go (Map.insert k v mp) (Just k) rest
              | otherwise = fail "Keys not in ascending order, or duplicate keys."

instance S.Serialize CredentialPublicKeys where
  put CredentialPublicKeys{..} = do
    S.putWord8 (fromIntegral (length credKeys))
    forM_ (Map.toAscList credKeys) $ \(idx, key) -> S.put idx <> S.put key
    S.put credThreshold
  get = do
    len <- S.getWord8
    when (len == 0) $ fail "Number of keys out of bounds."
    credKeys <- safeFromAscList =<< replicateM (fromIntegral len) (S.getTwoOf S.get S.get)
    credThreshold <- S.get
    return CredentialPublicKeys{..}

instance FromJSON CredentialPublicKeys where
  parseJSON = withObject "CredentialPublicKeys" $ \v -> do
    credThreshold <- v .: "threshold"
    credKeys <- v .: "keys"
    return CredentialPublicKeys{..}

instance ToJSON CredentialPublicKeys where
  toJSON CredentialPublicKeys{..} = object [
    "keys" .= credKeys,
    "threshold" .= credThreshold
    ]

{-# INLINE getCredentialPublicKey #-}
getCredentialPublicKey :: KeyIndex -> CredentialPublicKeys -> Maybe VerifyKey
getCredentialPublicKey idx keys = Map.lookup idx (credKeys keys)

getKeyIndices :: CredentialPublicKeys -> Set.Set KeyIndex
getKeyIndices keys = Map.keysSet $ credKeys keys

-- |Name of Identity Provider
newtype IdentityProviderIdentity  = IP_ID Word32
    deriving (Eq, Hashable, Ord)
    deriving newtype (Show, FromJSONKey)

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

-- NB: This instance relies on the show instance being the one of Word32.
instance ToJSONKey IdentityProviderIdentity where
  toJSONKey = toJSONKeyText (Text.pack . show)

-- Account signatures (eddsa key)
type AccountSignature = Signature

-- encryption key for accounts (Elgamal?)
newtype AccountEncryptionKey = AccountEncryptionKey {_elgamalPublicKey :: ElgamalPublicKey}
    deriving (Eq, Show, Serialize, FromJSON, ToJSON) via ElgamalPublicKey

makeEncryptionKey :: GlobalContext -> CredentialRegistrationID -> AccountEncryptionKey
makeEncryptionKey gc (RegIdCred ge) = AccountEncryptionKey (deriveElgamalPublicKey gc ge)

data RegIdSize

instance FBS.FixedLength RegIdSize where
  fixedLength _ = 48

-- |Credential Registration ID (48 bytes)
newtype CredentialRegistrationID = RegIdCred GroupElement
    deriving newtype (Eq, Show, Serialize, ToJSON)

-- Ord instance based on serialization
instance Ord CredentialRegistrationID where
  compare = compare `on` encode

-- This is duplicated from ElgamalPublicKey for better error messages.
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
newtype AttributeValue = AttributeValue ShortByteString
  deriving(Eq)

instance Show AttributeValue where
  show (AttributeValue bytes) = Text.unpack (Text.decodeUtf8 (BSS.fromShort bytes))

instance Serialize AttributeValue where
    put (AttributeValue bytes) =
      putWord8 (fromIntegral (BSS.length bytes)) <>
      putShortByteString bytes

    get = do
      l <- getWord8
      if l <= 31 then do
        bytes <- getShortByteString (fromIntegral l)
        return $! AttributeValue bytes
      else fail "Attribute malformed. Must fit into 31 bytes."

instance ToJSON AttributeValue where
  -- this is safe because the bytestring should contain
  toJSON (AttributeValue v) = String (Text.decodeUtf8 (BSS.fromShort v))

instance FromJSON AttributeValue where
  parseJSON = withText "Attribute value"$ \v -> do
    let s = Text.encodeUtf8 v
    unless (BS.length s <= 31) $ fail "Attribute values must fit into 31 bytes."
    return (AttributeValue (BSS.toShort s))

-- |ValidTo of a credential.
type CredentialValidTo = YearMonth

-- |CreatedAt of a credential.
type CredentialCreatedAt = YearMonth

newtype AttributeTag = AttributeTag Word8
 deriving (Eq, Show, Serialize, Ord, Enum, Num) via Word8

-- *NB: This mapping must be kept consistent with the mapping in id/types.rs.
attributeNames :: [Text.Text]
attributeNames = ["firstName",
                  "lastName",
                  "sex",
                  "dob",
                  "countryOfResidence",
                  "nationality",
                  "idDocType",
                  "idDocNo",
                  "idDocIssuer",
                  "idDocIssuedAt",
                  "idDocExpiresAt",
                  "nationalIdNo",
                  "taxIdNo",
                  "lei"
                 ]

mapping :: Map.Map Text.Text AttributeTag
mapping = Map.fromList $ zip attributeNames [0..]

invMapping :: Map.Map AttributeTag Text.Text
invMapping = Map.fromList $ zip [0..] attributeNames

instance FromJSONKey AttributeTag where
  -- parse values with this key as objects (the default instance uses
  -- association list encoding
  fromJSONKey = FromJSONKeyTextParser (parseJSON . String)

instance ToJSONKey AttributeTag where
  toJSONKey = toJSONKeyText $ (\tag -> fromMaybe (Text.pack ("UNNAMED#" ++ show tag)) $ Map.lookup tag invMapping)

instance FromJSON AttributeTag where
  parseJSON = withText "Attribute name" $ \text -> do
        case Map.lookup text mapping of
          Just x -> return x
          Nothing -> case Text.stripPrefix "UNNAMED#" text >>= Text.readMaybe . Text.unpack of
            Just tag | tag < 254 -> return $ AttributeTag tag -- 254 is the capacity of the field defined by the BLS curve.
            _ -> fail "Unsupported tag."

instance ToJSON AttributeTag where
  toJSON tag = maybe (String (Text.pack ("UNNAMED#" ++ show tag))) toJSON $ Map.lookup tag invMapping

data Policy = Policy {
  -- |Validity of this credential.
  pValidTo :: CredentialValidTo,
  -- |Creation of this credential
  pCreatedAt :: CredentialCreatedAt,
  -- |List of items in this attribute list.
  pItems :: Map.Map AttributeTag AttributeValue
  } deriving(Eq, Show)

instance ToJSON Policy where
  toJSON Policy{..} = object [
    "validTo" .= pValidTo,
    "createdAt" .= pCreatedAt,
    "revealedAttributes" .= pItems
    ]

instance FromJSON Policy where
  parseJSON = withObject "Policy" $ \v -> do
    pValidTo <- v .: "validTo"
    pCreatedAt <- v .: "createdAt"
    pItems <- v .: "revealedAttributes"
    return Policy{..}

-- |Unique identifier of the anonymity revoker.
newtype ArIdentity = ArIdentity Word32
    deriving(Eq, Ord)
    deriving (Show, Hashable) via Word32

instance Serialize ArIdentity where
  put (ArIdentity n) = S.putWord32be n
  get = do
    n <- S.getWord32be
    when (n == 0) $ fail "ArIdentity must be at least 1."
    return (ArIdentity n)

-- |Public key of an anonymity revoker.
newtype AnonymityRevokerPublicKey = AnonymityRevokerPublicKey ElgamalPublicKey
    deriving(Eq, Serialize, NFData)
    deriving Show via ElgamalPublicKey

instance ToJSON ArIdentity where
  toJSON (ArIdentity v) = toJSON v

-- |NB: This just reads the string. No decoding.
instance FromJSON ArIdentity where
  parseJSON v = do
    n <- parseJSON v
    when (n == 0) $ fail "ArIdentity must be at least 1."
    return (ArIdentity n)

instance FromJSONKey ArIdentity where
  fromJSONKey = FromJSONKeyTextParser arIdFromText
      where arIdFromText t = do
              when (Text.length t > 10) $ fail "Out of bounds."
              case Text.readMaybe (Text.unpack t) of
                Nothing -> fail "ArIdentity not an integral value."
                Just i -> do
                  when (i <= 0) $ fail "ArIdentity must be positive."
                  when (i > toInteger (maxBound :: Word32)) $ fail "ArIdentity out of bounds."
                  return (ArIdentity (fromInteger i))

-- NB: This instance relies on the show instance being the one of Word32.
instance ToJSONKey ArIdentity where
  toJSONKey = toJSONKeyText (Text.pack . show)

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

-- |Anonymity revocation threshold.
newtype Threshold = Threshold Word8
    deriving (Eq, Show, Ord)
    deriving (ToJSON) via Word8

instance FromJSON Threshold where
  parseJSON v = do
    n <- parseJSON v
    when (n == 0) $ fail "Threshold must be at least 1."
    return (Threshold n)

instance Serialize Threshold where
  put (Threshold n) = S.putWord8 n
  get = do
    n <- S.getWord8
    when (n == 0) $ fail "Threshold must be at least 1."
    return (Threshold n)

-- |Data needed on-chain to revoke anonymity of the account holder.
newtype ChainArData = ChainArData {
  -- |Encrypted share of id cred pub
  ardIdCredPubShare :: AREnc
  } deriving(Eq, Show)


instance ToJSON ChainArData where
  toJSON ChainArData{..} = object [
    "encIdCredPubShare" .=  ardIdCredPubShare
    ]

instance FromJSON ChainArData where
  parseJSON = withObject "ChainArData" $ \v -> do
    ardIdCredPubShare <- v .: "encIdCredPubShare"
    return ChainArData{..}

instance Serialize ChainArData where
  put ChainArData{..} =
    put ardIdCredPubShare
  get = ChainArData <$> get

type AccountVerificationKey = VerifyKey

-- |The number of keys required to sign the message.
-- The value is at least 1 and at most 255.
newtype SignatureThreshold = SignatureThreshold Word8
    deriving newtype (Eq, Ord, Show, Enum, Num, Real, Integral)

newtype AccountThreshold = AccountThreshold Word8
    deriving newtype (Eq, Ord, Show, Enum, Num, Real, Integral)

instance Serialize SignatureThreshold where
  get = do
    w <- getWord8
    when (w == 0) $ fail "0 is not a valid signature threshold."
    return (SignatureThreshold w)
  put (SignatureThreshold w) = putWord8 w

instance Read SignatureThreshold where
  -- filter out the 0 values
  readsPrec parsePrec input = [(SignatureThreshold w, rest) | (w, rest) <- readsPrec parsePrec input, w /= 0]

instance ToJSON SignatureThreshold where
  toJSON (SignatureThreshold x) = toJSON x

instance FromJSON SignatureThreshold where
  parseJSON v = do
    x <- parseJSON v
    unless (x <= (255::Word) || x >= 1) $ fail "Signature threshold out of bounds."
    return $! SignatureThreshold (fromIntegral x)

instance Serialize AccountThreshold where
  get = do
    w <- getWord8
    when (w == 0) $ fail "0 is not a valid signature threshold."
    return (AccountThreshold w)
  put (AccountThreshold w) = putWord8 w

instance Read AccountThreshold where
  -- filter out the 0 values
  readsPrec parsePrec input = [(AccountThreshold w, rest) | (w, rest) <- readsPrec parsePrec input, w /= 0]

instance ToJSON AccountThreshold where
  toJSON (AccountThreshold x) = toJSON x

instance FromJSON AccountThreshold where
  parseJSON v = do
    x <- parseJSON v
    unless (x <= (255::Word) || x >= 1) $ fail "Signature threshold out of bounds."
    return $! AccountThreshold (fromIntegral x)

-- |Data about which account this credential belongs to.
data CredentialAccount =
  -- | Create a new account. The list of keys must be non-empty and no longer
  -- than 255 elements.
  NewAccount ![AccountVerificationKey] !SignatureThreshold
  deriving(Eq, Show)

instance ToJSON CredentialAccount where
  toJSON (NewAccount keys threshold) = object [
    "keys" .= keys,
    "threshold" .= threshold
    ]

instance FromJSON CredentialAccount where
  parseJSON = withObject "Credential account" $ \obj -> do
    keys <- obj .: "keys"
    when (null keys) $ fail "The list of keys must be non-empty."
    let len = length keys
    unless (len <= 255) $ fail "The list of keys must be no longer than 255 elements."
    threshold <- obj .:? "threshold" .!= fromIntegral (length keys) -- default to all the keys as a threshold
    return $! NewAccount keys threshold

instance Serialize CredentialAccount where
  put (NewAccount keys threshold) = S.putWord8 1 <> do
      S.putWord8 (fromIntegral (length keys))
      mapM_ S.put keys
      S.put threshold

  get =
    S.getWord8 >>= \case
      1 -> do
        len <- S.getWord8
        unless (len >= 1) $ fail "The list of keys must be non-empty and at most 255 elements long."
        keys <- replicateM (fromIntegral len) S.get
        threshold <- S.get
        return $! NewAccount keys threshold
      _ -> fail "Input must be either a new account with a list of keys and threshold."

data CredentialDeploymentValues = CredentialDeploymentValues {
  -- |Either an address of an existing account, or the list of keys the newly
  -- created account should have, together with a threshold for how many are needed
  -- Its address is derived from the registration id of this credential.
  cdvPublicKeys :: !CredentialPublicKeys,
  -- |Registration id of __this__ credential.
  cdvCredId     :: !CredentialRegistrationID,
  -- |Identity of the identity provider who signed the identity object from
  -- which this credential is derived.
  cdvIpId      :: !IdentityProviderIdentity,
  -- |Revocation threshold. Any set of this many anonymity revokers can reveal IdCredPub.
  cdvThreshold :: !Threshold,
  -- |Anonymity revocation data associated with this credential.
  cdvArData :: !(Map.Map ArIdentity ChainArData),
  -- |Policy. At the moment only opening of specific commitments.
  cdvPolicy :: !Policy
} deriving(Eq, Show)

credentialAccountAddress :: CredentialDeploymentValues -> AccountAddress
credentialAccountAddress cdv = addressFromRegId (cdvCredId cdv)

credentialDeploymentValuesList :: CredentialDeploymentValues -> [Pair]
credentialDeploymentValuesList CredentialDeploymentValues{..} =
  [
    "credentialPublicKeys" .= cdvPublicKeys,
    "credId" .= cdvCredId,
    "ipIdentity" .= cdvIpId,
    "revocationThreshold" .= cdvThreshold,
    "arData" .= cdvArData,
    "policy" .= cdvPolicy
  ]

instance ToJSON CredentialDeploymentValues where
  toJSON =
    object . credentialDeploymentValuesList

instance FromJSON CredentialDeploymentValues where
  parseJSON = withObject "CredentialDeploymentValues" $ \v -> do
    cdvPublicKeys <- v .: "credentialPublicKeys"
    cdvCredId <- v .: "credId"
    cdvIpId <- v .: "ipIdentity"
    cdvThreshold <- v.: "revocationThreshold"
    cdvArData <- v .: "arData"
    cdvPolicy <- v .: "policy"
    return CredentialDeploymentValues{..}

getPolicy :: Get Policy
getPolicy = do
  pValidTo <- get
  pCreatedAt <- get
  l <- fromIntegral <$> getWord16be
  pItems <- safeFromAscList =<< replicateM l (getTwoOf get get)
  return Policy{..}

putPolicy :: Putter Policy
putPolicy Policy{..} =
  let l = length pItems
  in put pValidTo <>
     put pCreatedAt <>
     putWord16be (fromIntegral l) <>
     mapM_ (putTwoOf put put) (Map.toAscList pItems)

instance Serialize CredentialDeploymentValues where
  get = do
    cdvPublicKeys <- get
    cdvCredId <- get
    cdvIpId <- get
    cdvThreshold <- get
    l <- S.getWord16be
    cdvArData <- safeFromAscList =<< replicateM (fromIntegral l) get
    cdvPolicy <- getPolicy
    return CredentialDeploymentValues{..}

  put CredentialDeploymentValues{..} =
    put cdvPublicKeys <>
    put cdvCredId <>
    put cdvIpId <>
    put cdvThreshold <>
    S.putWord16be (fromIntegral (length cdvArData)) <>
    mapM_ put (Map.toAscList cdvArData) <>
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
  parseJSON = withObject "CredentialDeploymentInformation" $ \x -> do
    cdiValues <- parseJSON (Object x)
    proofsText <- x .: "proofs"
    let (bs, rest) = BS16.decode . Text.encodeUtf8 $ proofsText
    unless (BS.null rest) $ fail "\"proofs\" is not a valid base16 string."
    return CredentialDeploymentInformation {
        cdiProofs = Proofs (BSS.toShort bs),
        ..
      }


-- |Information about the account that should be created as part of the initial
-- credential deployment.
data InitialCredentialAccount = InitialCredentialAccount {
  icaKeys :: ![AccountVerificationKey],
  icaThreshold :: !SignatureThreshold
} deriving(Eq, Show)

instance ToJSON InitialCredentialAccount where
  toJSON (InitialCredentialAccount keys threshold) = object [
    "keys" .= keys,
    "threshold" .= threshold
    ]

instance FromJSON InitialCredentialAccount where
  parseJSON = withObject "InitialCredentialAccount" $ \v -> do
    icaKeys <- v .: "keys"
    when (null icaKeys) $ fail "The list of keys must be non-empty."
    let len = length icaKeys
    unless (len <= 255) $ fail "The list of keys must be no longer than 255 elements."
    icaThreshold <- v .: "threshold"
    return InitialCredentialAccount{..}

instance Serialize InitialCredentialAccount where
  put InitialCredentialAccount{..} =
      S.putWord8 (fromIntegral (length icaKeys)) <>
      mapM_ S.put icaKeys <>
      S.put icaThreshold

  get = do
    len <- S.getWord8
    unless (len >= 1) $ fail "The list of keys must be non-empty and at most 255 elements long."
    icaKeys <- replicateM (fromIntegral len) S.get
    icaThreshold <- S.get
    return InitialCredentialAccount{..}

-- |The data for the initial account creation. This is submitted by the identity
-- provider on behalf of the account holder.
data InitialCredentialDeploymentValues = InitialCredentialDeploymentValues {
  -- |List of keys the new account should have, together with a threshold
  -- for how many are needed. Its address is derived from the registration
  -- id of this credential.
  icdvAccount :: !CredentialPublicKeys,
  -- |Registration id of __this__ credential.
  icdvRegId :: !CredentialRegistrationID,
  -- |Identity of the identity provider who signed this account creation
  icdvIpId :: !IdentityProviderIdentity,
  -- |Policy.
  icdvPolicy :: !Policy
} deriving(Eq, Show)

-- |Address of the account that is created as a result of the initial credential
-- deployment.
initialCredentialAccountAddress :: InitialCredentialDeploymentValues -> AccountAddress
initialCredentialAccountAddress icdv = addressFromRegId (icdvRegId icdv)

instance ToJSON InitialCredentialDeploymentValues where
  toJSON InitialCredentialDeploymentValues{..} =
    object [
    "credentialPublicKeys" .= icdvAccount,
    "regId" .= icdvRegId,
    "ipIdentity" .= icdvIpId,
    "policy" .= icdvPolicy
    ]

instance FromJSON InitialCredentialDeploymentValues where
  parseJSON = withObject "InitialCredentialDeploymentValues" $ \v -> do
    icdvAccount <- v .: "credentialPublicKeys"
    icdvRegId <- v .: "regId"
    icdvIpId <- v .: "ipIdentity"
    icdvPolicy <- v .: "policy"
    return InitialCredentialDeploymentValues{..}

instance Serialize InitialCredentialDeploymentValues where
  get = do
    icdvAccount <- get
    icdvRegId <- get
    icdvIpId <- get
    icdvPolicy <- getPolicy
    return InitialCredentialDeploymentValues{..}

  put InitialCredentialDeploymentValues{..} =
    put icdvAccount <>
    put icdvRegId <>
    put icdvIpId <>
    putPolicy icdvPolicy

-- |A signature using the Ed25519 signature scheme.
-- Always 64 bytes in length.
newtype IpCdiSignature = IpCdiSignature { theSignature :: ShortByteString }
    deriving (ToJSON, FromJSON, Show) via ByteStringHex

instance Serialize IpCdiSignature where
  put = putShortByteString . theSignature
  get = IpCdiSignature <$> getShortByteString 64

-- |The initial credential deployment information consists of values deployed
-- a signature from the identity provider on said values
data InitialCredentialDeploymentInfo = InitialCredentialDeploymentInfo {
  icdiValues :: InitialCredentialDeploymentValues,
  -- |A signature under the public key of identity provider's key on the
  -- credential deployment values. This is the dual of `proofs` for the normal
  -- credential deployment.
  icdiSig :: IpCdiSignature
  }
  deriving (Show)

-- |NB: This must match the one defined in rust
instance Serialize InitialCredentialDeploymentInfo where
  put InitialCredentialDeploymentInfo{..} =
    put icdiValues <> put icdiSig

  get = do
    icdiValues <- get
    icdiSig <- get
    return InitialCredentialDeploymentInfo {..}

-- |NB: This makes sense for well-formed data only and is consistent with how
-- accounts are identified internally.
instance Eq InitialCredentialDeploymentInfo where
  icdi1 == icdi2 = icdiValues icdi1 == icdiValues icdi2

instance FromJSON InitialCredentialDeploymentInfo where
  parseJSON = withObject "InitialCredentialDeploymentInformation" $ \v -> do
    icdiValues <- parseJSON (Object v)
    icdiSig <- v .: "sig"
    return InitialCredentialDeploymentInfo{..}


-- |Different kinds of credentials that can go onto the chain.
data AccountCredentialWithProofs =
  InitialACWP InitialCredentialDeploymentInfo
  | NormalACWP CredentialDeploymentInformation
  deriving(Eq, Show)

instance Serialize AccountCredentialWithProofs where
  put (InitialACWP icdi) = putWord8 0 <> put icdi
  put (NormalACWP cdi) = putWord8 1 <> put cdi

  get = getWord8 >>= \case
    0 -> InitialACWP <$> get
    1 -> NormalACWP <$> get
    _ -> fail "Unsupported credential type."

-- |Analogue of 'AccountCredentialWithProofs' but with the proofs removed and commitments kept.
data AccountCredential =
  InitialAC InitialCredentialDeploymentValues
  | NormalAC CredentialDeploymentValues CredentialDeploymentCommitments
  deriving(Eq, Show)

data CredentialType = Initial | Normal
    deriving(Eq, Show)

instance FromJSON CredentialType where
  parseJSON = withText "Credential Type" $ \t ->
    if t == "initial" then return Initial
    else if t == "normal" then return Normal
    else fail "Unsupported credential type."

instance ToJSON CredentialType where
  toJSON Initial = String "initial"
  toJSON Normal = String "normal"

instance Serialize CredentialType where
  put Initial = putWord8 0
  put Normal = putWord8 1

  get = getWord8 >>= \case
    0 -> return Initial
    1 -> return Normal
    _ -> fail "Unsupported credential type."

instance Serialize AccountCredential where
  put (InitialAC icdi) = putWord8 0 <> put icdi
  put (NormalAC cdi coms) = putWord8 1 <> put cdi <> put coms

  get = getWord8 >>= \case
    0 -> InitialAC <$> get
    1 -> NormalAC <$> get <*> getCommitments
    _ -> fail "Unsupported credential type."

instance FromJSON AccountCredentialWithProofs where
  parseJSON = withObject "Account credential with proofs" $ \v -> do
    ty <- v .: "type"
    case ty of
      Initial -> InitialACWP <$> v .: "contents"
      Normal -> NormalACWP <$> v .: "contents"

instance FromJSON AccountCredential where
  parseJSON = withObject "Account credential" $ \v -> do
    ty <- v .: "type"
    case ty of
      Initial -> InitialAC <$> v .: "contents"
      Normal -> do
        co <- v .: "contents"
        cdv <- parseJSON co
        coms <- withObject "Credential commitments" (.: "commitments") co
        return $ NormalAC cdv coms

instance ToJSON AccountCredential where
  toJSON (InitialAC icdv) = object ["type" .= Initial, "contents" .= icdv]
  toJSON (NormalAC cdv coms) = object ["type" .= Normal, "contents" .= object (credentialDeploymentValuesList cdv ++ ["commitments" .= coms])]

-- |Helper class to unify access to fields of CredentialDeploymentValues
-- for both the values, as well as values with proofs.
class CredentialValuesFields a where
  -- |Extract the validity information for the credential.
  {-# INLINE validTo #-}
  validTo :: a -> CredentialValidTo
  validTo = pValidTo . policy
  credId :: a -> CredentialRegistrationID
  ipId :: a -> IdentityProviderIdentity
  policy :: a -> Policy
  credPubKeys :: a -> CredentialPublicKeys

instance CredentialValuesFields CredentialDeploymentInformation where
  {-# INLINE credId #-}
  credId = cdvCredId . cdiValues
  {-# INLINE ipId #-}
  ipId = cdvIpId . cdiValues
  {-# INLINE policy #-}
  policy = cdvPolicy . cdiValues
  {-# INLINE credPubKeys #-}
  credPubKeys = cdvPublicKeys . cdiValues

instance CredentialValuesFields AccountCredential where
  credId (NormalAC cdv _) = cdvCredId cdv
  credId (InitialAC icdv) = icdvRegId icdv

  ipId (InitialAC icdv) = icdvIpId icdv
  ipId (NormalAC cdv _) = cdvIpId cdv

  policy (InitialAC icdv) = icdvPolicy icdv
  policy (NormalAC cdv _) = cdvPolicy cdv

  credPubKeys (InitialAC icdv) = icdvAccount icdv
  credPubKeys (NormalAC cdv _) = cdvPublicKeys cdv


instance CredentialValuesFields AccountCredentialWithProofs where
  credId (NormalACWP cdi) = cdvCredId . cdiValues $ cdi
  credId (InitialACWP icdi) = icdvRegId . icdiValues $ icdi

  ipId (NormalACWP cdi) = cdvIpId . cdiValues $ cdi
  ipId (InitialACWP icdi) = icdvIpId . icdiValues $ icdi

  policy (NormalACWP cdi) = cdvPolicy . cdiValues $ cdi
  policy (InitialACWP icdi) = icdvPolicy . icdiValues $ icdi

  credPubKeys (InitialACWP icdi) = icdvAccount . icdiValues $ icdi
  credPubKeys (NormalACWP cdi) = cdvPublicKeys . cdiValues $ cdi

-- |Extract only the values we care about from the account credential.
-- Concretely this retains the "Values" part, as well as the commitments. This
-- function can fail if the credential proofs are malformed. This cannot happen
-- on a credential that has been validated, but it can happen before that.
values :: AccountCredentialWithProofs -> Maybe AccountCredential
values (InitialACWP icdi) = Just (InitialAC (icdiValues icdi))
values (NormalACWP cdi) = NormalAC (cdiValues cdi) <$> proofCommitments (cdiProofs cdi)

class HasCredentialType a where
  credentialType :: a -> CredentialType

instance HasCredentialType AccountCredential where
  credentialType (InitialAC _) = Initial
  credentialType (NormalAC _ _) = Normal

instance HasCredentialType AccountCredentialWithProofs where
  credentialType (InitialACWP _) = Initial
  credentialType (NormalACWP _) = Normal

-- * Credential commitments helpers.

-- |Commitment size is 48 bytes since that is the size of the serialization of
-- G1 group of BLS12-381.
commitmentSize :: Int
commitmentSize = 48
-- |Size of a commitment in the G1 group of the BLS curve.
data CommitmentSize
instance FBS.FixedLength CommitmentSize where
    fixedLength _ = commitmentSize

-- |A commitment in the G1 group of the BLS curve.
newtype Commitment = Commitment (FBS.FixedByteString CommitmentSize)
  deriving(Eq)
  deriving (Show, ToJSON, FromJSON) via FBSHex CommitmentSize

data CredentialDeploymentCommitments = CredentialDeploymentCommitments {
  cmmPrf :: !Commitment,
  cmmCredCounter :: !Commitment,
  cmmMaxAccounts :: !Commitment,
  cmmAttributes :: !(Map.Map AttributeTag Commitment),
  cmmIdCredSecSharingCoeff :: ![Commitment]
} deriving(Eq, Show)

instance ToJSON CredentialDeploymentCommitments where
  toJSON CredentialDeploymentCommitments{..} = object [
    "cmmPrf" .= cmmPrf,
    "cmmCredCounter" .= cmmCredCounter,
    "cmmMaxAccounts" .= cmmMaxAccounts,
    "cmmAttributes" .= cmmAttributes,
    "cmmIdCredSecSharingCoeff" .= cmmIdCredSecSharingCoeff
    ]

instance FromJSON CredentialDeploymentCommitments where
  parseJSON = withObject "CredentialDeploymentCommitments" $ \v -> do
    cmmPrf <- v .: "cmmPrf"
    cmmCredCounter <- v .: "cmmCredCounter"
    cmmMaxAccounts <- v .: "cmmMaxAccounts"
    cmmAttributes <- v .: "cmmAttributes"
    cmmIdCredSecSharingCoeff <- v .: "cmmIdCredSecSharingCoeff"
    return CredentialDeploymentCommitments{..}

instance Serialize Commitment where
    put (Commitment h) = putByteString $ FBS.toByteString h
    get = Commitment . FBS.fromByteString <$> getByteString commitmentSize

instance Serialize CredentialDeploymentCommitments where
    put CredentialDeploymentCommitments{..} =
      put cmmPrf <>
      put cmmCredCounter <>
      put cmmMaxAccounts <>
      putWord16be (fromIntegral $ Map.size cmmAttributes) <>
      mapM_ put (Map.toAscList cmmAttributes) <>
      putWord64be (fromIntegral $ length cmmIdCredSecSharingCoeff) <>
      mapM_ put cmmIdCredSecSharingCoeff
    get = getCommitments

-- |Parse commitments. This must correspond to the serialization
-- of the datatype "CredentialDeploymentCommitments" in rust-src/id/src/types.rs
getCommitments :: Get CredentialDeploymentCommitments
getCommitments = do
  cmmPrf <- get
  cmmCredCounter <- get
  cmmMaxAccounts <- get
  cmmAttributesLen <- getWord16be
  cmmAttributesList <- replicateM (fromIntegral cmmAttributesLen) get
  let cmmAttributes = Map.fromList cmmAttributesList
  cmmIdLen <- getWord64be
  cmmIdCredSecSharingCoeff <- replicateM (fromIntegral cmmIdLen) get
  return CredentialDeploymentCommitments{..}

-- |Attempt to extract commitments from proofs. If the proofs belong
-- to a credential that has been validated this function will return 'Just',
-- otherwise it might return 'Nothing'.
proofCommitments :: Proofs -> Maybe CredentialDeploymentCommitments
proofCommitments (Proofs shortByteString) =
  case runGet getCommitments $ BS.drop 96 $ BSS.fromShort shortByteString  of
    Left _ -> Nothing
    Right coms -> Just coms
