{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TemplateHaskell #-}

module Concordium.Types.Locks.CBOR (
    LockControllerSimpleV0Capability (..),
    encodeLockControllerSimpleV0Capability,
    decodeLockControllerSimpleV0Capability,
    LockControllerSimpleV0Grant (..),
    encodeLockControllerSimpleV0Grant,
    decodeLockControllerSimpleV0Grant,
    LockControllerSimpleConfigV0 (..),
    encodeLockControllerSimpleConfigV0,
    decodeLockControllerSimpleConfigV0,
    LockController (..),
    encodeLockController,
    decodeLockController,
    LockRecipients (..),
    encodeLockRecipients,
    decodeLockRecipients,
    LockMetadata (..),
    encodeLockMetadata,
    decodeLockMetadata,
    LockConfig (..),
    LockedTokenAmount (..),
    encodeLockAccountFunds,
    decodeLockAccountFunds,
    encodeLockId,
    decodeLockId,
    encodeLockedTokenAmount,
    decodeLockedTokenAmount,
    LockAccountFunds (..),
    LockInfoDetails (..),
    lockInfoFromBytes,
    lockInfoToBytes,
) where

import Codec.CBOR.Decoding
import Codec.CBOR.Encoding
import qualified Codec.CBOR.Term as CBORTerm
import Control.Monad
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Map.Lazy as Map
import qualified Data.Sequence as Seq
import Data.Text (Text)
import qualified Data.Text.Lazy as LazyText
import Lens.Micro.Platform

import Concordium.Types (TransactionTime (..))
import Concordium.Types.Locks
import Concordium.Types.ProtocolLevelTokens.CBOR (
    CborAccountAddress,
    TaggableMemo,
    decodeFromBytes,
    decodeMap,
    decodeSequence,
    decodeTaggableMemo,
    decodeTokenAmount,
    encodeMapDeterministic,
    encodeSequence,
    encodeTaggableMemo,
    encodeTokenAmount,
    makeMapKeyEncoding,
    mapValueDecoder,
 )
import qualified Concordium.Types.ProtocolLevelTokens.CBOR as CBOR
import Concordium.Types.Tokens

-- | CBOR tag used for the standalone 'LockId' encoding.
--
-- This is the lock identifier tag in general, not just the tag for the
-- embedded `lock` field inside `lock-info`.
lockIdTag :: Word
lockIdTag = 40920

encodeLockId :: LockId -> Encoding
encodeLockId LockId{..} =
    encodeTag lockIdTag
        <> encodeListLen 3
        <> encodeWord64 liAccountIndex
        <> encodeWord64 liSequenceNumber
        <> encodeWord64 liCreationOrder

decodeLockId :: Decoder s LockId
decodeLockId = do
    tag <- decodeTag
    unless (tag == lockIdTag) $
        fail $
            "lock-id: Expected tag 40920 but found " ++ show tag
    listLen <- decodeListLen
    unless (listLen == 3) $ fail "lock-id: Expected array of length 3"
    liAccountIndex <- decodeWord64
    liSequenceNumber <- decodeWord64
    liCreationOrder <- decodeWord64
    return LockId{..}

-- | Capabilities supported by the simple lock controller.
data LockControllerSimpleV0Capability
    = LockControllerSimpleV0Fund
    | LockControllerSimpleV0Return
    | LockControllerSimpleV0Send
    | LockControllerSimpleV0Cancel
    deriving (Eq, Show)

encodeLockControllerSimpleV0Capability :: LockControllerSimpleV0Capability -> Encoding
encodeLockControllerSimpleV0Capability =
    encodeString . \case
        LockControllerSimpleV0Fund -> "fund"
        LockControllerSimpleV0Return -> "return"
        LockControllerSimpleV0Send -> "send"
        LockControllerSimpleV0Cancel -> "cancel"

decodeLockControllerSimpleV0Capability :: Decoder s LockControllerSimpleV0Capability
decodeLockControllerSimpleV0Capability = do
    role <- decodeString
    case role of
        "fund" -> return LockControllerSimpleV0Fund
        "return" -> return LockControllerSimpleV0Return
        "send" -> return LockControllerSimpleV0Send
        "cancel" -> return LockControllerSimpleV0Cancel
        _ -> fail $ "Unsupported lock controller capability: " ++ show role

-- | Grant of simple lock controller capabilities to an account.
data LockControllerSimpleV0Grant = LockControllerSimpleV0Grant
    { lcsv0gAccount :: !CborAccountAddress,
      lcsv0gRoles :: !(Seq.Seq LockControllerSimpleV0Capability)
    }
    deriving (Eq, Show)

encodeLockControllerSimpleV0Grant :: LockControllerSimpleV0Grant -> Encoding
encodeLockControllerSimpleV0Grant LockControllerSimpleV0Grant{..} =
    encodeMapDeterministic $
        Map.empty
            & k "account" ?~ CBOR.encodeCborAccountAddress lcsv0gAccount
            & k "roles" ?~ encodeSequence encodeLockControllerSimpleV0Capability lcsv0gRoles
  where
    k = at . makeMapKeyEncoding . encodeString

data LockControllerSimpleV0GrantBuilder = LockControllerSimpleV0GrantBuilder
    { _lcsvgbAccount :: !(Maybe CborAccountAddress),
      _lcsvgbRoles :: !(Maybe (Seq.Seq LockControllerSimpleV0Capability))
    }

makeLenses ''LockControllerSimpleV0GrantBuilder

emptyLockControllerSimpleV0GrantBuilder :: LockControllerSimpleV0GrantBuilder
emptyLockControllerSimpleV0GrantBuilder = LockControllerSimpleV0GrantBuilder Nothing Nothing

decodeLockControllerSimpleV0Grant :: Decoder s LockControllerSimpleV0Grant
decodeLockControllerSimpleV0Grant =
    decodeMap valDecoder build emptyLockControllerSimpleV0GrantBuilder
  where
    build LockControllerSimpleV0GrantBuilder{..} = do
        lcsv0gAccount <- _lcsvgbAccount `CBOR.orFail` "Missing \"account\""
        lcsv0gRoles <- _lcsvgbRoles `CBOR.orFail` "Missing \"roles\""
        return LockControllerSimpleV0Grant{..}
    valDecoder k@"account" = Just $ mapValueDecoder k CBOR.decodeCborAccountAddress lcsvgbAccount
    valDecoder k@"roles" = Just $ mapValueDecoder k (decodeSequence decodeLockControllerSimpleV0Capability) lcsvgbRoles
    valDecoder _ = Nothing

-- | Simple lock controller configuration.
data LockControllerSimpleConfigV0 = LockControllerSimpleConfigV0
    { lcsv0Grants :: !(Seq.Seq LockControllerSimpleV0Grant),
      lcsv0Tokens :: !(Seq.Seq TokenId),
      lcsv0KeepAlive :: !Bool,
      lcsv0Memo :: !(Maybe TaggableMemo)
    }
    deriving (Eq, Show)

encodeLockControllerSimpleConfigV0 :: LockControllerSimpleConfigV0 -> Encoding
encodeLockControllerSimpleConfigV0 LockControllerSimpleConfigV0{..} =
    encodeMapDeterministic $
        Map.empty
            & k "grants" ?~ encodeSequence encodeLockControllerSimpleV0Grant lcsv0Grants
            & k "tokens" ?~ encodeSequence CBOR.encodeTokenId lcsv0Tokens
            & k "keepAlive" .~ (if lcsv0KeepAlive then Just (encodeBool True) else Nothing)
            & k "memo" .~ (encodeTaggableMemo <$> lcsv0Memo)
  where
    k = at . makeMapKeyEncoding . encodeString

data LockControllerSimpleV0Builder = LockControllerSimpleV0Builder
    { _lcsv0bGrants :: !(Maybe (Seq.Seq LockControllerSimpleV0Grant)),
      _lcsv0bTokens :: !(Maybe (Seq.Seq TokenId)),
      _lcsv0bKeepAlive :: !(Maybe Bool),
      _lcsv0bMemo :: !(Maybe TaggableMemo)
    }

makeLenses ''LockControllerSimpleV0Builder

emptyLockControllerSimpleV0Builder :: LockControllerSimpleV0Builder
emptyLockControllerSimpleV0Builder = LockControllerSimpleV0Builder Nothing Nothing Nothing Nothing

decodeLockControllerSimpleConfigV0 :: Decoder s LockControllerSimpleConfigV0
decodeLockControllerSimpleConfigV0 =
    decodeMap valDecoder build emptyLockControllerSimpleV0Builder
  where
    build LockControllerSimpleV0Builder{..} = do
        lcsv0Grants <- _lcsv0bGrants `CBOR.orFail` "Missing \"grants\""
        lcsv0Tokens <- _lcsv0bTokens `CBOR.orFail` "Missing \"tokens\""
        let lcsv0KeepAlive = maybe False id _lcsv0bKeepAlive
        let lcsv0Memo = _lcsv0bMemo
        return LockControllerSimpleConfigV0{..}
    valDecoder k@"grants" = Just $ mapValueDecoder k (decodeSequence decodeLockControllerSimpleV0Grant) lcsv0bGrants
    valDecoder k@"tokens" = Just $ mapValueDecoder k (decodeSequence CBOR.decodeTokenId) lcsv0bTokens
    valDecoder k@"keepAlive" = Just $ mapValueDecoder k decodeBool lcsv0bKeepAlive
    valDecoder k@"memo" = Just $ mapValueDecoder k decodeTaggableMemo lcsv0bMemo
    valDecoder _ = Nothing

-- | Lock controller configuration.
data LockController
    = LockControllerSimpleV0 !LockControllerSimpleConfigV0
    deriving (Eq, Show)

encodeLockController :: LockController -> Encoding
encodeLockController = \case
    LockControllerSimpleV0 cfg ->
        encodeMapDeterministic $ Map.singleton (makeMapKeyEncoding (encodeString "simpleV0")) (encodeLockControllerSimpleConfigV0 cfg)

decodeLockController :: Decoder s LockController
decodeLockController =
    decodeMap valDecoder build Nothing
  where
    valDecoder k@"simpleV0" = Just $ mapValueDecoder k decodeLockControllerSimpleConfigV0 id
    valDecoder _ = Nothing
    build (Just cfg) = Right $ LockControllerSimpleV0 cfg
    build Nothing = Left "Missing \"simpleV0\""

-- | Accounts that can receive funds controlled by a lock.
data LockRecipients
    = LockRecipientsAny
    | LockRecipientsLimited !(Seq.Seq CborAccountAddress)
    deriving (Eq, Show)

-- | Encode lock recipients as CBOR text @"any"@ or an account-address array.
encodeLockRecipients :: LockRecipients -> Encoding
encodeLockRecipients LockRecipientsAny = encodeString "any"
encodeLockRecipients (LockRecipientsLimited accounts) = encodeSequence CBOR.encodeCborAccountAddress accounts

-- | Decode lock recipients from CBOR text @"any"@ or an account-address array.
decodeLockRecipients :: Decoder s LockRecipients
decodeLockRecipients = do
    term <- CBORTerm.decodeTerm
    either fail return $ decodeLockRecipientsHelper term

-- | Decode lock recipients from a CBOR term.
decodeLockRecipientsHelper :: CBORTerm.Term -> Either String LockRecipients
decodeLockRecipientsHelper = \case
    CBORTerm.TString "any" -> return LockRecipientsAny
    CBORTerm.TString value -> unsupportedText value
    CBORTerm.TStringI value ->
        let strictValue = LazyText.toStrict value
        in  if strictValue == "any" then return LockRecipientsAny else unsupportedText strictValue
    CBORTerm.TList accounts -> LockRecipientsLimited . Seq.fromList <$> traverse CBOR.decodeCborAccountAddressHelper accounts
    CBORTerm.TListI accounts -> LockRecipientsLimited . Seq.fromList <$> traverse CBOR.decodeCborAccountAddressHelper accounts
    term -> Left $ "lock recipients: expected text \"any\" or account address array, found " ++ show term
  where
    unsupportedText :: Text -> Either String LockRecipients
    unsupportedText value = Left $ "Unsupported lock recipients text value: " ++ show value

-- | User-facing metadata attached to a lock at creation time.
data LockMetadata = LockMetadata
    { lmName :: !(Maybe Text),
      lmDescription :: !(Maybe Text),
      lmAdditional :: !(Map.Map Text CBORTerm.Term)
    }
    deriving (Eq, Show)

data LockMetadataBuilder = LockMetadataBuilder
    { _lmbName :: !(Maybe Text),
      _lmbDescription :: !(Maybe Text),
      _lmbAdditional :: !(Map.Map Text CBORTerm.Term)
    }

makeLenses ''LockMetadataBuilder

emptyLockMetadataBuilder :: LockMetadataBuilder
emptyLockMetadataBuilder = LockMetadataBuilder Nothing Nothing Map.empty

-- | Encode lock metadata as a text-keyed CBOR map.
encodeLockMetadata :: LockMetadata -> Encoding
encodeLockMetadata LockMetadata{..} =
    encodeMapDeterministic $
        CBOR.encodeAdditionalMapCbor lmAdditional
            & k "name" .~ (encodeString <$> lmName)
            & k "description" .~ (encodeString <$> lmDescription)
  where
    k = at . makeMapKeyEncoding . encodeString

-- | Decode lock metadata from a text-keyed CBOR map.
decodeLockMetadata :: Decoder s LockMetadata
decodeLockMetadata =
    decodeMap valDecoder build emptyLockMetadataBuilder
  where
    build LockMetadataBuilder{..} =
        Right $
            LockMetadata
                { lmName = _lmbName,
                  lmDescription = _lmbDescription,
                  lmAdditional = _lmbAdditional
                }
    valDecoder k@"name" = Just $ mapValueDecoder k decodeString lmbName
    valDecoder k@"description" = Just $ mapValueDecoder k decodeString lmbDescription
    valDecoder k = Just $ mapValueDecoder k CBORTerm.decodeTerm (lmbAdditional . at k)

-- | Static configuration of a lock.
data LockConfig = LockConfig
    { lcRecipients :: !LockRecipients,
      lcExpiry :: !TransactionTime,
      lcController :: !LockController,
      lcMetadata :: !(Maybe LockMetadata)
    }
    deriving (Eq, Show)

encodeEpochTime :: TransactionTime -> Encoding
encodeEpochTime (TransactionTime t) = encodeTag 1 <> encodeWord64 t

decodeEpochTime :: Decoder s TransactionTime
decodeEpochTime = do
    tag <- decodeTag
    unless (tag == 1) $ fail $ "epoch-time: Expected tag 1 but found " ++ show tag
    TransactionTime <$> decodeWord64

-- | Encode lock metadata as a byte string containing its CBOR encoding.
encodeLockMetadataBytes :: LockMetadata -> Encoding
encodeLockMetadataBytes = encodeBytes . CBOR.encodeToBytes . encodeLockMetadata

-- | Decode lock metadata from a byte string containing its CBOR encoding.
decodeLockMetadataBytes :: Decoder s LockMetadata
decodeLockMetadataBytes = do
    bytes <- decodeBytes
    either fail return $ decodeFromBytes decodeLockMetadata "lock metadata" (LBS.fromStrict bytes)

-- | Locked amount for a token.
data LockedTokenAmount = LockedTokenAmount
    { ltaToken :: !TokenId,
      ltaAmount :: !TokenAmount
    }
    deriving (Eq, Show)

encodeLockedTokenAmount :: LockedTokenAmount -> Encoding
encodeLockedTokenAmount LockedTokenAmount{..} =
    encodeMapDeterministic $
        Map.empty
            & k "token" ?~ CBOR.encodeTokenId ltaToken
            & k "amount" ?~ encodeTokenAmount ltaAmount
  where
    k = at . makeMapKeyEncoding . encodeString

data LockedTokenAmountBuilder = LockedTokenAmountBuilder
    { _ltabToken :: !(Maybe TokenId),
      _ltabAmount :: !(Maybe TokenAmount)
    }

makeLenses ''LockedTokenAmountBuilder

emptyLockedTokenAmountBuilder :: LockedTokenAmountBuilder
emptyLockedTokenAmountBuilder = LockedTokenAmountBuilder Nothing Nothing

decodeLockedTokenAmount :: Decoder s LockedTokenAmount
decodeLockedTokenAmount =
    decodeMap valDecoder build emptyLockedTokenAmountBuilder
  where
    build LockedTokenAmountBuilder{..} = do
        ltaToken <- _ltabToken `CBOR.orFail` "Missing \"token\""
        ltaAmount <- _ltabAmount `CBOR.orFail` "Missing \"amount\""
        return LockedTokenAmount{..}
    valDecoder k@"token" = Just $ mapValueDecoder k CBOR.decodeTokenId ltabToken
    valDecoder k@"amount" = Just $ mapValueDecoder k decodeTokenAmount ltabAmount
    valDecoder _ = Nothing

-- | Locked funds for one account.
data LockAccountFunds = LockAccountFunds
    { lafAccount :: !CborAccountAddress,
      lafAmounts :: !(Seq.Seq LockedTokenAmount)
    }
    deriving (Eq, Show)

encodeLockAccountFunds :: LockAccountFunds -> Encoding
encodeLockAccountFunds LockAccountFunds{..} =
    encodeMapDeterministic $
        Map.empty
            & k "account" ?~ CBOR.encodeCborAccountAddress lafAccount
            & k "amounts" ?~ encodeSequence encodeLockedTokenAmount lafAmounts
  where
    k = at . makeMapKeyEncoding . encodeString

data LockAccountFundsBuilder = LockAccountFundsBuilder
    { _lafbAccount :: !(Maybe CborAccountAddress),
      _lafbAmounts :: !(Maybe (Seq.Seq LockedTokenAmount))
    }

makeLenses ''LockAccountFundsBuilder

emptyLockAccountFundsBuilder :: LockAccountFundsBuilder
emptyLockAccountFundsBuilder = LockAccountFundsBuilder Nothing Nothing

decodeLockAccountFunds :: Decoder s LockAccountFunds
decodeLockAccountFunds =
    decodeMap valDecoder build emptyLockAccountFundsBuilder
  where
    build LockAccountFundsBuilder{..} = do
        lafAccount <- _lafbAccount `CBOR.orFail` "Missing \"account\""
        lafAmounts <- _lafbAmounts `CBOR.orFail` "Missing \"amounts\""
        return LockAccountFunds{..}
    valDecoder k@"account" = Just $ mapValueDecoder k CBOR.decodeCborAccountAddress lafbAccount
    valDecoder k@"amounts" = Just $ mapValueDecoder k (decodeSequence decodeLockedTokenAmount) lafbAmounts
    valDecoder _ = Nothing

-- | Structured representation of the CBOR payload returned by `GetLockInfo`.
data LockInfoDetails = LockInfoDetails
    { lipLock :: !LockId,
      lipConfig :: !LockConfig,
      lipFunds :: !(Seq.Seq LockAccountFunds)
    }
    deriving (Eq, Show)

data LockInfoDetailsBuilder = LockInfoDetailsBuilder
    { _lidbLock :: !(Maybe LockId),
      _lidbRecipients :: !(Maybe LockRecipients),
      _lidbExpiry :: !(Maybe TransactionTime),
      _lidbController :: !(Maybe LockController),
      _lidbMetadata :: !(Maybe LockMetadata),
      _lidbFunds :: !(Maybe (Seq.Seq LockAccountFunds))
    }

makeLenses ''LockInfoDetailsBuilder

emptyLockInfoDetailsBuilder :: LockInfoDetailsBuilder
emptyLockInfoDetailsBuilder = LockInfoDetailsBuilder Nothing Nothing Nothing Nothing Nothing Nothing

decodeLockInfoDetails :: Decoder s LockInfoDetails
decodeLockInfoDetails =
    decodeMap valDecoder build emptyLockInfoDetailsBuilder
  where
    build LockInfoDetailsBuilder{..} = do
        lipLock <- _lidbLock `CBOR.orFail` "Missing \"lock\""
        lcRecipients <- _lidbRecipients `CBOR.orFail` "Missing \"recipients\""
        lcExpiry <- _lidbExpiry `CBOR.orFail` "Missing \"expiry\""
        lcController <- _lidbController `CBOR.orFail` "Missing \"controller\""
        let lcMetadata = _lidbMetadata
        lipFunds <- _lidbFunds `CBOR.orFail` "Missing \"funds\""
        return LockInfoDetails{lipConfig = LockConfig{..}, ..}
    valDecoder k@"lock" = Just $ mapValueDecoder k decodeLockId lidbLock
    valDecoder k@"recipients" = Just $ mapValueDecoder k decodeLockRecipients lidbRecipients
    valDecoder k@"expiry" = Just $ mapValueDecoder k decodeEpochTime lidbExpiry
    valDecoder k@"controller" = Just $ mapValueDecoder k decodeLockController lidbController
    valDecoder k@"metadata" = Just $ mapValueDecoder k decodeLockMetadataBytes lidbMetadata
    valDecoder k@"funds" = Just $ mapValueDecoder k (decodeSequence decodeLockAccountFunds) lidbFunds
    valDecoder _ = Nothing

encodeLockInfoDetails :: LockInfoDetails -> Encoding
encodeLockInfoDetails LockInfoDetails{..} =
    encodeMapDeterministic $
        Map.empty
            & k "lock" ?~ encodeLockId lipLock
            & k "recipients" ?~ encodeLockRecipients (lcRecipients lipConfig)
            & k "expiry" ?~ encodeEpochTime (lcExpiry lipConfig)
            & k "controller" ?~ encodeLockController (lcController lipConfig)
            & k "metadata" .~ (encodeLockMetadataBytes <$> lcMetadata lipConfig)
            & k "funds" ?~ encodeSequence encodeLockAccountFunds lipFunds
  where
    k = at . makeMapKeyEncoding . encodeString

lockInfoFromBytes :: LBS.ByteString -> Either String LockInfoDetails
lockInfoFromBytes = decodeFromBytes decodeLockInfoDetails "lock info"

lockInfoToBytes :: LockInfoDetails -> BS.ByteString
lockInfoToBytes = CBOR.encodeToBytes . encodeLockInfoDetails
