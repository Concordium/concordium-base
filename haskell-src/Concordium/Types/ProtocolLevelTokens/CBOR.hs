{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}

module Concordium.Types.ProtocolLevelTokens.CBOR (
    decodeFromBytes,
    encodeToBytes,
    cborTermToHex,
    hexToCborTerm,
    MapValueDecoder,
    mapValueDecoder,
    decodeMap,
    decodeEmptyMap,
    decodeDecimalFraction,
    decodeSequence,
    decodeAdditionalMapJson,
    MapKeyEncoding (..),
    makeMapKeyEncoding,
    encodeMapDeterministic,
    encodeAdditionalMapJson,
    encodeAdditionalMapCbor,
    CoinInfo (..),
    decodeCoinInfo,
    encodeCoinInfo,
    CborAccountAddress (..),
    accountTokenHolder,
    accountTokenHolderShort,
    decodeAccountAddress,
    encodeAccountAddress,
    decodeCborAccountAddress,
    encodeCborAccountAddress,
    decodeTokenAmount,
    encodeTokenAmount,
    encodeSequence,
    TokenMetadataUrl (..),
    decodeTokenMetadataUrl,
    encodeTokenMetadataUrl,
    tokenMetadataUrlFromBytes,
    tokenMetadataUrlToBytes,
    TokenAdminRole (..),
    decodeTokenAdminRole,
    encodeTokenAdminRole,
    UpdateAdminRolesDetails (..),
    decodeUpdateAdminRolesDetails,
    encodeUpdateAdminRolesDetails,
    TokenInitializationParameters (..),
    decodeTokenInitializationParameters,
    tokenInitializationParametersFromBytes,
    encodeTokenInitializationParameters,
    tokenInitializationParametersToBytes,
    TaggableMemo (..),
    decodeTaggableMemo,
    encodeTaggableMemo,
    TokenTransferBody (..),
    decodeTokenTransfer,
    encodeTokenTransfer,
    TokenOperation (..),
    decodeTokenOperation,
    encodeTokenOperation,
    TokenUpdateTransaction (..),
    decodeTokenUpdateTransaction,
    tokenUpdateTransactionFromBytes,
    encodeTokenUpdateTransaction,
    tokenUpdateTransactionToBytes,
    EncodedTokenEvent (..),
    TokenEvent (..),
    encodeTokenEvent,
    decodeTokenEvent,
    EncodedTokenRejectReason (..),
    TokenRejectReason (..),
    encodeTokenRejectReason,
    decodeTokenRejectReason,
    TokenModuleState (..),
    encodeTokenModuleState,
    tokenModuleStateToBytes,
    decodeTokenModuleState,
    tokenModuleStateFromBytes,
    TokenAuthorizationsMap (..),
    encodeTokenAuthorizationsMap,
    decodeTokenAuthorizationsMap,
    tokenAuthorizationsMapFromBytes,
    tokenAuthorizationsMapToBytes,
    LockId (..),
    LockControllerSimpleV0Capability (..),
    LockControllerSimpleV0Grant (..),
    LockControllerSimpleV0 (..),
    LockController (..),
    LockConfig (..),
    LockedTokenAmount (..),
    LockAccountFunds (..),
    LockInfoDetails (..),
    lockInfoFromBytes,
    lockInfoToBytes,
    TokenModuleAccountState (..),
    encodeTokenModuleAccountState,
    tokenModuleAccountStateToBytes,
    decodeTokenModuleAccountState,
    tokenModuleAccountStateFromBytes,
) where

import qualified Codec.CBOR.ByteArray as BA
import qualified Codec.CBOR.ByteArray.Sliced as SBA
import Codec.CBOR.Decoding
import Codec.CBOR.Encoding
import qualified Codec.CBOR.Read as CBOR
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Write as CBOR
import Control.Monad
import qualified Data.Aeson as AE
import qualified Data.Aeson.Key as AE.Key
import qualified Data.Aeson.KeyMap as KeyMap
import Data.Aeson.Types ((.!=))
import qualified Data.Aeson.Types as AE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Short as BSS
import Data.Foldable
import Data.Function
import qualified Data.Map.Lazy as Map
import Data.Maybe
import Data.Scientific
import qualified Data.Sequence as Seq
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TextEncoding
import qualified Data.Text.Lazy as LazyText
import Data.Word
import Lens.Micro.Platform

import qualified Concordium.Crypto.SHA256 as SHA256
import Concordium.ID.Types
import Concordium.Types.Common (TransactionTime (..))
import Concordium.Types.Memo
import Concordium.Types.Tokens
import qualified Data.FixedByteString as FBS

-- | Helper function to convert a 'Decoder s a' to a function from a lazy bytestring to 'a'.
decodeFromBytes :: (forall s. Decoder s a) -> String -> LBS.ByteString -> Either String a
decodeFromBytes decoder name lbs =
    case CBOR.deserialiseFromBytes decoder lbs of
        Left e -> Left (show e)
        Right ("", res) -> return res
        Right (remaining, _) ->
            Left $
                show (LBS.length remaining)
                    ++ " bytes remaining after parsing "
                    ++ name

-- | Helper function to converting an 'Encoder' to a strict bytestring.
encodeToBytes :: Encoding -> BS.ByteString
encodeToBytes = CBOR.toStrictByteString

-- * Primitive Decoder/encoder helpers

-- | Convert CBOR.Term to a hex-encoded string
cborTermToHex :: CBOR.Term -> Text
cborTermToHex term =
    let bs = CBOR.toStrictByteString $ CBOR.encodeTerm term
    in  TextEncoding.decodeUtf8 (Base16.encode bs)

-- | Convert a hex-encoded string to a CBOR.Term.
hexToCborTerm :: Text -> Either String CBOR.Term
hexToCborTerm hexText = do
    bs <- Base16.decode (TextEncoding.encodeUtf8 hexText)
    decodeFromBytes CBOR.decodeTerm "CBOR term" (LBS.fromStrict bs)

-- * Decoder helpers

-- | A 'MapValueDecoder' consumes a value corresponding to a known key and sets it in the builder.
--  It should fail if entry in the builder corresponding to the key is already set.
type MapValueDecoder s builder = builder -> Decoder s builder

-- | Build a 'MapValueDecoder' for a particular key. This enforces that a field cannot be set more
--  than once.
mapValueDecoder ::
    -- | The key being decoded (used for error reporting).
    Text ->
    -- | The decoder to use for the value.
    Decoder s v ->
    -- | A lens to access the field on the builder.
    Lens' builder (Maybe v) ->
    MapValueDecoder s builder
mapValueDecoder key decodeVal l = \builder -> do
    val <- decodeVal
    case builder ^. l of
        Nothing -> return $ builder & l ?~ val
        Just _ -> fail $ "Key already set: " ++ show key

-- | Helper function for decoding an indefinitely-encoded sequence or map.
decodeIndefHelper ::
    -- | Decode the next entry, updating the builder.
    (builder -> Decoder s builder) ->
    -- | Initial builder.
    builder ->
    Decoder s builder
{-# INLINE decodeIndefHelper #-}
decodeIndefHelper decoder = decodeLoop
  where
    decodeLoop builder =
        decodeBreakOr >>= \case
            True -> return builder
            False -> decoder builder >>= decodeLoop

-- | Helper function for decoding a sequence or map of known length.
decodeDefHelper ::
    -- | Decode the next entry, updating the builder.
    (builder -> Decoder s builder) ->
    -- | Number of entries.
    Int ->
    -- | Initial builder.
    builder ->
    Decoder s builder
{-# INLINE decodeDefHelper #-}
decodeDefHelper decoder = decodeLoop
  where
    decodeLoop n builder
        | n > 0 = decoder builder >>= decodeLoop (n - 1)
        | otherwise = return builder

-- | Decode a CBOR-encoded map to type @r@. This exclusively supports UTF-8 string keys.
--  The decoding uses a @builder@ type that is used to progressively decode the map.
--  The first argument is a function that determines if each key is allowed, and if so,
--  how the corresponding value should be decoded and added to the builder.
decodeMap ::
    -- | Function that determines the 'MapValueDecoder' for a map key.
    (Text -> Maybe (MapValueDecoder s builder)) ->
    -- | Function to run the builder and produce a value.
    (builder -> Either String r) ->
    -- | The empty builder.
    builder ->
    Decoder s r
decodeMap valDecoder runBuilder emptyBuilder = do
    builder <-
        decodeMapLenOrIndef >>= \case
            Nothing -> decodeIndefHelper decodeKV emptyBuilder
            Just len -> decodeDefHelper decodeKV len emptyBuilder
    case runBuilder builder of
        Left e -> fail e
        Right r -> return r
  where
    decodeKV builder = do
        key <- decodeString
        case valDecoder key of
            Nothing -> fail $ "Unexpected key " ++ show key
            Just decoder -> decoder builder

-- | Decode the empty map
decodeEmptyMap :: Decoder s ()
decodeEmptyMap = do
    decodeMapLenOrIndef >>= \case
        Just 0 -> return ()
        Just len -> fail $ "Unexpected non-empty map of length " ++ show len
        Nothing -> do
            isEmpty <- decodeBreakOr
            unless isEmpty $ fail "Unexpected non-empty map"

-- | Decode a CBOR decimal fraction into a 'Scientific'. The result is not normalized.
decodeDecimalFraction :: Decoder s Scientific
decodeDecimalFraction = do
    tag <- decodeTag
    unless (tag == 4) $ fail $ "Expected decimal fraction (tag 4), but found tag " ++ show tag
    mLen <- decodeListLenOrIndef
    forM_ mLen $ \len ->
        unless (len == 2) $
            fail $
                "Expected an array of length 2, but length was " ++ show len
    exp10 <- decodeInt
    mantissa <- decodeInteger
    when (isNothing mLen) $ decodeBreakOr >>= \b -> unless b (fail "Expected end of array")
    return $ scientific mantissa exp10

-- | Given a decoder for a single value, decode a sequence of values.
decodeSequence :: Decoder s r -> Decoder s (Seq.Seq r)
decodeSequence decoder =
    decodeListLenOrIndef >>= \case
        Just len -> decodeDefHelper decodeNext len Seq.empty
        Nothing -> decodeIndefHelper decodeNext Seq.empty
  where
    decodeNext l = (l Seq.|>) <$> decoder

-- | Parse JSON map of additional entries into CBOR Terms
decodeAdditionalMapJson :: Map.Map Text Text -> AE.Parser (Map.Map Text CBOR.Term)
decodeAdditionalMapJson =
    Map.traverseWithKey
        ( \k hexTxt ->
            case hexToCborTerm hexTxt of
                Left err ->
                    fail $ "Failed to decode CBOR for key " ++ show k ++ ": " ++ err
                Right term -> return term
        )

-- * Encoding helpers

-- | An 'Encoding' that represents a key in a CBOR map. The 'Ord' instance corresponds to
--  lexicographic ordering of the CBOR encodings, so that these can be used to order keys for
--  deterministic CBOR encoding.
data MapKeyEncoding = MapKeyEncoding
    { -- | The encoding of the value
      meEncoding :: Encoding,
      -- | The value encoded to a 'LBS.ByteString'.
      meBytes :: LBS.ByteString
    }

instance Eq MapKeyEncoding where
    (==) = (==) `on` meBytes

instance Ord MapKeyEncoding where
    compare = compare `on` meBytes

-- | Convert an 'Encoding' to a 'MapKeyEncoding'
makeMapKeyEncoding :: Encoding -> MapKeyEncoding
makeMapKeyEncoding meEncoding = MapKeyEncoding{meBytes = CBOR.toLazyByteString meEncoding, ..}

-- | Encode a map deterministically. Specifically, the map length is definite and the keys are
--  ordered in bytewise lexicographic order. It is assumed that all encodings in the map are
--  deterministic.
encodeMapDeterministic :: Map.Map MapKeyEncoding Encoding -> Encoding
encodeMapDeterministic m =
    encodeMapLen (fromIntegral $ Map.size m)
        <> mconcat [meEncoding k <> v | (k, v) <- Map.toAscList m]

-- * Builder helpers

-- | Convert a 'Maybe' to an 'Either'.
orFail :: Maybe a -> b -> Either b a
orFail Nothing = Left
orFail (Just v) = const (Right v)

-- | Unwrap a 'Maybe' using a supplied default value.
orDefault :: Maybe a -> a -> a
orDefault Nothing = id
orDefault (Just a) = const a

-- | Encode additional entries of CBOR Terms into JSON
encodeAdditionalMapJson :: (Map.Map Text CBOR.Term) -> Maybe AE.Value
encodeAdditionalMapJson additional
    | null additional = Nothing
    | otherwise = Just $ AE.object $ map (\(k, v) -> AE.Key.fromText k AE..= cborTermToHex v) (Map.toList additional)

-- | Encode additional entries of CBOR Terms into CBOR
encodeAdditionalMapCbor :: (Map.Map Text CBOR.Term) -> (Map.Map MapKeyEncoding Encoding)
encodeAdditionalMapCbor additional =
    Map.fromList
        [ (makeMapKeyEncoding (encodeString key), CBOR.encodeTerm val)
        | (key, val) <- Map.toList additional
        ]

-- * Token ID

-- | Decode a CBOR-encoded 'TokenId'.
decodeTokenId :: Decoder s TokenId
decodeTokenId = do
    tid <- decodeStringCanonical
    case makeTokenId (BSS.toShort $ TextEncoding.encodeUtf8 tid) of
        Left e -> fail $ "Invalid token ID: " ++ e
        Right tokenId -> return tokenId

-- | Encode a 'TokenId' as CBOR.
encodeTokenId :: TokenId -> Encoding
encodeTokenId (TokenId tid) = encodeString (TextEncoding.decodeUtf8 $ BSS.fromShort tid)

-- * Token holder parameters

-- | Coin info that indicates the type of the address. Only Concordium addresses are supported.
data CoinInfo = CoinInfoConcordium
    deriving (Eq, Show)

instance AE.ToJSON CoinInfo where
    toJSON CoinInfoConcordium = AE.String "CCD"

instance AE.FromJSON CoinInfo where
    parseJSON (AE.String "CCD") = return CoinInfoConcordium
    parseJSON _ = fail "CoinInfo JSON must be the string 'CCD'"

-- | Decode a 'CoinInfo' from a CBOR term.
decodeCoinInfoHelper :: CBOR.Term -> Either String CoinInfo
decodeCoinInfoHelper = \case
    CBOR.TTagged tag term
        | tag == 40305 -> do
            keyValues <- case term of
                CBOR.TMap kvs -> return kvs
                CBOR.TMapI kvs -> return kvs
                _ -> Left "coin-info: Expected a map"
            keyValueList <- forM keyValues $ \(k, v) -> case k of
                CBOR.TInt i -> return (i, v)
                _ -> Left "coin-info: Expected an integer key"
            build (Map.fromList keyValueList)
        | otherwise -> Left $ "coin-info: Expected coininfo (tag 40305), but found tag " ++ show tag
    other -> Left $ "coin-info: Unexpected term constructor for coin info: " ++ show other
  where
    build :: Map.Map Int CBOR.Term -> Either String CoinInfo
    build m0 = do
        ((), m1) <- getAndClear 1 convertCoinType m0
        unless (Map.null m1) $ Left $ "coin-info: unexpected map key(s): " ++ show (Map.keys m1)
        return CoinInfoConcordium
    getAndClear key convert m = do
        let (maybeTerm, m') = m & at key <<.~ Nothing
        term <- maybeTerm `orFail` ("coin-info: Missing " ++ show key)
        val <- convert term `orFail` ("coin-info: Invalid " ++ show key)
        return (val, m')
    convertCoinType :: CBOR.Term -> Maybe ()
    convertCoinType (CBOR.TInt i)
        | i == 919 = Just ()
        | otherwise = Nothing
    convertCoinType _ = Nothing

-- | Decode a tagged-coininfo type. Only the concordium coininfo type is supported.
decodeCoinInfo :: Decoder s CoinInfo
decodeCoinInfo = do
    term <- CBOR.decodeTerm
    either fail return $ decodeCoinInfoHelper term

-- | Encode a 'CoinInfo' in the tagged-coininfo schema.
encodeCoinInfo :: CoinInfo -> Encoding
encodeCoinInfo CoinInfoConcordium =
    encodeTag 40305
        <> encodeMapLen 1
        <> encodeInt 1
        <> encodeInt 919

-- | Decode a CBOR-encoded account address, that is encoded as a raw byte string.
decodeAccountAddress :: Decoder s AccountAddress
decodeAccountAddress = do
    addressBA <- decodeByteArray
    let actualSize = BA.sizeofByteArray addressBA
    unless (actualSize == accountAddressSize) $
        fail $
            "account-address: expected "
                ++ show accountAddressSize
                ++ " bytes, but saw "
                ++ show actualSize
    return $ AccountAddress $ FBS.FixedByteString $ BA.unBA addressBA

-- | Encode an account address as a CBOR byte string.
encodeAccountAddress :: AccountAddress -> Encoding
encodeAccountAddress (AccountAddress (FBS.FixedByteString ba)) =
    encodeByteArray (SBA.fromByteArray ba)

-- | Concordium account address in the context of receiving and holding protocol-level tokens.
-- The type is used in the transaction
-- payload, in reject reasons, and in the `TokenModuleEvent`.
data CborAccountAddress = CborAccountAddress
    { -- | The account address.
      chaAccount :: !AccountAddress,
      -- | Although the account can only be a Concordium address, this specifies whether the
      --  address type should be explicit in the CBOR encoding.
      chaCoinInfo :: !(Maybe CoinInfo)
    }
    deriving (Eq, Show)

instance AE.ToJSON CborAccountAddress where
    toJSON CborAccountAddress{..} = do
        AE.object $
            [ -- Tag with type of receiver
              "type" AE..= AE.String "account",
              "address" AE..= chaAccount
            ]
                ++ ["coinInfo" AE..= coinInfo | coinInfo <- toList chaCoinInfo]

instance AE.FromJSON CborAccountAddress where
    parseJSON = AE.withObject "CborAccountAddress" $ \o -> do
        type_string <- o AE..: "type"
        case (type_string :: String) of
            "account" -> do
                chaAccount <- o AE..: "address"
                chaCoinInfo <- o AE..:? "coinInfo"
                return CborAccountAddress{..}
            _ -> fail ("Unknown CborAccountAddress type " ++ type_string)

-- | Create a 'HolderAccount' from an 'AccountAddress'. The address type will be present in the
--  CBOR encoding.
accountTokenHolder :: AccountAddress -> CborAccountAddress
accountTokenHolder addr =
    CborAccountAddress
        { chaAccount = addr,
          chaCoinInfo = Just CoinInfoConcordium
        }

-- | Create a 'HolderAccount' from an 'AccountAddress'. The address type will not be present in
--  the CBOR encoding.
accountTokenHolderShort :: AccountAddress -> CborAccountAddress
accountTokenHolderShort addr =
    CborAccountAddress
        { chaAccount = addr,
          chaCoinInfo = Nothing
        }

-- | A builder for the 'HolderAccount' constructor.
data HolderAccountBuilder = HolderAccountBuilder
    { -- | Receiver account address.
      _habAccountAddress :: Maybe AccountAddress,
      -- | Identifier for the address type.
      _habCoinInfo :: Maybe CoinInfo
    }

makeLenses ''HolderAccountBuilder

-- | Empty 'HolderAccountBuilder'.
emptyHolderAccountBuilder :: HolderAccountBuilder
emptyHolderAccountBuilder = HolderAccountBuilder Nothing Nothing

-- | Helper function for decoding a 'CborAccountAddress' from a 'CBOR.Term'.
decodeCborAccountAddressHelper :: CBOR.Term -> Either String CborAccountAddress
decodeCborAccountAddressHelper = \case
    CBOR.TTagged tag term
        | tag == 40307 -> do
            keyValues <- case term of
                CBOR.TMap kvs -> return kvs
                CBOR.TMapI kvs -> return kvs
                _ -> Left "token-holder: Expected a map"
            keyValueList <- forM keyValues $ \(k, v) -> case k of
                CBOR.TInt i -> return (i, v)
                _ -> Left "token-holder: Expected an integer key"
            build (Map.fromList keyValueList)
        | otherwise -> Left $ "token-holder: Expected cryptocurrency address (tag 40307), but found tag " ++ show tag
    other -> Left $ "token-holder: Unexpected term constructor for token holder: " ++ show other
  where
    build :: Map.Map Int CBOR.Term -> Either String CborAccountAddress
    build m0 = do
        (chaAccount, m1) <- getAndClear 3 convertAddress m0
        (chaCoinInfo, m2) <- getMaybeAndClear 1 convertCoinInfo m1
        unless (Map.null m2) $ Left $ "token-holder: unexpected map key(s): " ++ show (Map.keys m2)
        return CborAccountAddress{..}
    getAndClear key convert m = do
        let (maybeTerm, m') = m & at key <<.~ Nothing
        term <- maybeTerm `orFail` ("token-holder: Missing " ++ show key)
        val <- convert term `orFail` ("token-holder: Invalid " ++ show key)
        return (val, m')
    getMaybeAndClear key convert m = do
        let (maybeTerm, m') = m & at key <<.~ Nothing
        maybeVal <- forM maybeTerm $ \term -> convert term `orFail` ("token-holder: Invalid " ++ show key)
        return (maybeVal, m')
    convertAddress :: CBOR.Term -> Maybe AccountAddress
    convertAddress (CBOR.TBytes bs)
        | BS.length bs == accountAddressSize = Just $ AccountAddress $ FBS.fromByteString bs
        | otherwise = Nothing
    convertAddress _ = Nothing
    convertCoinInfo :: CBOR.Term -> Maybe CoinInfo
    convertCoinInfo term =
        case decodeCoinInfoHelper term of
            Left _err -> Nothing
            Right coinInfo -> Just coinInfo

-- | Decode a CBOR-encoded 'CborAccountAddress'.
decodeCborAccountAddress :: Decoder s CborAccountAddress
decodeCborAccountAddress = do
    term <- CBOR.decodeTerm
    either fail return $ decodeCborAccountAddressHelper term

encodeCborAccountAddress :: CborAccountAddress -> Encoding
encodeCborAccountAddress CborAccountAddress{..} =
    encodeTag 40307
        <> encodeMapDeterministic
            ( Map.empty
                & k 1 .~ (encodeCoinInfo <$> chaCoinInfo)
                & k 3 ?~ encodeAccountAddress chaAccount
            )
  where
    k = at . makeMapKeyEncoding . encodeWord

-- * Token amounts

-- | Decode a CBOR-encoded 'TokenAmount'. This limits the number of decimals to the
--  range @[0..255]@.
decodeTokenAmount :: Decoder s TokenAmount
decodeTokenAmount = do
    sci <- decodeDecimalFraction
    unless (coefficient sci >= 0) $ fail "Unexpected negative token amount"
    unless (coefficient sci <= fromIntegral (maxBound :: Word64)) $
        fail "Token amount exceeds expressible bound"
    unless (base10Exponent sci <= 0) $ fail "Token amount cannot have a positive exponent"
    unless (base10Exponent sci >= -255) $ fail "Token amount exponent is too small"
    return
        TokenAmount
            { taValue = fromIntegral (coefficient sci),
              taDecimals = fromIntegral (negate (base10Exponent sci))
            }

-- | Encode a 'TokenAmount' as CBOR.
encodeTokenAmount :: TokenAmount -> Encoding
encodeTokenAmount TokenAmount{..} =
    encodeTag 4
        <> encodeListLen 2
        <> encodeInteger (-fromIntegral taDecimals)
        <> encodeWord64 (theTokenRawAmount taValue)

-- | Helper function to encode a sequence.
encodeSequence :: (a -> Encoding) -> Seq.Seq a -> Encoding
encodeSequence encodeItem s =
    encodeListLen (fromIntegral $ Seq.length s)
        <> foldMap encodeItem s

-- | A token metadata URL and an optional checksum. The checksum is a SHA256 hash of the metadata at the location of the URL.
data TokenMetadataUrl = TokenMetadataUrl
    { -- | The URL of the token metadata.
      tmUrl :: !Text,
      -- | The sha256 hash of the token metadata.
      tmChecksumSha256 :: !(Maybe SHA256.Hash),
      -- | Any additional values associated with the metadata url, e.g. checksums produced by alternative hash functions.
      --  Keys in this map SHOULD NOT overlap those used for the other (standardised) fields in this structure as that will
      --  break the invertability of the CBOR encoding.
      tmAdditional :: !(Map.Map Text CBOR.Term)
    }
    deriving (Eq, Show)

-- | Create a 'TokenMetadataUrl' with the given URL and no checksum.
createTokenMetadataUrl :: Text -> TokenMetadataUrl
createTokenMetadataUrl url = TokenMetadataUrl{tmUrl = url, tmChecksumSha256 = Nothing, tmAdditional = Map.empty}

-- | Create a 'TokenMetadataUrl' the given URL and associated SHA256 checksum.
createTokenMetadataUrlWithSha256 :: Text -> SHA256.Hash -> TokenMetadataUrl
createTokenMetadataUrlWithSha256 url checksum = TokenMetadataUrl{tmUrl = url, tmChecksumSha256 = Just checksum, tmAdditional = Map.empty}

instance AE.ToJSON TokenMetadataUrl where
    toJSON TokenMetadataUrl{..} =
        AE.object . catMaybes $
            [ Just ("url" AE..= tmUrl),
              ("checksumSha256" AE..=) <$> tmChecksumSha256,
              ("_additional" AE..=) <$> (encodeAdditionalMapJson tmAdditional)
            ]

instance AE.FromJSON TokenMetadataUrl where
    parseJSON = AE.withObject "TokenMetadataUrl" $ \v -> do
        tmUrl <- v AE..: "url" -- Mandatory field
        tmChecksumSha256 <- v AE..:? "checksumSha256" -- Optional field
        tmAdditional <- v AE..:? "_additional" .!= Map.empty >>= decodeAdditionalMapJson
        return TokenMetadataUrl{..}

decodeTokenMetadataUrlHelper :: CBOR.Term -> Either String TokenMetadataUrl
decodeTokenMetadataUrlHelper rootTerm = do
    keyValues <- case rootTerm of
        CBOR.TMap kvs -> return kvs
        CBOR.TMapI kvs -> return kvs
        _ -> Left $ "metadata-url: Expected a map"
    keyValueList <- forM keyValues $ \(k, v) -> case k of
        CBOR.TString t -> return (t, v)
        CBOR.TStringI t -> return (LazyText.toStrict t, v)
        _ -> Left $ "metadata-url: Expected a string key"
    build (Map.fromList keyValueList)
  where
    build :: Map.Map Text CBOR.Term -> Either String TokenMetadataUrl
    build m0 = do
        (tmUrl, m1) <- getAndClear "url" convertText m0
        (tmChecksumSha256, tmAdditional) <- getMaybeAndClear "checksumSha256" convertSha256Hash m1
        return TokenMetadataUrl{..}
    getAndClear key convert m = do
        let (maybeTerm, m') = m & at key <<.~ Nothing
        term <- maybeTerm `orFail` ("metadata-url: Missing " ++ show key)
        val <- convert term `orFail` ("metadata-url: Invalid " ++ show key)
        return (val, m')
    getMaybeAndClear key convert m = do
        let (maybeTerm, m') = m & at key <<.~ Nothing
        maybeVal <- forM maybeTerm $ \term -> convert term `orFail` ("metadata-url: Invalid " ++ show key)
        return (maybeVal, m')
    convertText (CBOR.TString t) = Just t
    convertText (CBOR.TStringI t) = Just (LazyText.toStrict t)
    convertText _ = Nothing

    convertSha256Hash :: CBOR.Term -> Maybe SHA256.Hash
    convertSha256Hash (CBOR.TBytes bs)
        | BS.length bs == SHA256.digestSize = Just $ SHA256.Hash (FBS.fromByteString bs)
        | otherwise = Nothing
    convertSha256Hash _ = Nothing

-- | Decode a CBOR-encoded 'TokenMetadataUrl'.
decodeTokenMetadataUrl :: Decoder s TokenMetadataUrl
decodeTokenMetadataUrl = do
    term <- CBOR.decodeTerm
    either fail return $ decodeTokenMetadataUrlHelper term

-- | Encode a 'TokenMetadataUrl' as CBOR.
encodeTokenMetadataUrl :: TokenMetadataUrl -> Encoding
encodeTokenMetadataUrl TokenMetadataUrl{..} =
    encodeMapDeterministic $
        (encodeAdditionalMapCbor tmAdditional)
            & k "url" ?~ encodeString tmUrl
            & k "checksumSha256" .~ (encodeSha256Hash <$> tmChecksumSha256)
  where
    k = at . makeMapKeyEncoding . encodeString
    encodeSha256Hash (SHA256.Hash h) = encodeBytes (FBS.toByteString h)

-- | Parse a 'TokenMetadataUrl' from a 'LBS.ByteString'. The entire bytestring must
--  be consumed in the parsing.
tokenMetadataUrlFromBytes :: LBS.ByteString -> Either String TokenMetadataUrl
tokenMetadataUrlFromBytes =
    decodeFromBytes decodeTokenMetadataUrl "token metadata url"

-- | CBOR-encode a 'TokenMetadataUrl to a (strict) 'BS.ByteString'.
tokenMetadataUrlToBytes :: TokenMetadataUrl -> BS.ByteString
tokenMetadataUrlToBytes = encodeToBytes . encodeTokenMetadataUrl

-- * Administrative roles

-- | The different admin roles defined for the current token module implementation.
--  Each role gives access to specific adminstrative operations.
data TokenAdminRole
    = -- | Authority to perform @assignAdminRoles@ and @revokeAdminRoles@.
      RoleUpdateAdminRoles
    | -- | Authority to perform @mint@.
      RoleMint
    | -- | Authority to perfrom @burn@.
      RoleBurn
    | -- | Authority to perform @addAllowList@ and @removeAllowList@.
      RoleUpdateAllowList
    | -- | Authority to perform @addDenyList@ and @removeDenyList@.
      RoleUpdateDenyList
    | -- | Authority to perform @pause@ and @unpause@.
      RolePause
    | -- | Authority to perform @updateMetadata@.
      RoleUpdateMetadata
    deriving (Eq, Ord, Show)

instance AE.ToJSON TokenAdminRole where
    toJSON = AE.String . tokenAdminRoleToText

instance AE.FromJSON TokenAdminRole where
    parseJSON = AE.withText "TokenAdminRole" parseTokenAdminRoleFromText

instance AE.ToJSONKey TokenAdminRole where
    toJSONKey = AE.toJSONKeyText tokenAdminRoleToText

instance AE.FromJSONKey TokenAdminRole where
    fromJSONKey = AE.FromJSONKeyTextParser parseTokenAdminRoleFromText

-- | Parse a 'Text' as a 'TokenAdminRole'.
tokenAdminRoleFromText :: Text -> Maybe TokenAdminRole
tokenAdminRoleFromText "updateAdminRoles" = Just RoleUpdateAdminRoles
tokenAdminRoleFromText "mint" = Just RoleMint
tokenAdminRoleFromText "burn" = Just RoleBurn
tokenAdminRoleFromText "updateAllowList" = Just RoleUpdateAllowList
tokenAdminRoleFromText "updateDenyList" = Just RoleUpdateDenyList
tokenAdminRoleFromText "pause" = Just RolePause
tokenAdminRoleFromText "updateMetadata" = Just RoleUpdateMetadata
tokenAdminRoleFromText _ = Nothing

-- | Parse a 'TokenAdminRole' from a 'Text' in a monad that supports 'MonadFail'.
parseTokenAdminRoleFromText :: (MonadFail m) => Text -> m TokenAdminRole
{-# INLINE parseTokenAdminRoleFromText #-}
parseTokenAdminRoleFromText role = case tokenAdminRoleFromText role of
    Just r -> return r
    Nothing -> fail $ "Unsupported role: " ++ show role

-- | Encode a 'TokenAdminRole' as 'Text'.
tokenAdminRoleToText :: TokenAdminRole -> Text
tokenAdminRoleToText RoleUpdateAdminRoles = "updateAdminRoles"
tokenAdminRoleToText RoleMint = "mint"
tokenAdminRoleToText RoleBurn = "burn"
tokenAdminRoleToText RoleUpdateAllowList = "updateAllowList"
tokenAdminRoleToText RoleUpdateDenyList = "updateDenyList"
tokenAdminRoleToText RolePause = "pause"
tokenAdminRoleToText RoleUpdateMetadata = "updateMetadata"

-- | Decode a CBOR-encoded 'TokenAdminRole'.
decodeTokenAdminRole :: Decoder s TokenAdminRole
decodeTokenAdminRole = decodeString >>= parseTokenAdminRoleFromText

-- | Encode a 'TokenAdminRole' as CBOR.
encodeTokenAdminRole :: TokenAdminRole -> Encoding
encodeTokenAdminRole = encodeString . tokenAdminRoleToText

-- | The details of @assignAdminRoles@ and @revokeAdminRoles@ operations.
data UpdateAdminRolesDetails = UpdateAdminRolesDetails
    { -- | The account to assign or revoke administrative roles.
      uardAccount :: !CborAccountAddress,
      -- | The roles to assign or revoke.
      uardRoles :: !(Seq.Seq TokenAdminRole)
    }
    deriving (Eq, Show)

instance AE.ToJSON UpdateAdminRolesDetails where
    toJSON UpdateAdminRolesDetails{..} = do
        AE.object $
            [ "account" AE..= uardAccount,
              "roles" AE..= uardRoles
            ]

instance AE.FromJSON UpdateAdminRolesDetails where
    parseJSON = AE.withObject "UpdateAdminRolesDetails" $ \o -> do
        uardAccount <- o AE..: "account"
        uardRoles <- o AE..: "roles"
        return UpdateAdminRolesDetails{..}

data UpdateAdminRolesDetailsBuilder = UpdateAdminRolesDetailsBuilder
    { _uardbAccount :: Maybe CborAccountAddress,
      _uardbRoles :: Maybe (Seq.Seq TokenAdminRole)
    }

makeLenses ''UpdateAdminRolesDetailsBuilder

-- | Empty 'UpdateAdminRolesDetailsBuilder'.
emptyUpdateAdminRolesDetailsBuilder :: UpdateAdminRolesDetailsBuilder
emptyUpdateAdminRolesDetailsBuilder = UpdateAdminRolesDetailsBuilder Nothing Nothing

-- | Construct an 'UpdateAdminRolesDetails' from a 'UpdateAdminRolesDetailsBuilder'.
--  This results in @Left err@ (where @err@ describes the failure reason) when a required parameter
--  is missing.
buildUpdateAdminRolesDetails :: UpdateAdminRolesDetailsBuilder -> Either String UpdateAdminRolesDetails
buildUpdateAdminRolesDetails UpdateAdminRolesDetailsBuilder{..} = do
    uardAccount <- _uardbAccount `orFail` "Missing \"account\""
    uardRoles <- _uardbRoles `orFail` "Missing \"roles\""
    return UpdateAdminRolesDetails{..}

-- | Decode a CBOR-encoded 'UpdateAdminRolesDetails'.
decodeUpdateAdminRolesDetails :: Decoder s UpdateAdminRolesDetails
decodeUpdateAdminRolesDetails =
    decodeMap
        valDecoder
        buildUpdateAdminRolesDetails
        emptyUpdateAdminRolesDetailsBuilder
  where
    valDecoder k@"account" = Just $ mapValueDecoder k decodeCborAccountAddress uardbAccount
    valDecoder k@"roles" = Just $ mapValueDecoder k (decodeSequence decodeTokenAdminRole) uardbRoles
    valDecoder _ = Nothing

-- | Encode an 'UpdateAdminRolesDetails' as CBOR.
encodeUpdateAdminRolesDetails :: UpdateAdminRolesDetails -> Encoding
encodeUpdateAdminRolesDetails UpdateAdminRolesDetails{..} =
    encodeMapDeterministic $
        Map.empty
            & k "account" ?~ encodeCborAccountAddress uardAccount
            & k "roles" ?~ encodeSequence encodeTokenAdminRole uardRoles
  where
    k = at . makeMapKeyEncoding . encodeString

-- * Initialization parameters

-- | The parsed token-initialization-parameters. These parameters are passed to the token module
--  to initialize the token.
data TokenInitializationParameters = TokenInitializationParameters
    { -- | The name of the token.
      tipName :: !(Maybe Text),
      -- | A URL pointing to the token metadata.
      tipMetadata :: !(Maybe TokenMetadataUrl),
      -- | The governance account of this token.
      tipGovernanceAccount :: !(Maybe CborAccountAddress),
      -- | Whether the token supports an allow list.
      tipAllowList :: !(Maybe Bool),
      -- | Whether the token supports a deny list.
      tipDenyList :: !(Maybe Bool),
      -- | The initial supply of the token. If not present, no tokens are minted initially.
      tipInitialSupply :: !(Maybe TokenAmount),
      -- | Whether the token is mintable.
      tipMintable :: !(Maybe Bool),
      -- | Whether the token is burnable.
      tipBurnable :: !(Maybe Bool),
      -- | Any additional state data. Keys in this map SHOULD NOT overlap those
      --  used for the other (standardised) fields in this structure as that will
      --  break the invertability of the CBOR encoding.
      tipAdditional :: !(Map.Map Text CBOR.Term)
    }
    deriving (Eq, Show)

makeLensesFor
    [ ("tipName", "tipNameLens"),
      ("tipMetadata", "tipMetadataLens"),
      ("tipGovernanceAccount", "tipGovernanceAccountLens"),
      ("tipAllowList", "tipAllowListLens"),
      ("tipDenyList", "tipDenyListLens"),
      ("tipInitialSupply", "tipInitialSupplyLens"),
      ("tipMintable", "tipMintableLens"),
      ("tipBurnable", "tipBurnableLens"),
      ("tipAdditional", "tipAdditionalLens")
    ]
    ''TokenInitializationParameters

-- | A 'TokenInitializationParameters' with no fields initialized.
emptyTokenInitializationParameters :: TokenInitializationParameters
emptyTokenInitializationParameters =
    TokenInitializationParameters Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Map.empty

instance AE.ToJSON TokenInitializationParameters where
    toJSON TokenInitializationParameters{..} = do
        AE.object . catMaybes $
            [ ("name" AE..=) <$> tipName,
              ("metadata" AE..=) <$> tipMetadata,
              ("governanceAccount" AE..=) <$> tipGovernanceAccount,
              ("allowList" AE..=) <$> tipAllowList,
              ("denyList" AE..=) <$> tipDenyList,
              ("initialSupply" AE..=) <$> tipInitialSupply,
              ("mintable" AE..=) <$> tipMintable,
              ("burnable" AE..=) <$> tipBurnable,
              ("_additional" AE..=) <$> (encodeAdditionalMapJson tipAdditional)
            ]

instance AE.FromJSON TokenInitializationParameters where
    parseJSON = AE.withObject "TokenInitializationParameters" $ \o -> do
        tipName <- o AE..:? "name"
        tipMetadata <- o AE..:? "metadata"
        tipGovernanceAccount <- o AE..:? "governanceAccount"
        tipAllowList <- o AE..:? "allowList"
        tipDenyList <- o AE..:? "denyList"
        tipInitialSupply <- o AE..:? "initialSupply"
        tipMintable <- o AE..:? "mintable"
        tipBurnable <- o AE..:? "burnable"
        tipAdditional <- o AE..:? "_additional" .!= Map.empty >>= decodeAdditionalMapJson
        return $ TokenInitializationParameters{..}

-- | Decode a CBOR-encoded 'TokenInitializationParameters'.
--  This decoder enforces CBOR-validity (in particular, no duplicate map keys), disallows
--  extraneous keys, and applies defaults specified by the CDDL schema.  It does not require
--  deterministic encoding.
decodeTokenInitializationParameters :: Decoder s TokenInitializationParameters
decodeTokenInitializationParameters =
    decodeMap
        valDecoder
        Right
        emptyTokenInitializationParameters
  where
    valDecoder k@"name" = Just $ mapValueDecoder k decodeString tipNameLens
    valDecoder k@"metadata" = Just $ mapValueDecoder k decodeTokenMetadataUrl tipMetadataLens
    valDecoder k@"governanceAccount" = Just $ mapValueDecoder k decodeCborAccountAddress tipGovernanceAccountLens
    valDecoder k@"allowList" = Just $ mapValueDecoder k decodeBool tipAllowListLens
    valDecoder k@"denyList" = Just $ mapValueDecoder k decodeBool tipDenyListLens
    valDecoder k@"initialSupply" = Just $ mapValueDecoder k decodeTokenAmount tipInitialSupplyLens
    valDecoder k@"mintable" = Just $ mapValueDecoder k decodeBool tipMintableLens
    valDecoder k@"burnable" = Just $ mapValueDecoder k decodeBool tipBurnableLens
    valDecoder k = Just $ mapValueDecoder k CBOR.decodeTerm (tipAdditionalLens . (at k))

-- | Parse a 'TokenInitializationParameters' from a 'LBS.ByteString'. The entire bytestring must
--  be consumed in the parsing.
tokenInitializationParametersFromBytes :: LBS.ByteString -> Either String TokenInitializationParameters
tokenInitializationParametersFromBytes = decodeFromBytes decodeTokenInitializationParameters "token initialization parameters"

-- | Encode a 'TokenInitializationParameters' as CBOR.
encodeTokenInitializationParameters :: TokenInitializationParameters -> Encoding
encodeTokenInitializationParameters TokenInitializationParameters{..} =
    encodeMapDeterministic $
        (encodeAdditionalMapCbor tipAdditional)
            & k "name" .~ (encodeString <$> tipName)
            & k "metadata" .~ (encodeTokenMetadataUrl <$> tipMetadata)
            & k "governanceAccount" .~ (encodeCborAccountAddress <$> tipGovernanceAccount)
            & k "allowList" .~ (encodeBool <$> tipAllowList)
            & k "denyList" .~ (encodeBool <$> tipDenyList)
            & k "initialSupply" .~ (encodeTokenAmount <$> tipInitialSupply)
            & k "mintable" .~ (encodeBool <$> tipMintable)
            & k "burnable" .~ (encodeBool <$> tipBurnable)
  where
    k = at . makeMapKeyEncoding . encodeString

-- | CBOR-encode a 'TokenInitializationParameters' to a (strict) 'BS.ByteString'.
tokenInitializationParametersToBytes :: TokenInitializationParameters -> BS.ByteString
tokenInitializationParametersToBytes =
    CBOR.toStrictByteString . encodeTokenInitializationParameters

-- | A 'TaggableMemo' represents a 'Memo' that may optionally be tagged as CBOR-encoded.
--  Memos are often assumed to be CBOR-encoded, but the tag can be used to make this explicit.
data TaggableMemo
    = -- | The memo is represented as a byte string with no tag.
      UntaggedMemo {untaggedMemo :: !Memo}
    | -- | The memo is represented as a byte string with a tag indicating CBOR-encoded data.
      CBORMemo {cborMemo :: !Memo}
    deriving (Eq, Show)

-- | Unwrap the 'TaggableMemo' into the inner 'Memo'
taggableMemoInner :: TaggableMemo -> Memo
taggableMemoInner UntaggedMemo{..} = untaggedMemo
taggableMemoInner CBORMemo{..} = cborMemo

instance AE.ToJSON TaggableMemo where
    toJSON UntaggedMemo{..} = do
        AE.object $
            [ "type" AE..= AE.String "raw",
              "value" AE..= untaggedMemo
            ]
    toJSON CBORMemo{..} = do
        AE.object $
            [ "type" AE..= AE.String "cbor",
              "value" AE..= cborMemo
            ]

instance AE.FromJSON TaggableMemo where
    parseJSON = AE.withObject "TaggableMemo" $ \o -> do
        type_string <- o AE..: "type"
        case (type_string :: String) of
            "raw" -> do
                untaggedMemo <- o AE..: "value"
                return UntaggedMemo{..}
            "cbor" -> do
                cborMemo <- o AE..: "value"
                return CBORMemo{..}
            _ -> fail ("Unknown TaggableMemo type " ++ type_string)

-- | Decode a CBOR-encoded 'TaggableMemo'.
--  A memo can be encoded either directly as a byte string (of length at most 256) or as
--  such a byte string but tagged as CBOR-encoded (tag 24).
decodeTaggableMemo :: Decoder s TaggableMemo
decodeTaggableMemo = do
    nextTokenType <- peekTokenType
    constructor <-
        if nextTokenType == TypeTag
            then do
                tag <- decodeTag
                unless (tag == 24) $
                    fail $
                        "memo: expected either a byte string or CBOR-encoded bytes (tag 24), but saw tag "
                            ++ show tag
                return CBORMemo
            else return UntaggedMemo
    memoBA <- decodeByteArray
    when (BA.sizeofByteArray memoBA > maxMemoSize) $
        fail $
            tooBigErrorString "memo" (BA.sizeofByteArray memoBA) maxMemoSize
    return . constructor . Memo . BA.toShortByteString $ memoBA

-- | Encode a 'TaggableMemo' as CBOR.
encodeTaggableMemo :: TaggableMemo -> Encoding
encodeTaggableMemo (UntaggedMemo (Memo memo)) =
    encodeByteArray (SBA.fromShortByteString memo)
encodeTaggableMemo (CBORMemo (Memo memo)) =
    encodeTag 24 <> encodeByteArray (SBA.fromShortByteString memo)

-- | Token transfer operation. This transfers a specified amount of tokens from the sender account
--  (implicit) to the recipient account.
data TokenTransferBody = TokenTransferBody
    { -- | The amount to transfer.
      ttAmount :: !TokenAmount,
      -- | The recipient account address.
      ttRecipient :: !CborAccountAddress,
      -- | An optional memo associated with the transfer.
      ttMemo :: !(Maybe TaggableMemo)
    }
    deriving (Eq, Show)

instance AE.ToJSON TokenTransferBody where
    toJSON TokenTransferBody{..} = do
        AE.object $
            [ "amount" AE..= ttAmount,
              "recipient" AE..= ttRecipient
            ]
                ++ ["memo" AE..= memo | memo <- toList ttMemo]

instance AE.FromJSON TokenTransferBody where
    parseJSON = AE.withObject "TokenTransferBody" $ \o -> do
        ttAmount <- o AE..: "amount"
        ttRecipient <- o AE..: "recipient"
        ttMemo <- o AE..:? "memo"
        return TokenTransferBody{..}

-- | Builder
data TokenTransferBuilder = TokenTransferBuilder
    { _ttbAmount :: Maybe TokenAmount,
      _ttbRecipient :: Maybe CborAccountAddress,
      _ttbMemo :: Maybe TaggableMemo
    }

makeLenses ''TokenTransferBuilder

-- | A 'TokenTransferBuilder' with no fields set.
emptyTokenTransferBuilder :: TokenTransferBuilder
emptyTokenTransferBuilder = TokenTransferBuilder Nothing Nothing Nothing

-- | Construct a 'TokenTransferBody' from a 'TokenTransferBuilder'.
--  This results in @Left err@ (where @err@ describes the failure reason) when a required parameter
--  is missing. Missing optional parameters are populated with the appropriate default values.
buildTokenTransfer :: TokenTransferBuilder -> Either String TokenTransferBody
buildTokenTransfer TokenTransferBuilder{..} = do
    ttAmount <- _ttbAmount `orFail` "Missing \"amount\""
    ttRecipient <- _ttbRecipient `orFail` "Missing \"recipient\""
    let ttMemo = _ttbMemo
    return TokenTransferBody{..}

-- | Decode a CBOR-encoded 'TokenTransferBody'.
decodeTokenTransfer :: Decoder s TokenTransferBody
decodeTokenTransfer =
    decodeMap valDecoder buildTokenTransfer emptyTokenTransferBuilder
  where
    valDecoder k@"amount" = Just $ mapValueDecoder k decodeTokenAmount ttbAmount
    valDecoder k@"recipient" = Just $ mapValueDecoder k decodeCborAccountAddress ttbRecipient
    valDecoder k@"memo" = Just $ mapValueDecoder k decodeTaggableMemo ttbMemo
    valDecoder _ = Nothing

-- | Encode a 'TokenTransferBody' as CBOR.
encodeTokenTransfer :: TokenTransferBody -> Encoding
encodeTokenTransfer TokenTransferBody{..} =
    encodeMapDeterministic $
        Map.empty
            & k "amount" ?~ encodeTokenAmount ttAmount
            & k "recipient" ?~ encodeCborAccountAddress ttRecipient
            & k "memo" .~ (encodeTaggableMemo <$> ttMemo)
  where
    k = at . makeMapKeyEncoding . encodeString

-- * Token Operations

-- | A token operation. This can be a transfer, mint, burn, pause, unpause or update to
--  the allow or deny list.
data TokenOperation
    = TokenTransfer TokenTransferBody
    | -- | Mint a specified token amount to the token governance account.
      TokenMint {toMintAmount :: !TokenAmount}
    | -- | Burn a specified token amount from the token governance account.
      TokenBurn {toBurnAmount :: !TokenAmount}
    | -- | Add the specified account to the allow list.
      TokenAddAllowList {toTarget :: !CborAccountAddress}
    | -- | Remove the specified account from the allow list.
      TokenRemoveAllowList {toTarget :: !CborAccountAddress}
    | -- | Add the specified account to the deny list.
      TokenAddDenyList {toTarget :: !CborAccountAddress}
    | -- | Remove the specified account from the deny list.
      TokenRemoveDenyList {toTarget :: !CborAccountAddress}
    | -- | Pause transfer/mint/burn operations for the token.
      TokenPause
    | -- | Unpause transfer/mint/burn operations for the token.
      TokenUnpause
    | -- | Assign admin roles to an account.
      TokenAssignAdminRoles !UpdateAdminRolesDetails
    | -- | Revoke admin roles from an account.
      TokenRevokeAdminRoles !UpdateAdminRolesDetails
    | -- | Update metadata
      TokenUpdateMetadata !TokenMetadataUrl
    deriving (Eq, Show)

instance AE.ToJSON TokenOperation where
    toJSON (TokenTransfer body) = do
        AE.object
            [ "transfer" AE..= AE.toJSON body
            ]
    toJSON (TokenMint body) = do
        AE.object
            [ "mint" AE..= AE.toJSON body
            ]
    toJSON (TokenBurn body) = do
        AE.object
            [ "burn" AE..= AE.toJSON body
            ]
    toJSON (TokenAddAllowList body) = do
        AE.object
            [ "addAllowList" AE..= AE.toJSON body
            ]
    toJSON (TokenAddDenyList body) = do
        AE.object
            [ "addDenyList" AE..= AE.toJSON body
            ]
    toJSON (TokenRemoveAllowList body) = do
        AE.object
            [ "removeAllowList" AE..= AE.toJSON body
            ]
    toJSON (TokenRemoveDenyList body) = do
        AE.object
            [ "removeDenyList" AE..= AE.toJSON body
            ]
    toJSON TokenPause =
        AE.object
            [ "pause" AE..= AE.object []
            ]
    toJSON TokenUnpause =
        AE.object
            [ "unpause" AE..= AE.object []
            ]
    toJSON (TokenAssignAdminRoles update) =
        AE.object
            [ "assignAdminRoles" AE..= update
            ]
    toJSON (TokenRevokeAdminRoles update) =
        AE.object
            [ "revokeAdminRoles" AE..= update
            ]
    toJSON (TokenUpdateMetadata metadata) =
        AE.object
            [ "updateMetadata" AE..= metadata
            ]

instance AE.FromJSON TokenOperation where
    parseJSON = AE.withObject "TokenOperation" $ \o -> do
        let keys = KeyMap.keys o
        case keys of
            ["transfer"] -> do
                body <- o AE..: "transfer"
                pure $ TokenTransfer body
            ["mint"] -> do
                body <- o AE..: "mint"
                pure $ TokenMint body
            ["burn"] -> do
                body <- o AE..: "burn"
                pure $ TokenBurn body
            ["addAllowList"] -> do
                body <- o AE..: "addAllowList"
                pure $ TokenAddAllowList body
            ["removeAllowList"] -> do
                body <- o AE..: "removeAllowList"
                pure $ TokenRemoveAllowList body
            ["addDenyList"] -> do
                body <- o AE..: "addDenyList"
                pure $ TokenAddDenyList body
            ["removeDenyList"] -> do
                body <- o AE..: "removeDenyList"
                pure $ TokenRemoveDenyList body
            ["pause"] -> do
                pure TokenPause
            ["unpause"] -> do
                pure TokenUnpause
            ["assignAdminRoles"] -> do
                body <- o AE..: "assignAdminRoles"
                pure $ TokenAssignAdminRoles body
            ["revokeAdminRoles"] -> do
                body <- o AE..: "revokeAdminRoles"
                pure $ TokenRevokeAdminRoles body
            ["updateMetadata"] -> do
                metadata <- o AE..: "updateMetadata"
                pure $ TokenUpdateMetadata metadata
            other -> fail $ "token-operation: unsupported operation type: " ++ show other

-- | Decode a CBOR-encoded 'TokenOperation'.
decodeTokenOperation :: Decoder s TokenOperation
decodeTokenOperation = do
    maybeMapLen <- decodeMapLenOrIndef
    forM_ maybeMapLen $ \mapLen ->
        unless (mapLen == 1) $
            fail $
                "token-operation: expected a map of size 1, but saw " ++ show mapLen
    opType <- decodeString
    res <- case opType of
        "transfer" -> TokenTransfer <$> decodeTokenTransfer
        "mint" -> TokenMint <$> decodeSupplyUpdate opType
        "burn" -> TokenBurn <$> decodeSupplyUpdate opType
        "addAllowList" -> TokenAddAllowList <$> decodeListTarget opType
        "removeAllowList" -> TokenRemoveAllowList <$> decodeListTarget opType
        "addDenyList" -> TokenAddDenyList <$> decodeListTarget opType
        "removeDenyList" -> TokenRemoveDenyList <$> decodeListTarget opType
        "pause" -> TokenPause <$ decodeEmptyMap
        "unpause" -> TokenUnpause <$ decodeEmptyMap
        "assignAdminRoles" -> TokenAssignAdminRoles <$> decodeUpdateAdminRolesDetails
        "revokeAdminRoles" -> TokenRevokeAdminRoles <$> decodeUpdateAdminRolesDetails
        "updateMetadata" -> TokenUpdateMetadata <$> decodeTokenMetadataUrl
        _ -> fail $ "token-operation: unsupported operation type: " ++ show opType
    when (isNothing maybeMapLen) $ do
        isEnd <- decodeBreakOr
        unless isEnd $ fail "token-operation: expected end of map"
    return res
  where
    decodeSupplyUpdate opType = do
        let valDecoder k@"amount" = Just (mapValueDecoder k decodeTokenAmount id)
            valDecoder _ = Nothing
            build (Just v) = Right v
            build Nothing =
                Left $
                    "token-operation (" ++ Text.unpack opType ++ "): missing amount"
        decodeMap valDecoder build Nothing
    decodeListTarget opType = do
        let valDecoder k@"target" = Just (mapValueDecoder k decodeCborAccountAddress id)
            valDecoder _ = Nothing
            build (Just v) = Right v
            build Nothing =
                Left $
                    "token-operation (" ++ Text.unpack opType ++ "): missing target"
        decodeMap valDecoder build Nothing

-- | Encode a 'TokenOperation' as CBOR.
encodeTokenOperation :: TokenOperation -> Encoding
encodeTokenOperation = \case
    TokenTransfer ttb ->
        encodeMapLen 1
            <> encodeString "transfer"
            <> encodeTokenTransfer ttb
    TokenMint amount -> encodeSupplyUpdate "mint" amount
    TokenBurn amount -> encodeSupplyUpdate "burn" amount
    TokenAddAllowList target -> encodeListTarget "addAllowList" target
    TokenRemoveAllowList target -> encodeListTarget "removeAllowList" target
    TokenAddDenyList target -> encodeListTarget "addDenyList" target
    TokenRemoveDenyList target -> encodeListTarget "removeDenyList" target
    TokenPause -> encodePause
    TokenUnpause -> encodeUnpause
    TokenAssignAdminRoles body ->
        encodeMapLen 1
            <> encodeString "assignAdminRoles"
            <> encodeUpdateAdminRolesDetails body
    TokenRevokeAdminRoles body ->
        encodeMapLen 1
            <> encodeString "revokeAdminRoles"
            <> encodeUpdateAdminRolesDetails body
    TokenUpdateMetadata metadata ->
        encodeMapLen 1
            <> encodeString "updateMetadata"
            <> encodeTokenMetadataUrl metadata
  where
    encodeSupplyUpdate opType amount =
        encodeMapLen 1
            <> encodeString opType
            <> encodeMapLen 1
            <> encodeString "amount"
            <> encodeTokenAmount amount
    encodeListTarget opType target =
        encodeMapLen 1
            <> encodeString opType
            <> encodeMapLen 1
            <> encodeString "target"
            <> encodeCborAccountAddress target
    encodePause =
        encodeMapLen 1
            <> encodeString "pause"
            <> encodeMapLen 0
    encodeUnpause =
        encodeMapLen 1
            <> encodeString "unpause"
            <> encodeMapLen 0

-- | A token transaction consists of a sequence of token operations.
newtype TokenUpdateTransaction = TokenUpdateTransaction
    { tokenOperations :: Seq.Seq TokenOperation
    }
    deriving (Eq, Show)

instance AE.ToJSON TokenUpdateTransaction where
    toJSON = AE.toJSON . tokenOperations

instance AE.FromJSON TokenUpdateTransaction where
    parseJSON = (TokenUpdateTransaction <$>) . AE.parseJSON

-- | Decode a CBOR-encoded 'TokenTransaction'.
decodeTokenUpdateTransaction :: Decoder s TokenUpdateTransaction
decodeTokenUpdateTransaction = TokenUpdateTransaction <$> decodeSequence decodeTokenOperation

-- | Parse a 'TokenTransaction' from a 'LBS.ByteString'. The entire bytestring
--  must be consumed in the parsing.
tokenUpdateTransactionFromBytes :: LBS.ByteString -> Either String TokenUpdateTransaction
tokenUpdateTransactionFromBytes = decodeFromBytes decodeTokenUpdateTransaction "token transaction"

-- | Encode a 'TokenTransaction' as CBOR.
encodeTokenUpdateTransaction :: TokenUpdateTransaction -> Encoding
encodeTokenUpdateTransaction = encodeSequence encodeTokenOperation . tokenOperations

-- | CBOR-encode a 'TokenTransaction' to a (strict) 'BS.ByteString'.
tokenUpdateTransactionToBytes :: TokenUpdateTransaction -> BS.ByteString
tokenUpdateTransactionToBytes = encodeToBytes . encodeTokenUpdateTransaction

-- * Meta-update operations

-- | A meta-update operation. This can be a token operation or a lock operation.
data MetaUpdateOperation
    = MetaTokenUpdate
    { -- | The token affected by the operation.
      muoToken :: !TokenId,
      -- | The token operation to perform.
      muoTokenOperation :: !TokenOperation
    }
    deriving (Eq, Show)

instance AE.ToJSON MetaUpdateOperation where
    toJSON MetaTokenUpdate{..} =
        case AE.toJSON muoTokenOperation of
            AE.Object obj ->
                case KeyMap.toList obj of
                    [(opKey, AE.Object opObj)] ->
                        AE.Object $
                            KeyMap.singleton
                                opKey
                                (AE.Object $ KeyMap.insert "token" (AE.toJSON muoToken) opObj)
                    _ -> error "Unexpected JSON structure from token operation encoding"
            _ -> error "Unexpected JSON structure from token operation encoding"

instance AE.FromJSON MetaUpdateOperation where
    parseJSON = AE.withObject "MetaUpdateOperation" $ \o -> do
        muoToken <- case KeyMap.toList o of
            [(_opKey, AE.Object opObj)] -> opObj AE..: "token"
            _ -> fail "Expected a single key in MetaUpdateOperation object whose value is an object containing a \"token\" field"
        muoTokenOperation <- AE.parseJSON (AE.Object o)
        return MetaTokenUpdate{..}

-- | Builder for constructing a 'MetaUpdateOperation'. This is parametrised by
--  the builder for the particular operation.
data MetaUpdateBuilder b = MetaUpdateBuilder
    { _mubToken :: Maybe TokenId,
      _mubOperationBuilder :: b
    }

makeLenses ''MetaUpdateBuilder

-- | Empty 'MetaUpdateBuilder'.
emptyMetaUpdateBuilder :: b -> MetaUpdateBuilder b
emptyMetaUpdateBuilder = MetaUpdateBuilder Nothing

-- | Decode a CBOR-encoded 'MetaUpdateOperation'.
decodeMetaUpdateOperation :: Decoder s MetaUpdateOperation
decodeMetaUpdateOperation = do
    maybeMapLen <- decodeMapLenOrIndef
    forM_ maybeMapLen $ \mapLen ->
        unless (mapLen == 1) $
            fail $
                "meta-operation: expected a map of size 1, but saw " ++ show mapLen
    opType <- decodeString
    res <- case opType of
        "transfer" -> muDecodeTokenTransfer
        "mint" -> decodeSupplyUpdate TokenMint opType
        "burn" -> decodeSupplyUpdate TokenBurn opType
        "addAllowList" -> decodeListTarget TokenAddAllowList opType
        "removeAllowList" -> decodeListTarget TokenRemoveAllowList opType
        "addDenyList" -> decodeListTarget TokenAddDenyList opType
        "removeDenyList" -> decodeListTarget TokenRemoveDenyList opType
        "pause" -> decodeSimpleOp TokenPause opType
        "unpause" -> decodeSimpleOp TokenUnpause opType
        "assignAdminRoles" -> decodeUpdateAdminRoles TokenAssignAdminRoles
        "revokeAdminRoles" -> decodeUpdateAdminRoles TokenRevokeAdminRoles
        "updateMetadata" -> do
            TokenMetadataUrl{..} <- decodeTokenMetadataUrl
            token <- case Map.lookup "token" tmAdditional of
                Nothing -> fail $ "token-operation (updateMetdata): missing token"
                Just (CBOR.TString tid) ->
                    case makeTokenId (BSS.toShort $ TextEncoding.encodeUtf8 tid) of
                        Left e -> fail $ "Invalid token ID: " ++ e
                        Right tokenId -> return tokenId
                Just _ -> fail $ "token-operation (updateMetadata - token): Expected string"
            let op =
                    TokenUpdateMetadata
                        TokenMetadataUrl{tmAdditional = Map.delete "token" tmAdditional, ..}
            return MetaTokenUpdate{muoToken = token, muoTokenOperation = op}
        _ -> fail $ "token-operation: unsupported operation type: " ++ show opType
    when (isNothing maybeMapLen) $ do
        isEnd <- decodeBreakOr
        unless isEnd $ fail "token-operation: expected end of map"
    return res
  where
    liftBuild constr build MetaUpdateBuilder{..} = do
        muoToken <- _mubToken `orFail` "Missing \"token\""
        muoTokenOperation <- constr <$> build _mubOperationBuilder
        return $ MetaTokenUpdate{..}
    muDecodeTokenTransfer = do
        let valDecoder k@"token" = Just (mapValueDecoder k decodeTokenId mubToken)
            valDecoder k@"amount" = Just (mapValueDecoder k decodeTokenAmount (mubOperationBuilder . ttbAmount))
            valDecoder k@"recipient" = Just (mapValueDecoder k decodeCborAccountAddress (mubOperationBuilder . ttbRecipient))
            valDecoder k@"memo" = Just (mapValueDecoder k decodeTaggableMemo (mubOperationBuilder . ttbMemo))
            valDecoder _ = Nothing
        decodeMap valDecoder (liftBuild TokenTransfer buildTokenTransfer) (emptyMetaUpdateBuilder emptyTokenTransferBuilder)
    decodeSupplyUpdate constr opType = do
        let valDecoder k@"token" = Just (mapValueDecoder k decodeTokenId mubToken)
            valDecoder k@"amount" = Just (mapValueDecoder k decodeTokenAmount mubOperationBuilder)
            valDecoder _ = Nothing
            build (Just v) = Right v
            build Nothing =
                Left $
                    "token-operation (" ++ Text.unpack opType ++ "): missing amount"
        decodeMap valDecoder (liftBuild constr build) (emptyMetaUpdateBuilder Nothing)
    decodeListTarget constr opType = do
        let valDecoder k@"token" = Just (mapValueDecoder k decodeTokenId mubToken)
            valDecoder k@"target" = Just (mapValueDecoder k decodeCborAccountAddress mubOperationBuilder)
            valDecoder _ = Nothing
            build (Just v) = Right v
            build Nothing =
                Left $
                    "token-operation (" ++ Text.unpack opType ++ "): missing target"
        decodeMap valDecoder (liftBuild constr build) (emptyMetaUpdateBuilder Nothing)
    decodeSimpleOp constr opType = do
        let valDecoder k@"token" = Just (mapValueDecoder k decodeTokenId id)
            valDecoder _ = Nothing
            build (Just token) = Right $ MetaTokenUpdate token constr
            build Nothing =
                Left $
                    "token-operation (" ++ Text.unpack opType ++ "): missing token"
        decodeMap valDecoder build Nothing
    decodeUpdateAdminRoles constr = do
        let valDecoder k@"token" = Just (mapValueDecoder k decodeTokenId mubToken)
            valDecoder k@"account" = Just (mapValueDecoder k decodeCborAccountAddress (mubOperationBuilder . uardbAccount))
            valDecoder k@"roles" = Just (mapValueDecoder k (decodeSequence decodeTokenAdminRole) (mubOperationBuilder . uardbRoles))
            valDecoder _ = Nothing
        decodeMap
            valDecoder
            (liftBuild constr buildUpdateAdminRolesDetails)
            (emptyMetaUpdateBuilder emptyUpdateAdminRolesDetailsBuilder)

-- | Encode a 'MetaUpdateOperation' as CBOR.
encodeMetaUpdateOperation :: MetaUpdateOperation -> Encoding
encodeMetaUpdateOperation MetaTokenUpdate{..} = do
    case muoTokenOperation of
        TokenTransfer TokenTransferBody{..} ->
            enc "transfer" $
                baseMap
                    & k "amount" ?~ encodeTokenAmount ttAmount
                    & k "recipient" ?~ encodeCborAccountAddress ttRecipient
                    & k "memo" .~ (encodeTaggableMemo <$> ttMemo)
        TokenMint amount -> enc "mint" $ baseMap & k "amount" ?~ encodeTokenAmount amount
        TokenBurn amount -> enc "burn" $ baseMap & k "amount" ?~ encodeTokenAmount amount
        TokenAddAllowList target ->
            enc "addAllowList" $
                baseMap & k "target" ?~ encodeCborAccountAddress target
        TokenRemoveAllowList target ->
            enc "removeAllowList" $
                baseMap & k "target" ?~ encodeCborAccountAddress target
        TokenAddDenyList target ->
            enc "addDenyList" $
                baseMap & k "target" ?~ encodeCborAccountAddress target
        TokenRemoveDenyList target ->
            enc "removeDenyList" $
                baseMap & k "target" ?~ encodeCborAccountAddress target
        TokenPause -> enc "pause" baseMap
        TokenUnpause -> enc "unpause" baseMap
        TokenAssignAdminRoles details -> enc "assignAdminRoles" $ rolesMap details
        TokenRevokeAdminRoles details -> enc "revokeAdminRoles" $ rolesMap details
        TokenUpdateMetadata TokenMetadataUrl{..} ->
            enc "updateMetadata" $
                (encodeAdditionalMapCbor tmAdditional)
                    & k "token" ?~ encodeTokenId muoToken
                    & k "url" ?~ encodeString tmUrl
                    & k "checksumSha256" .~ (encodeSha256Hash <$> tmChecksumSha256)
  where
    rolesMap UpdateAdminRolesDetails{..} =
        baseMap
            & k "account" ?~ encodeCborAccountAddress uardAccount
            & k "roles" ?~ encodeSequence encodeTokenAdminRole uardRoles
    baseMap = Map.singleton (makeMapKeyEncoding $ encodeString "token") (encodeTokenId muoToken)
    k = at . makeMapKeyEncoding . encodeString
    enc opType body =
        encodeMapLen 1
            <> encodeString opType
            <> encodeMapDeterministic body
    encodeSha256Hash (SHA256.Hash h) = encodeBytes (FBS.toByteString h)

-- | A token transaction consists of a sequence of token operations.
newtype MetaUpdateTransaction = MetaUpdateTransaction
    { metaOperations :: Seq.Seq MetaUpdateOperation
    }
    deriving (Eq, Show)

instance AE.ToJSON MetaUpdateTransaction where
    toJSON = AE.toJSON . metaOperations

instance AE.FromJSON MetaUpdateTransaction where
    parseJSON = (MetaUpdateTransaction <$>) . AE.parseJSON

-- | Decode a CBOR-encoded 'MetaUpdateTransaction'.
decodeMetaUpdateTransaction :: Decoder s MetaUpdateTransaction
decodeMetaUpdateTransaction = MetaUpdateTransaction <$> decodeSequence decodeMetaUpdateOperation

-- | Parse a 'MetaUpdateTransaction' from a 'LBS.ByteString'. The entire bytestring
--  must be consumed in the parsing.
metaUpdateTransactionFromBytes :: LBS.ByteString -> Either String MetaUpdateTransaction
metaUpdateTransactionFromBytes = decodeFromBytes decodeMetaUpdateTransaction "token transaction"

-- | Encode a 'MetaUpdateTransaction' as CBOR.
encodeMetaUpdateTransaction :: MetaUpdateTransaction -> Encoding
encodeMetaUpdateTransaction = encodeSequence encodeMetaUpdateOperation . metaOperations

-- | CBOR-encode a 'MetaUpdateTransaction' to a (strict) 'BS.ByteString'.
metaUpdateTransactionToBytes :: MetaUpdateTransaction -> BS.ByteString
metaUpdateTransactionToBytes = encodeToBytes . encodeMetaUpdateTransaction

-- * Token module events

-- | A token-module generated event as part of executing a transaction.
data EncodedTokenEvent = EncodedTokenEvent
    { -- | The type of the event. At most 255 bytes.
      eteType :: !TokenEventType,
      -- | CBOR-encoded details.
      eteDetails :: !TokenEventDetails
    }
    deriving (Eq, Show)

data TokenEvent
    = -- | An account was added to the allow list.
      AddAllowListEvent !CborAccountAddress
    | -- | An account was removed from the allow list.
      RemoveAllowListEvent !CborAccountAddress
    | -- | An account was added to the deny list.
      AddDenyListEvent !CborAccountAddress
    | -- | An account was removed from the deny list.
      RemoveDenyListEvent !CborAccountAddress
    | -- | The execution of balance-changing operations was paused.
      Pause
    | -- | The execution of balance-changing operations was unpaused.
      Unpause
    | -- | The token metadata reference was updated.
      UpdateMetadataEvent !TokenMetadataUrl
    | -- | Admin roles were assigned to an account.
      AssignAdminRolesEvent !UpdateAdminRolesDetails
    | -- | Admin roles were revoked from an account.
      RevokeAdminRolesEvent !UpdateAdminRolesDetails
    deriving (Eq, Show)

-- | CBOR-encode the details for the list update events in the form:
--  > {"target": <TokenHolder>}
encodeTargetDetails :: CborAccountAddress -> TokenEventDetails
encodeTargetDetails target =
    TokenEventDetails . BSS.toShort . CBOR.toStrictByteString $
        encodeMapLen 1
            <> encodeString "target"
            <> encodeCborAccountAddress target

-- | CBOR-encoded event details consisting of just the empty map.
--  > {}
emptyEventDetails :: TokenEventDetails
emptyEventDetails = TokenEventDetails . BSS.toShort . CBOR.toStrictByteString $ encodeMapLen 0

-- | Encode a 'TokenEvent' as an 'EncodedTokenEvent'.
encodeTokenEvent :: TokenEvent -> EncodedTokenEvent
encodeTokenEvent = \case
    AddAllowListEvent target ->
        EncodedTokenEvent
            { eteType = TokenEventType "addAllowList",
              eteDetails = encodeTargetDetails target
            }
    RemoveAllowListEvent target ->
        EncodedTokenEvent
            { eteType = TokenEventType "removeAllowList",
              eteDetails = encodeTargetDetails target
            }
    AddDenyListEvent target ->
        EncodedTokenEvent
            { eteType = TokenEventType "addDenyList",
              eteDetails = encodeTargetDetails target
            }
    RemoveDenyListEvent target ->
        EncodedTokenEvent
            { eteType = TokenEventType "removeDenyList",
              eteDetails = encodeTargetDetails target
            }
    Pause ->
        EncodedTokenEvent
            { eteType = TokenEventType "pause",
              eteDetails = emptyEventDetails
            }
    Unpause ->
        EncodedTokenEvent
            { eteType = TokenEventType "unpause",
              eteDetails = emptyEventDetails
            }
    UpdateMetadataEvent meta ->
        EncodedTokenEvent
            { eteType = TokenEventType "updateMetadata",
              eteDetails =
                TokenEventDetails . BSS.toShort . CBOR.toStrictByteString $
                    encodeTokenMetadataUrl meta
            }
    AssignAdminRolesEvent details ->
        EncodedTokenEvent
            { eteType = TokenEventType "assignAdminRoles",
              eteDetails =
                TokenEventDetails . BSS.toShort . CBOR.toStrictByteString $
                    encodeUpdateAdminRolesDetails details
            }
    RevokeAdminRolesEvent details ->
        EncodedTokenEvent
            { eteType = TokenEventType "revokeAdminRoles",
              eteDetails =
                TokenEventDetails . BSS.toShort . CBOR.toStrictByteString $
                    encodeUpdateAdminRolesDetails details
            }

-- | Decoder for the event details of the list update events.
--  This is the "token-list-update-details" type in the CDDL schema.
decodeTokenEventTarget :: Decoder s CborAccountAddress
decodeTokenEventTarget = do
    maybeMapLen <- decodeMapLenOrIndef
    forM_ maybeMapLen $ \mapLen ->
        unless (mapLen == 1) $
            fail $
                "token-event: expected a map of size 1, but saw " ++ show mapLen
    label <- decodeString
    unless (label == "target") $
        fail $
            "token-event: expected \"target\" key, but saw "
                ++ show label
    target <- decodeCborAccountAddress
    when (isNothing maybeMapLen) $ do
        isEnd <- decodeBreakOr
        unless isEnd $ fail "token-event: expected end of map"
    return target

-- | Decode a 'TokenEvent' from an 'EncodedTokenEvent'.
decodeTokenEvent :: EncodedTokenEvent -> Either String TokenEvent
decodeTokenEvent EncodedTokenEvent{..} = case tokenEventTypeBytes eteType of
    "addAllowList" -> AddAllowListEvent <$> decodeTarget
    "removeAllowList" -> RemoveAllowListEvent <$> decodeTarget
    "addDenyList" -> AddDenyListEvent <$> decodeTarget
    "removeDenyList" -> RemoveDenyListEvent <$> decodeTarget
    "pause" -> Pause <$ decodePauseUnpause
    "unpause" -> Unpause <$ decodePauseUnpause
    "updateMetadata" -> UpdateMetadataEvent <$> decodeMetadata
    "assignAdminRoles" -> AssignAdminRolesEvent <$> decodeRoleUpdate
    "revokeAdminRoles" -> RevokeAdminRolesEvent <$> decodeRoleUpdate
    unknownType -> Left $ "token-event: unsupported event type: " ++ show unknownType
  where
    detailsLBS = LBS.fromStrict $ BSS.fromShort $ tokenEventDetailsBytes eteDetails
    decodeTarget = decodeFromBytes decodeTokenEventTarget "event details" detailsLBS
    decodePauseUnpause = decodeFromBytes decodeEmptyMap "event details" detailsLBS
    decodeMetadata = decodeFromBytes decodeTokenMetadataUrl "event details" detailsLBS
    decodeRoleUpdate = decodeFromBytes decodeUpdateAdminRolesDetails "event details" detailsLBS

-- * Reject reasons

-- | Details provided by the token module in the event of rejecting a transaction.
data EncodedTokenRejectReason = EncodedTokenRejectReason
    { -- | The type of the reject reason. At most 255 bytes.
      etrrType :: !BSS.ShortByteString,
      -- | (Optional) CBOR-encoded details.
      etrrDetails :: !(Maybe BSS.ShortByteString)
    }
    deriving (Eq, Show)

-- | Reasons that a transaction might be rejected by the Token Module.
data TokenRejectReason
    = -- | The token holder address was not valid.
      AddressNotFound
        { -- | The index in the list of operations of the failing operation.
          trrOperationIndex :: !Word64,
          -- | The address that could not be resolved.
          trrAddress :: !CborAccountAddress
        }
    | -- | The balance of tokens on the sender account is insufficient to perform the operation.
      TokenBalanceInsufficient
        { -- | The index in the list of operations of the failing operation.
          trrOperationIndex :: !Word64,
          -- | The available balance of the sender.
          trrAvailableBalance :: !TokenAmount,
          -- | The minimum required balance to perform the operation.
          trrRequiredBalance :: !TokenAmount
        }
    | -- | The transaction could not be deserialized.
      DeserializationFailure
        { -- | (Optional) text description of the failure mode.
          trrCause :: !(Maybe Text)
        }
    | -- | The operation was not supported.
      UnsupportedOperation
        { -- | The index in the list of operations of the failing operation.
          trrOperationIndex :: !Word64,
          -- | The type of the operation that was not supported.
          trrOperationType :: !Text,
          -- | The reason why the operation was not supported.
          trrReason :: !(Maybe Text)
        }
    | -- | Minting the requested amount would overflow the representable token amount.
      MintWouldOverflow
        { -- | The index in the list of operations of the failing operation.
          trrOperationIndex :: !Word64,
          -- | The requested amount to mint.
          trrRequestedAmount :: !TokenAmount,
          -- | The current circulating supply.
          trrCurrentSupply :: !TokenAmount,
          -- | The maximum representable token amount.
          trrMaxRepresentableAmount :: !TokenAmount
        }
    | -- | The operation is not permitted.
      OperationNotPermitted
        { -- | The index in the list of operations of the failing operation.
          trrOperationIndex :: !Word64,
          -- | (Optionally) the address that does not have the necessary permissions to perform
          --  the operation.
          trrAddressNotPermitted :: !(Maybe CborAccountAddress),
          -- | The reason why the operation is not permitted.
          trrReason :: !(Maybe Text)
        }
    deriving (Eq, Show)

-- | A builder for constructing 'TokenRejectReason' values with the 'AddressNotFound'
--  constructor.
data AddressNotFoundBuilder = AddressNotFoundBuilder
    { _anfbTransactionIndex :: Maybe Word64,
      _anfbRecipient :: Maybe CborAccountAddress
    }

makeLenses ''AddressNotFoundBuilder

-- | The empty 'AddressNotFoundBuilder'.
emptyAddressNotFoundBuilder :: AddressNotFoundBuilder
emptyAddressNotFoundBuilder = AddressNotFoundBuilder Nothing Nothing

-- | Construct a 'TokenRejectReason' from a 'AddressNotFoundBuilder'.
--  This results in @Left err@ (where @err@ describes the failure reason) when a required parameter
--  is missing.
buildAddressNotFound :: AddressNotFoundBuilder -> Either String TokenRejectReason
buildAddressNotFound AddressNotFoundBuilder{..} = do
    trrOperationIndex <- _anfbTransactionIndex `orFail` "Missing \"index\""
    trrAddress <- _anfbRecipient `orFail` "Missing \"recipient\""
    return AddressNotFound{..}

-- | A builder for constructing 'TokenRejectReason' values with the 'TokenBalanceInsufficient'
--  constructor.
data TokenBalanceInsufficientBuilder = TokenBalanceInsufficientBuilder
    { _tbibTransactionIndex :: Maybe Word64,
      _tbibAvailableBalance :: Maybe TokenAmount,
      _tbibRequiredBalance :: Maybe TokenAmount
    }

makeLenses ''TokenBalanceInsufficientBuilder

-- | The empty 'TokenBalanceInsufficientBuilder'.
emptyTokenBalanceInsufficientBuilder :: TokenBalanceInsufficientBuilder
emptyTokenBalanceInsufficientBuilder = TokenBalanceInsufficientBuilder Nothing Nothing Nothing

-- | Construct a 'TokenRejectReason' from a 'TokenBalanceInsufficientBuilder'.
--  This results in @Left err@ (where @err@ describes the failure reason) when a required parameter
--  is missing.
buildTokenBalanceInsufficient :: TokenBalanceInsufficientBuilder -> Either String TokenRejectReason
buildTokenBalanceInsufficient TokenBalanceInsufficientBuilder{..} = do
    trrOperationIndex <- _tbibTransactionIndex `orFail` "Missing \"index\""
    trrAvailableBalance <- _tbibAvailableBalance `orFail` "Missing \"availableBalance\""
    trrRequiredBalance <- _tbibRequiredBalance `orFail` "Missing \"requiredBalance\""
    return TokenBalanceInsufficient{..}

-- | A builder for constructing 'TokenRejectReason' values with the 'DeserializationFailure'
--  constructor.
newtype DeserializationFailureBuilder = DeserializationFailureBuilder
    { _dfbCause :: Maybe Text
    }

makeLenses ''DeserializationFailureBuilder

-- | The empty 'DeserializationFailureBuilder'.
emptyDeserializationFailureBuilder :: DeserializationFailureBuilder
emptyDeserializationFailureBuilder = DeserializationFailureBuilder Nothing

-- | Construct a 'TokenRejectReason' from a 'DeserializationFailureBuilder'.
--  This results in @Left err@ (where @err@ describes the failure reason) when a required parameter
--  is missing.
buildDeserializationFailure :: DeserializationFailureBuilder -> Either String TokenRejectReason
buildDeserializationFailure DeserializationFailureBuilder{..} = do
    let trrCause = _dfbCause
    return DeserializationFailure{..}

-- | A builder for constructing 'TokenRejectReason' values with the 'UnsupportedOperation'
--  constructor.
data UnsupportedOperationBuilder = UnsupportedOperationBuilder
    { _uobTransactionIndex :: Maybe Word64,
      _uobOperationType :: Maybe Text,
      _uobReason :: Maybe Text
    }

makeLenses ''UnsupportedOperationBuilder

-- | The empty 'UnsupportedOperationBuilder'.
emptyUnsupportedOperationBuilder :: UnsupportedOperationBuilder
emptyUnsupportedOperationBuilder =
    UnsupportedOperationBuilder Nothing Nothing Nothing

-- | Construct a 'TokenRejectReason' from a 'UnsupportedOperationBuilder'.
buildUnsupportedOperation ::
    UnsupportedOperationBuilder -> Either String TokenRejectReason
buildUnsupportedOperation UnsupportedOperationBuilder{..} = do
    trrOperationIndex <- _uobTransactionIndex `orFail` "Missing \"index\""
    trrOperationType <- _uobOperationType `orFail` "Missing \"operationType\""
    let trrReason = _uobReason
    return UnsupportedOperation{..}

-- | A builder for constructing 'TokenRejectReason' values with the 'MintWouldOverflow'
--  constructor.
data MintWouldOverflowBuilder = MintWouldOverflowBuilder
    { _mwoOperationIndex :: Maybe Word64,
      _mwoRequestedAmount :: Maybe TokenAmount,
      _mwoCurrentSupply :: Maybe TokenAmount,
      _mwoMaxRepresentableAmount :: Maybe TokenAmount
    }

makeLenses ''MintWouldOverflowBuilder

-- | The empty 'MintWouldOverflowBuilder'.
emptyMintWouldOverflowBuilder :: MintWouldOverflowBuilder
emptyMintWouldOverflowBuilder =
    MintWouldOverflowBuilder Nothing Nothing Nothing Nothing

-- | Construct a 'TokenRejectReason' from a 'MintWouldOverflowBuilder'.
buildMintWouldOverflow :: MintWouldOverflowBuilder -> Either String TokenRejectReason
buildMintWouldOverflow MintWouldOverflowBuilder{..} = do
    trrOperationIndex <- _mwoOperationIndex `orFail` "Missing \"index\""
    trrRequestedAmount <- _mwoRequestedAmount `orFail` "Missing \"requestedAmount\""
    trrCurrentSupply <- _mwoCurrentSupply `orFail` "Missing \"currentSupply\""
    trrMaxRepresentableAmount <- _mwoMaxRepresentableAmount `orFail` "Missing \"maxRepresentableAmount\""
    return MintWouldOverflow{..}

-- | A builder for constructing 'TokenRejectReason' values with the 'OperationNotPermitted'
--  constructor.
data OperationNotPermittedBuilder = OperationNotPermittedBuilder
    { _onpbTransactionIndex :: Maybe Word64,
      _onpbAddressNotPermitted :: Maybe CborAccountAddress,
      _onpbReason :: Maybe Text
    }

makeLenses ''OperationNotPermittedBuilder

-- | The empty 'OperationNotPermittedBuilder'.
emptyOperationNotPermittedBuilder :: OperationNotPermittedBuilder
emptyOperationNotPermittedBuilder =
    OperationNotPermittedBuilder Nothing Nothing Nothing

-- | Construct a 'TokenRejectReason' from a 'OperationNotPermittedBuilder'.
buildOperationNotPermitted :: OperationNotPermittedBuilder -> Either String TokenRejectReason
buildOperationNotPermitted OperationNotPermittedBuilder{..} = do
    trrOperationIndex <- _onpbTransactionIndex `orFail` "Missing \"index\""
    let trrAddressNotPermitted = _onpbAddressNotPermitted
    let trrReason = _onpbReason
    return OperationNotPermitted{..}

-- | Encode a 'TokenRejectReason' as an 'EncodedTokenRejectReason'.
encodeTokenRejectReason :: TokenRejectReason -> EncodedTokenRejectReason
encodeTokenRejectReason AddressNotFound{..} =
    EncodedTokenRejectReason
        { etrrType = "addressNotFound",
          etrrDetails =
            Just . BSS.toShort . CBOR.toStrictByteString . encodeMapDeterministic $
                Map.empty
                    & k "index" ?~ encodeWord64 trrOperationIndex
                    & k "address" ?~ encodeCborAccountAddress trrAddress
        }
  where
    k = at . makeMapKeyEncoding . encodeString
encodeTokenRejectReason TokenBalanceInsufficient{..} =
    EncodedTokenRejectReason
        { etrrType = "tokenBalanceInsufficient",
          etrrDetails =
            Just . BSS.toShort . CBOR.toStrictByteString . encodeMapDeterministic $
                Map.empty
                    & k "index" ?~ encodeWord64 trrOperationIndex
                    & k "availableBalance" ?~ encodeTokenAmount trrAvailableBalance
                    & k "requiredBalance" ?~ encodeTokenAmount trrRequiredBalance
        }
  where
    k = at . makeMapKeyEncoding . encodeString
encodeTokenRejectReason DeserializationFailure{..} =
    EncodedTokenRejectReason
        { etrrType = "deserializationFailure",
          etrrDetails =
            Just . BSS.toShort . CBOR.toStrictByteString . encodeMapDeterministic $
                Map.empty
                    & k "cause" .~ fmap encodeString trrCause
        }
  where
    k = at . makeMapKeyEncoding . encodeString
encodeTokenRejectReason UnsupportedOperation{..} =
    EncodedTokenRejectReason
        { etrrType = "unsupportedOperation",
          etrrDetails =
            Just . BSS.toShort . CBOR.toStrictByteString . encodeMapDeterministic $
                Map.empty
                    & k "index" ?~ encodeWord64 trrOperationIndex
                    & k "operationType" ?~ encodeString trrOperationType
                    & k "reason" .~ fmap encodeString trrReason
        }
  where
    k = at . makeMapKeyEncoding . encodeString
encodeTokenRejectReason MintWouldOverflow{..} =
    EncodedTokenRejectReason
        { etrrType = "mintWouldOverflow",
          etrrDetails =
            Just . BSS.toShort . CBOR.toStrictByteString . encodeMapDeterministic $
                Map.empty
                    & k "index" ?~ encodeWord64 trrOperationIndex
                    & k "requestedAmount" ?~ encodeTokenAmount trrRequestedAmount
                    & k "currentSupply" ?~ encodeTokenAmount trrCurrentSupply
                    & k "maxRepresentableAmount" ?~ encodeTokenAmount trrMaxRepresentableAmount
        }
  where
    k = at . makeMapKeyEncoding . encodeString
encodeTokenRejectReason OperationNotPermitted{..} =
    EncodedTokenRejectReason
        { etrrType = "operationNotPermitted",
          etrrDetails =
            Just . BSS.toShort . CBOR.toStrictByteString . encodeMapDeterministic $
                Map.empty
                    & k "index" ?~ encodeWord64 trrOperationIndex
                    & k "address" .~ fmap encodeCborAccountAddress trrAddressNotPermitted
                    & k "reason" .~ fmap encodeString trrReason
        }
  where
    k = at . makeMapKeyEncoding . encodeString

-- | Decode a CBOR-encoded 'TokenRejectReason' given a string representing the type of the failure.
decodeTokenRejectReasonDetails :: BSS.ShortByteString -> Decoder s TokenRejectReason
decodeTokenRejectReasonDetails "addressNotFound" =
    decodeMap
        valDecoder
        buildAddressNotFound
        emptyAddressNotFoundBuilder
  where
    valDecoder k@"index" = Just $ mapValueDecoder k decodeWord64 anfbTransactionIndex
    valDecoder k@"address" = Just $ mapValueDecoder k decodeCborAccountAddress anfbRecipient
    valDecoder _ = Nothing
decodeTokenRejectReasonDetails "tokenBalanceInsufficient" =
    decodeMap
        valDecoder
        buildTokenBalanceInsufficient
        emptyTokenBalanceInsufficientBuilder
  where
    valDecoder k@"index" = Just $ mapValueDecoder k decodeWord64 tbibTransactionIndex
    valDecoder k@"availableBalance" = Just $ mapValueDecoder k decodeTokenAmount tbibAvailableBalance
    valDecoder k@"requiredBalance" = Just $ mapValueDecoder k decodeTokenAmount tbibRequiredBalance
    valDecoder _ = Nothing
decodeTokenRejectReasonDetails "deserializationFailure" =
    decodeMap
        valDecoder
        buildDeserializationFailure
        emptyDeserializationFailureBuilder
  where
    valDecoder k@"cause" = Just $ mapValueDecoder k decodeString dfbCause
    valDecoder _ = Nothing
decodeTokenRejectReasonDetails "unsupportedOperation" =
    decodeMap
        valDecoder
        buildUnsupportedOperation
        emptyUnsupportedOperationBuilder
  where
    valDecoder k@"index" = Just $ mapValueDecoder k decodeWord64 uobTransactionIndex
    valDecoder k@"operationType" = Just $ mapValueDecoder k decodeString uobOperationType
    valDecoder k@"reason" = Just $ mapValueDecoder k decodeString uobReason
    valDecoder _ = Nothing
decodeTokenRejectReasonDetails "mintWouldOverflow" =
    decodeMap
        valDecoder
        buildMintWouldOverflow
        emptyMintWouldOverflowBuilder
  where
    valDecoder k@"index" = Just $ mapValueDecoder k decodeWord64 mwoOperationIndex
    valDecoder k@"requestedAmount" = Just $ mapValueDecoder k decodeTokenAmount mwoRequestedAmount
    valDecoder k@"currentSupply" = Just $ mapValueDecoder k decodeTokenAmount mwoCurrentSupply
    valDecoder k@"maxRepresentableAmount" = Just $ mapValueDecoder k decodeTokenAmount mwoMaxRepresentableAmount
    valDecoder _ = Nothing
decodeTokenRejectReasonDetails "operationNotPermitted" =
    decodeMap
        valDecoder
        buildOperationNotPermitted
        emptyOperationNotPermittedBuilder
  where
    valDecoder k@"index" = Just $ mapValueDecoder k decodeWord64 onpbTransactionIndex
    valDecoder k@"address" = Just $ mapValueDecoder k decodeCborAccountAddress onpbAddressNotPermitted
    valDecoder k@"reason" = Just $ mapValueDecoder k decodeString onpbReason
    valDecoder _ = Nothing
decodeTokenRejectReasonDetails unknownType =
    fail $ "token-reject-reason: unsupported reject reason: " ++ show unknownType

-- | Decode a 'TokenRejectReason' from an 'EncodedTokenRejectReason'.
decodeTokenRejectReason :: EncodedTokenRejectReason -> Either String TokenRejectReason
decodeTokenRejectReason EncodedTokenRejectReason{..} = case etrrDetails of
    Nothing ->
        Left $
            "token-reject-reason: missing details for reject reason type "
                ++ show etrrType
    Just details -> do
        let detailsLBS = LBS.fromStrict $ BSS.fromShort details
        decodeFromBytes (decodeTokenRejectReasonDetails etrrType) "token reject reason details" detailsLBS

-- * Token Module state

-- | A representation of the global state information maintained by the token
--  module. The name, metadata and governance account fields are required, but
--  all other state is optional and may or may not be provided depending on
--  whether the token module supports it.
data TokenModuleState = TokenModuleState
    { -- | The name of the token.
      tmsName :: !(Maybe Text),
      -- | A URL pointing to the token metadata.
      tmsMetadata :: !(Maybe TokenMetadataUrl),
      -- | The governance account address of the token.
      tmsGovernanceAccount :: !(Maybe CborAccountAddress),
      -- | Whether the token is paused.
      tmsPaused :: !(Maybe Bool),
      -- | Whether the token supports an allow list.
      tmsAllowList :: !(Maybe Bool),
      -- | Whether the token supports a deny list.
      tmsDenyList :: !(Maybe Bool),
      -- | Whether the token is mintable.
      tmsMintable :: !(Maybe Bool),
      -- | Whether the token is burnable.
      tmsBurnable :: !(Maybe Bool),
      -- | Any additional state data. Keys in this map SHOULD NOT overlap those
      --  used for the other (standardised) fields in this structure as that will
      --  break the invertability of the CBOR encoding.
      tmsAdditional :: !(Map.Map Text CBOR.Term)
    }
    deriving (Eq, Show)

instance AE.ToJSON TokenModuleState where
    toJSON TokenModuleState{..} =
        AE.object . catMaybes $
            [ ("name" AE..=) <$> tmsName,
              ("metadata" AE..=) <$> tmsMetadata,
              ("governanceAccount" AE..=) <$> tmsGovernanceAccount,
              ("paused" AE..=) <$> tmsPaused,
              ("allowList" AE..=) <$> tmsAllowList,
              ("denyList" AE..=) <$> tmsDenyList,
              ("mintable" AE..=) <$> tmsMintable,
              ("burnable" AE..=) <$> tmsBurnable,
              ("_additional" AE..=) <$> (encodeAdditionalMapJson tmsAdditional)
            ]

instance AE.FromJSON TokenModuleState where
    parseJSON = AE.withObject "TokenModuleState" $ \v -> do
        tmsName <- v AE..:? "name"
        tmsMetadata <- v AE..:? "metadata"
        tmsGovernanceAccount <- v AE..:? "governanceAccount"
        tmsPaused <- v AE..:? "paused"
        tmsAllowList <- v AE..:? "allowList"
        tmsDenyList <- v AE..:? "denyList"
        tmsMintable <- v AE..:? "mintable"
        tmsBurnable <- v AE..:? "burnable"
        -- Decode each hex string into a CBOR.Term
        tmsAdditional <-
            v AE..:? "_additional" .!= Map.empty
                >>= decodeAdditionalMapJson
        return TokenModuleState{..}

-- | Encode a 'TokenModuleState' as CBOR. Any keys in 'tmsAdditional' that overlap with
--  standardized keys (e.g. "name", "metadata", "allowList", etc.) will be ignored.
encodeTokenModuleState :: TokenModuleState -> Encoding
encodeTokenModuleState TokenModuleState{..} =
    encodeMapDeterministic $
        (encodeAdditionalMapCbor tmsAdditional)
            & k "name" .~ (encodeString <$> tmsName)
            & k "metadata" .~ (encodeTokenMetadataUrl <$> tmsMetadata)
            & k "governanceAccount" .~ (encodeCborAccountAddress <$> tmsGovernanceAccount)
            & k "paused" .~ fmap encodeBool tmsPaused
            & k "allowList" .~ fmap encodeBool tmsAllowList
            & k "denyList" .~ fmap encodeBool tmsDenyList
            & k "mintable" .~ fmap encodeBool tmsMintable
            & k "burnable" .~ fmap encodeBool tmsBurnable
  where
    k = at . makeMapKeyEncoding . encodeString

-- | CBOR-encode a 'TokenModuleState' to a (strict) 'BS.ByteString'.
--  This uses default values in the encoding.
tokenModuleStateToBytes :: TokenModuleState -> BS.ByteString
tokenModuleStateToBytes = encodeToBytes . encodeTokenModuleState

-- | Decode a CBOR-encoded 'TokenModuleState'.
decodeTokenModuleState :: Decoder s TokenModuleState
decodeTokenModuleState = decodeMap decodeVal build Map.empty
  where
    decodeVal key = Just $ mapValueDecoder key CBOR.decodeTerm (at key)
    build :: Map.Map Text CBOR.Term -> Either String TokenModuleState
    build m0 = do
        (tmsName, m1) <- getMaybeAndClear "name" convertText m0
        (tmsMetadata, m2) <- getMaybeAndClear "metadata" convertTokenMetadataUrl m1
        (tmsGovernanceAccount, m3) <- getMaybeAndClear "governanceAccount" convertCborAccountAddress m2
        (tmsPaused, m4) <- getMaybeAndClear "paused" convertBool m3
        (tmsAllowList, m5) <- getMaybeAndClear "allowList" convertBool m4
        (tmsDenyList, m6) <- getMaybeAndClear "denyList" convertBool m5
        (tmsMintable, m7) <- getMaybeAndClear "mintable" convertBool m6
        (tmsBurnable, tmsAdditional) <- getMaybeAndClear "burnable" convertBool m7
        return TokenModuleState{..}
    getMaybeAndClear key convert m = do
        let (maybeTerm, m') = m & at key <<.~ Nothing
        maybeVal <- forM maybeTerm $ \term -> convert term `orFail` ("Invalid " ++ show key)
        return (maybeVal, m')
    convertText (CBOR.TString t) = Just t
    convertText (CBOR.TStringI t) = Just (LazyText.toStrict t)
    convertText _ = Nothing

    -- Convert CBOR to TokenMetadataUrl
    convertTokenMetadataUrl :: CBOR.Term -> Maybe TokenMetadataUrl
    convertTokenMetadataUrl = either (const Nothing) Just . decodeTokenMetadataUrlHelper

    convertCborAccountAddress :: CBOR.Term -> Maybe CborAccountAddress
    convertCborAccountAddress = either (const Nothing) Just . decodeCborAccountAddressHelper

-- | Parse a 'TokenModuleState' from a 'LBS.ByteString'. The entire bytestring must
--  be consumed in the parsing.
tokenModuleStateFromBytes :: LBS.ByteString -> Either String TokenModuleState
tokenModuleStateFromBytes = decodeFromBytes decodeTokenModuleState "token module state"

-- * Token authorizations

-- | The authorizations structure for a PLT.
newtype TokenAuthorizationsMap = TokenAuthorizationsMap
    { taMap :: Map.Map TokenAdminRole (Seq.Seq CborAccountAddress)
    }
    deriving newtype (Eq, Show, AE.ToJSON, AE.FromJSON)

-- | Encode a 'TokenAuthorizationsMap' as CBOR.
encodeTokenAuthorizationsMap :: TokenAuthorizationsMap -> Encoding
encodeTokenAuthorizationsMap (TokenAuthorizationsMap m) =
    encodeMapDeterministic $
        Map.mapKeys (makeMapKeyEncoding . encodeTokenAdminRole) $
            encodeSequence encodeCborAccountAddress <$> m

-- | Decode a CBOR-encoded 'TokenAuthorizationsMap'.
decodeTokenAuthorizationsMap :: Decoder s TokenAuthorizationsMap
decodeTokenAuthorizationsMap = decodeMap decodeVal (Right . TokenAuthorizationsMap) Map.empty
  where
    decodeVal key = do
        role <- tokenAdminRoleFromText key
        return $ mapValueDecoder key (decodeSequence decodeCborAccountAddress) (at role)

-- | Parse a 'TokenAuthorizationsMap' form a 'LBS.ByteString'. The entire bytestring must be
--  consumed by the parsing.
tokenAuthorizationsMapFromBytes :: LBS.ByteString -> Either String TokenAuthorizationsMap
tokenAuthorizationsMapFromBytes =
    decodeFromBytes decodeTokenAuthorizationsMap "token authorizations"

-- | Encode a 'TokenAuthorizationsMap' as a 'BS.ByteString'.
tokenAuthorizationsMapToBytes :: TokenAuthorizationsMap -> BS.ByteString
tokenAuthorizationsMapToBytes = encodeToBytes . encodeTokenAuthorizationsMap

-- * Lock identifiers

-- | Lock identifier: a trio of numbers that together uniquely identify a lock.
data LockId = LockId
    { liAccountIndex :: !Word64,
      liSequenceNumber :: !Word64,
      liCreationOrder :: !Word64
    }
    deriving (Eq, Show)

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

convertLockId :: CBOR.Term -> Maybe LockId
convertLockId = termToMaybe decodeLockIdHelper

decodeLockIdHelper :: CBOR.Term -> Either String LockId
decodeLockIdHelper = \case
    CBOR.TTagged tag term
        | tag == fromIntegral lockIdTag ->
            case term of
                CBOR.TList [accountIndex, sequenceNumber, creationOrder] ->
                    LockId <$> convertWord64 accountIndex <*> convertWord64 sequenceNumber <*> convertWord64 creationOrder
                CBOR.TListI [accountIndex, sequenceNumber, creationOrder] ->
                    LockId <$> convertWord64 accountIndex <*> convertWord64 sequenceNumber <*> convertWord64 creationOrder
                _ -> Left "lock-id: Expected array of length 3"
        | otherwise -> Left $ "lock-id: Expected tag 40920 but found " ++ show tag
    other -> Left $ "lock-id: Unexpected term constructor: " ++ show other

-- * Lock configuration

-- | Capabilities supported by the simple lock controller.
data LockControllerSimpleV0Capability
    = LockControllerSimpleV0Fund
    | LockControllerSimpleV0Return
    | LockControllerSimpleV0Send
    | LockControllerSimpleV0Cancel
    deriving (Eq, Show)

encodeLockControllerSimpleV0Capability :: LockControllerSimpleV0Capability -> Encoding
encodeLockControllerSimpleV0Capability = encodeString . \case
    LockControllerSimpleV0Fund -> "fund"
    LockControllerSimpleV0Return -> "return"
    LockControllerSimpleV0Send -> "send"
    LockControllerSimpleV0Cancel -> "cancel"

convertLockControllerSimpleV0Capability :: CBOR.Term -> Maybe LockControllerSimpleV0Capability
convertLockControllerSimpleV0Capability = \case
    CBOR.TString "fund" -> Just LockControllerSimpleV0Fund
    CBOR.TString "return" -> Just LockControllerSimpleV0Return
    CBOR.TString "send" -> Just LockControllerSimpleV0Send
    CBOR.TString "cancel" -> Just LockControllerSimpleV0Cancel
    _ -> Nothing

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
            & k "account" ?~ encodeCborAccountAddress lcsv0gAccount
            & k "roles" ?~ encodeSequence encodeLockControllerSimpleV0Capability lcsv0gRoles
  where
    k = at . makeMapKeyEncoding . encodeString

convertLockControllerSimpleV0Grant :: CBOR.Term -> Maybe LockControllerSimpleV0Grant
convertLockControllerSimpleV0Grant = termToMaybe decodeLockControllerSimpleV0GrantHelper

decodeLockControllerSimpleV0GrantHelper :: CBOR.Term -> Either String LockControllerSimpleV0Grant
decodeLockControllerSimpleV0GrantHelper term = do
    m <- decodeTextKeyMap "lock-controller-simple-v0-grant" term
    lcsv0gAccount <- requireField "account" (termToMaybe decodeCborAccountAddressHelper) m
    lcsv0gRoles <- requireField "roles" (convertSequence convertLockControllerSimpleV0Capability) m
    return LockControllerSimpleV0Grant{..}

-- | Simple lock controller configuration.
data LockControllerSimpleV0 = LockControllerSimpleV0
    { lcsv0Grants :: !(Seq.Seq LockControllerSimpleV0Grant),
      lcsv0Tokens :: !(Seq.Seq TokenId),
      lcsv0KeepAlive :: !Bool,
      lcsv0Memo :: !(Maybe TaggableMemo)
    }
    deriving (Eq, Show)

encodeLockControllerSimpleV0 :: LockControllerSimpleV0 -> Encoding
encodeLockControllerSimpleV0 LockControllerSimpleV0{..} =
    encodeMapDeterministic $
        Map.empty
            & k "grants" ?~ encodeSequence encodeLockControllerSimpleV0Grant lcsv0Grants
            & k "tokens" ?~ encodeSequence encodeString (TextEncoding.decodeUtf8 . BSS.fromShort . tokenId <$> lcsv0Tokens)
            & k "keepAlive" .~ (if lcsv0KeepAlive then Just (encodeBool True) else Nothing)
            & k "memo" .~ (encodeTaggableMemo <$> lcsv0Memo)
  where
    k = at . makeMapKeyEncoding . encodeString

decodeLockControllerSimpleV0Helper :: CBOR.Term -> Either String LockControllerSimpleV0
decodeLockControllerSimpleV0Helper term = do
    m <- decodeTextKeyMap "lock-controller-simple-v0" term
    lcsv0Grants <- requireField "grants" (convertSequence convertLockControllerSimpleV0Grant) m
    lcsv0Tokens <- requireField "tokens" (convertSequence convertTokenId) m
    let lcsv0KeepAlive = orDefault (optionalField "keepAlive" convertBool m) False
    let lcsv0Memo = optionalField "memo" convertTaggableMemo m
    return LockControllerSimpleV0{..}

-- | Lock controller configuration.
data LockController
    = LockControllerSimpleV0Variant !LockControllerSimpleV0
    deriving (Eq, Show)

encodeLockController :: LockController -> Encoding
encodeLockController = \case
    LockControllerSimpleV0Variant cfg ->
        encodeMapDeterministic $ Map.singleton (makeMapKeyEncoding (encodeString "simpleV0")) (encodeLockControllerSimpleV0 cfg)

convertLockController :: CBOR.Term -> Maybe LockController
convertLockController = termToMaybe decodeLockControllerHelper

decodeLockControllerHelper :: CBOR.Term -> Either String LockController
decodeLockControllerHelper term = do
    m <- decodeTextKeyMap "lock-controller" term
    cfg <- requireField "simpleV0" (termToMaybe decodeLockControllerSimpleV0Helper) m
    return $ LockControllerSimpleV0Variant cfg

-- | Static configuration of a lock.
data LockConfig = LockConfig
    { lcRecipients :: !(Seq.Seq CborAccountAddress),
      lcExpiry :: !TransactionTime,
      lcController :: !LockController
    }
    deriving (Eq, Show)

encodeEpochTime :: TransactionTime -> Encoding
encodeEpochTime (TransactionTime t) = encodeTag 1 <> encodeWord64 t

convertEpochTime :: CBOR.Term -> Maybe TransactionTime
convertEpochTime = termToMaybe decodeEpochTimeHelper

decodeEpochTimeHelper :: CBOR.Term -> Either String TransactionTime
decodeEpochTimeHelper = \case
    CBOR.TTagged tag term
        | tag == 1 -> TransactionTime <$> convertWord64 term
        | otherwise -> Left $ "epoch-time: Expected tag 1 but found " ++ show tag
    other -> Left $ "epoch-time: Unexpected term constructor: " ++ show other

-- * Lock info

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
            & k "token" ?~ encodeString (TextEncoding.decodeUtf8 $ BSS.fromShort $ tokenId ltaToken)
            & k "amount" ?~ encodeTokenAmount ltaAmount
  where
    k = at . makeMapKeyEncoding . encodeString

convertLockedTokenAmount :: CBOR.Term -> Maybe LockedTokenAmount
convertLockedTokenAmount = termToMaybe decodeLockedTokenAmountHelper

decodeLockedTokenAmountHelper :: CBOR.Term -> Either String LockedTokenAmount
decodeLockedTokenAmountHelper term = do
    m <- decodeTextKeyMap "locked-token-and-amount" term
    ltaToken <- requireField "token" convertTokenId m
    ltaAmount <- requireField "amount" convertTokenAmountTerm m
    return LockedTokenAmount{..}

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
            & k "account" ?~ encodeCborAccountAddress lafAccount
            & k "amounts" ?~ encodeSequence encodeLockedTokenAmount lafAmounts
  where
    k = at . makeMapKeyEncoding . encodeString

convertLockAccountFunds :: CBOR.Term -> Maybe LockAccountFunds
convertLockAccountFunds = termToMaybe decodeLockAccountFundsHelper

decodeLockAccountFundsHelper :: CBOR.Term -> Either String LockAccountFunds
decodeLockAccountFundsHelper term = do
    m <- decodeTextKeyMap "lock-account-fund" term
    lafAccount <- requireField "account" (termToMaybe decodeCborAccountAddressHelper) m
    lafAmounts <- requireField "amounts" (convertSequence convertLockedTokenAmount) m
    return LockAccountFunds{..}

-- | Structured representation of the CBOR payload returned by `GetLockInfo`.
data LockInfoDetails = LockInfoDetails
    { lipLock :: !LockId,
      lipConfig :: !LockConfig,
      lipFunds :: !(Seq.Seq LockAccountFunds)
    }
    deriving (Eq, Show)

lockInfoFromBytes :: LBS.ByteString -> Either String LockInfoDetails
lockInfoFromBytes = decodeFromBytes decodeLockInfoDetails "lock info"

lockInfoToBytes :: LockInfoDetails -> BS.ByteString
lockInfoToBytes = encodeToBytes . encodeLockInfoDetails

decodeLockInfoDetails :: Decoder s LockInfoDetails
decodeLockInfoDetails = do
    term <- CBOR.decodeTerm
    either fail return $ decodeLockInfoDetailsHelper term

encodeLockInfoDetails :: LockInfoDetails -> Encoding
encodeLockInfoDetails LockInfoDetails{..} =
    encodeMapDeterministic $
        Map.empty
            & k "lock" ?~ encodeLockId lipLock
            & k "recipients" ?~ encodeSequence encodeCborAccountAddress (lcRecipients lipConfig)
            & k "expiry" ?~ encodeEpochTime (lcExpiry lipConfig)
            & k "controller" ?~ encodeLockController (lcController lipConfig)
            & k "funds" ?~ encodeSequence encodeLockAccountFunds lipFunds
  where
    k = at . makeMapKeyEncoding . encodeString

decodeLockInfoDetailsHelper :: CBOR.Term -> Either String LockInfoDetails
decodeLockInfoDetailsHelper term = do
    m <- decodeTextKeyMap "lock-info" term
    lipLock <- requireField "lock" convertLockId m
    lcRecipients <- requireField "recipients" (convertSequence (termToMaybe decodeCborAccountAddressHelper)) m
    lcExpiry <- requireField "expiry" convertEpochTime m
    lcController <- requireField "controller" convertLockController m
    lipFunds <- requireField "funds" (convertSequence convertLockAccountFunds) m
    return LockInfoDetails{lipConfig = LockConfig{..}, ..}

termToMaybe :: (CBOR.Term -> Either String a) -> CBOR.Term -> Maybe a
termToMaybe = (either (const Nothing) Just .)

convertTokenAmountTerm :: CBOR.Term -> Maybe TokenAmount
convertTokenAmountTerm term =
    either (const Nothing) Just $ decodeFromBytes decodeTokenAmount "token amount" (CBOR.toLazyByteString $ CBOR.encodeTerm term)

convertTaggableMemo :: CBOR.Term -> Maybe TaggableMemo
convertTaggableMemo term =
    either (const Nothing) Just $ decodeFromBytes decodeTaggableMemo "memo" (CBOR.toLazyByteString $ CBOR.encodeTerm term)

convertTokenId :: CBOR.Term -> Maybe TokenId
convertTokenId = \case
    CBOR.TString txt -> either (const Nothing) Just $ makeTokenId (BSS.toShort $ TextEncoding.encodeUtf8 txt)
    _ -> Nothing

convertBool :: CBOR.Term -> Maybe Bool
convertBool = \case
    CBOR.TBool b -> Just b
    _ -> Nothing

convertWord64 :: CBOR.Term -> Either String Word64
convertWord64 = \case
    CBOR.TInt i
        | i >= 0 -> Right (fromIntegral i)
        | otherwise -> Left "expected non-negative integer"
    _ -> Left "expected non-negative integer"

convertSequence :: (CBOR.Term -> Maybe a) -> CBOR.Term -> Maybe (Seq.Seq a)
convertSequence convert = \case
    CBOR.TList xs -> Seq.fromList <$> mapM convert xs
    CBOR.TListI xs -> Seq.fromList <$> mapM convert xs
    _ -> Nothing

decodeTextKeyMap :: String -> CBOR.Term -> Either String (Map.Map Text CBOR.Term)
decodeTextKeyMap label = \case
    CBOR.TMap kvs -> build kvs
    CBOR.TMapI kvs -> build kvs
    _ -> Left $ label ++ ": Expected a map"
  where
    build = fmap Map.fromList . mapM toPair
    toPair (CBOR.TString key, value) = Right (key, value)
    toPair _ = Left $ label ++ ": Expected text keys"

requireField :: Text -> (CBOR.Term -> Maybe a) -> Map.Map Text CBOR.Term -> Either String a
requireField key convert m = do
    term <- Map.lookup key m `orFail` (Text.unpack key ++ ": missing field")
    convert term `orFail` (Text.unpack key ++ ": invalid field")

optionalField :: Text -> (CBOR.Term -> Maybe a) -> Map.Map Text CBOR.Term -> Maybe a
optionalField key convert m = Map.lookup key m >>= convert

-- * Token account state

-- | The account state represents account-specific information that is maintained by the Token
--  Module, and is returned as part of a `GetAccountInfo` query. It does not include state that is
--  managed by the Token Kernel, such as the token identifier and account balance.
--
--  All fields are optional, and can be omitted if the module implementation does not support them.
--  The structure supports additional fields for future extensibility. Non-standard fields (i.e. any
--  fields that are not defined by a standard, and are specific to the module implementation) may
--  be included, and their tags should be prefixed with an underscore ("_") to distinguish them
--  as such.
data TokenModuleAccountState = TokenModuleAccountState
    { -- | Whether the account is on the allow list.
      --  This is only present if the token supports an allow list; that is, accounts can only
      --  send or receive tokens if they are on the allow list.
      tmasAllowList :: !(Maybe Bool),
      -- | Whether the account is on the deny list.
      --  This is only present if the token supports a deny list; that is, accounts can
      --  only send or receive tokens if they are not on the deny list.
      tmasDenyList :: !(Maybe Bool),
      -- | Any additional state data. Keys in this map SHOULD NOT overlap those
      --  used for the other (standardised) fields in this structure as that will
      --  break the invertability of the CBOR encoding.
      tmasAdditional :: !(Map.Map Text CBOR.Term)
    }
    deriving (Eq, Show)

instance AE.ToJSON TokenModuleAccountState where
    toJSON TokenModuleAccountState{..} =
        AE.object . catMaybes $
            [ ("allowList" AE..=) <$> tmasAllowList,
              ("denyList" AE..=) <$> tmasDenyList,
              ("_additional" AE..=) <$> encodeAdditionalMapJson tmasAdditional
            ]

instance AE.FromJSON TokenModuleAccountState where
    parseJSON = AE.withObject "TokenModuleAccountState" $ \v -> do
        tmasAllowList <- v AE..:? "allowList"
        tmasDenyList <- v AE..:? "denyList"
        tmasAdditional <- v AE..:? "_additional" AE..!= Map.empty >>= decodeAdditionalMapJson
        return TokenModuleAccountState{..}

-- | Encode a 'TokenModuleAccountState' as CBOR. Any keys in 'tmasAdditional' that overlap with
--  standardized keys (e.g. "allowList", "denyList", etc.) will be ignored.
encodeTokenModuleAccountState :: TokenModuleAccountState -> Encoding
encodeTokenModuleAccountState TokenModuleAccountState{..} =
    encodeMapDeterministic $
        encodeAdditionalMapCbor tmasAdditional
            & k "allowList" .~ fmap encodeBool tmasAllowList
            & k "denyList" .~ fmap encodeBool tmasDenyList
  where
    k = at . makeMapKeyEncoding . encodeString

-- | CBOR-encode a 'TokenModuleAccountState' to a (strict) 'BS.ByteString'.
tokenModuleAccountStateToBytes :: TokenModuleAccountState -> BS.ByteString
tokenModuleAccountStateToBytes = encodeToBytes . encodeTokenModuleAccountState

-- | Decode a CBOR-encoded 'TokenModuleAccountState'.
decodeTokenModuleAccountState :: Decoder s TokenModuleAccountState
decodeTokenModuleAccountState = decodeMap decodeVal build Map.empty
  where
    decodeVal key = Just $ mapValueDecoder key CBOR.decodeTerm (at key)
    build :: Map.Map Text CBOR.Term -> Either String TokenModuleAccountState
    build m0 = do
        (tmasAllowList, m1) <- getMaybeAndClear "allowList" convertBool m0
        (tmasDenyList, tmasAdditional) <- getMaybeAndClear "denyList" convertBool m1
        return TokenModuleAccountState{..}
    getMaybeAndClear key convert m = do
        let (maybeTerm, m') = m & at key <<.~ Nothing
        maybeVal <- forM maybeTerm $ \term -> convert term `orFail` ("Invalid " ++ show key)
        return (maybeVal, m')

-- | Parse a 'TokenModuleAccountState' from a 'LBS.ByteString'. The entire bytestring must
--  be consumed in the parsing.
tokenModuleAccountStateFromBytes :: LBS.ByteString -> Either String TokenModuleAccountState
tokenModuleAccountStateFromBytes = decodeFromBytes decodeTokenModuleAccountState "token module account state"
