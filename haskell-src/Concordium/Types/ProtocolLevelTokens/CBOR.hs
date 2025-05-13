{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TemplateHaskell #-}

module Concordium.Types.ProtocolLevelTokens.CBOR where

import qualified Codec.CBOR.ByteArray as BA
import qualified Codec.CBOR.ByteArray.Sliced as SBA
import Codec.CBOR.Decoding
import Codec.CBOR.Encoding
import qualified Codec.CBOR.Read as CBOR
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Write as CBOR
import Control.Monad
import qualified Data.Aeson as AE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Short as BSS
import Data.Foldable
import Data.Function
import qualified Data.Map.Lazy as Map
import Data.Maybe
import Data.Scientific
import qualified Data.Sequence as Seq
import Data.Text
import qualified Data.Text.Lazy as LazyText
import Data.Word
import Lens.Micro.Platform

import Concordium.ID.Types
import Concordium.Types.Memo
import Concordium.Types.Tokens
import qualified Data.FixedByteString as FBS

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
            { digits = fromIntegral (coefficient sci),
              nrDecimals = fromIntegral (negate (base10Exponent sci))
            }

-- | Encode a 'TokenAmount' as CBOR.
encodeTokenAmount :: TokenAmount -> Encoding
encodeTokenAmount TokenAmount{..} =
    encodeTag 4
        <> encodeListLen 2
        <> encodeInteger (-fromIntegral nrDecimals)
        <> encodeWord64 digits

-- | Helper function to encode a sequence.
encodeSequence :: (a -> Encoding) -> Seq.Seq a -> Encoding
encodeSequence encodeItem s =
    encodeListLen (fromIntegral $ Seq.length s)
        <> foldMap encodeItem s

-- * Initialization parameters

-- | The parsed token-initialization-parameters. These parameters are passed to the token module
--  to initialize the token.
data TokenInitializationParameters = TokenInitializationParameters
    { -- | The name of the token.
      tipName :: !Text,
      -- | A URL pointing to the token metadata.
      tipMetadata :: !Text,
      -- | Whether the token supports an allow list.
      tipAllowList :: !Bool,
      -- | Whether the token supports a deny list.
      tipDenyList :: !Bool,
      -- | The initial supply of the token. If not present, no tokens are minted initially.
      tipInitialSupply :: !(Maybe TokenAmount),
      -- | Whether the token is mintable.
      tipMintable :: !Bool,
      -- | Whether the token is burnable.
      tipBurnable :: !Bool
    }
    deriving (Eq, Show)

-- | Builder for 'TokenInitializationParameters'
data TokenInitializationParametersBuilder = TokenInitializationParametersBuilder
    { _tipbName :: Maybe Text,
      _tipbMetadata :: Maybe Text,
      _tipbAllowList :: Maybe Bool,
      _tipbDenyList :: Maybe Bool,
      _tipbInitialSupply :: Maybe TokenAmount,
      _tipbMintable :: Maybe Bool,
      _tipbBurnable :: Maybe Bool
    }

makeLenses ''TokenInitializationParametersBuilder

-- | A 'TokenInitializationParametersBuilder' with no fields initialized.
emptyTokenInitializationParametersBuilder :: TokenInitializationParametersBuilder
emptyTokenInitializationParametersBuilder =
    TokenInitializationParametersBuilder Nothing Nothing Nothing Nothing Nothing Nothing Nothing

-- | Construct a 'TokenInitializationParameters' from a 'TokenInitializationParametersBuilder'.
--  This results in @Left err@ (where @err@ describes the failure reason) when a required parameter
--  is missing. Missing optional parameters are populated with the appropriate default values.
buildTokenInitializationParameters ::
    TokenInitializationParametersBuilder -> Either String TokenInitializationParameters
buildTokenInitializationParameters TokenInitializationParametersBuilder{..} = do
    tipName <- _tipbName `orFail` "Missing \"name\""
    tipMetadata <- _tipbMetadata `orFail` "Missing \"metadata\""
    let tipAllowList = _tipbAllowList `orDefault` False
    let tipDenyList = _tipbDenyList `orDefault` False
    let tipInitialSupply = _tipbInitialSupply
    let tipMintable = _tipbMintable `orDefault` False
    let tipBurnable = _tipbBurnable `orDefault` False
    return TokenInitializationParameters{..}

instance AE.ToJSON TokenInitializationParameters where
    toJSON :: TokenInitializationParameters -> AE.Value
    toJSON TokenInitializationParameters{..} = do
        AE.object $
            [ "name" AE..= tipName,
              "metadata" AE..= tipMetadata,
              "allowList" AE..= tipAllowList,
              "denyList" AE..= tipDenyList,
              "mintable" AE..= tipMintable,
              "burnable" AE..= tipBurnable
            ]
                ++ ["initialSupply" AE..= initSupply | initSupply <- toList tipInitialSupply]

instance AE.FromJSON TokenInitializationParameters where
    parseJSON = AE.withObject "TokenInitializationParameters" $ \o -> do
        _tipbName <- o AE..:? "name"
        _tipbMetadata <- o AE..:? "metadata"
        _tipbAllowList <- o AE..:? "allowList"
        _tipbDenyList <- o AE..:? "denyList"
        _tipbInitialSupply <- o AE..:? "initialSupply"
        _tipbMintable <- o AE..:? "mintable"
        _tipbBurnable <- o AE..:? "burnable"
        case buildTokenInitializationParameters TokenInitializationParametersBuilder{..} of
            Left e -> fail e
            Right res -> return res

-- | Decode a CBOR-encoded 'TokenInitializationParameters'.
--  This decoder enforces CBOR-validity (in particular, no duplicate map keys), disallows
--  extraneous keys, and applies defaults specified by the CDDL schema.  It does not require
--  deterministic encoding.
decodeTokenInitializationParameters :: Decoder s TokenInitializationParameters
decodeTokenInitializationParameters =
    decodeMap
        valDecoder
        buildTokenInitializationParameters
        emptyTokenInitializationParametersBuilder
  where
    valDecoder k@"name" = Just $ mapValueDecoder k decodeString tipbName
    valDecoder k@"metadata" = Just $ mapValueDecoder k decodeString tipbMetadata
    valDecoder k@"allowList" = Just $ mapValueDecoder k decodeBool tipbAllowList
    valDecoder k@"denyList" = Just $ mapValueDecoder k decodeBool tipbDenyList
    valDecoder k@"initialSupply" = Just $ mapValueDecoder k decodeTokenAmount tipbInitialSupply
    valDecoder k@"mintable" = Just $ mapValueDecoder k decodeBool tipbMintable
    valDecoder k@"burnable" = Just $ mapValueDecoder k decodeBool tipbBurnable
    valDecoder _ = Nothing

-- | Parse a 'TokenInitializationParameters' from a 'LBS.ByteString'. The entire bytestring must
--  be consumed in the parsing.
tokenInitializationParametersFromBytes :: LBS.ByteString -> Either String TokenInitializationParameters
tokenInitializationParametersFromBytes lbs =
    case CBOR.deserialiseFromBytes decodeTokenInitializationParameters lbs of
        Left e -> Left (show e)
        Right ("", res) -> return res
        Right (remaining, _) ->
            Left $
                show (LBS.length remaining) ++ " bytes remaining after parsing token initialization parameters"

-- | Encode a 'TokenInitializationParameters' as CBOR.
encodeTokenInitializationParametersNoDefaults :: TokenInitializationParameters -> Encoding
encodeTokenInitializationParametersNoDefaults TokenInitializationParameters{..} =
    encodeMapDeterministic $
        Map.empty
            & k "name" ?~ encodeString tipName
            & k "metadata" ?~ encodeString tipMetadata
            & k "allowList" ?~ encodeBool tipAllowList
            & k "denyList" ?~ encodeBool tipDenyList
            & k "initialSupply" .~ (encodeTokenAmount <$> tipInitialSupply)
            & k "mintable" ?~ encodeBool tipMintable
            & k "burnable" ?~ encodeBool tipBurnable
  where
    k = at . makeMapKeyEncoding . encodeString

-- | Encode a 'TokenInitializationParameters' as CBOR. Keys that hold their default values will
--  be omitted from the encoding.
encodeTokenInitializationParametersWithDefaults :: TokenInitializationParameters -> Encoding
encodeTokenInitializationParametersWithDefaults TokenInitializationParameters{..} =
    encodeMapDeterministic $
        Map.empty
            & k "name" ?~ encodeString tipName
            & k "metadata" ?~ encodeString tipMetadata
            & setIfTrue "allowList" tipAllowList
            & setIfTrue "denyList" tipDenyList
            & k "initialSupply" .~ (encodeTokenAmount <$> tipInitialSupply)
            & setIfTrue "mintable" tipMintable
            & setIfTrue "burnable" tipBurnable
  where
    k = at . makeMapKeyEncoding . encodeString
    setIfTrue _ False = id
    setIfTrue key True = k key ?~ encodeBool True

-- | CBOR-encode a 'TokenInitializationParameters' to a (strict) 'BS.ByteString'.
--  This uses default values in the encoding.
tokenInitializationParametersToBytes :: TokenInitializationParameters -> BS.ByteString
tokenInitializationParametersToBytes =
    CBOR.toStrictByteString . encodeTokenInitializationParametersWithDefaults

-- * Token holder parameters

-- | Coin info that indicates the type of the address. Only Concordium addresses are supported.
data CoinInfo = CoinInfoConcordium
    deriving (Eq, Show)

-- | Decode a tagged-coininfo type. Only the concordium coininfo type is supported.
decodeCoinInfo :: Decoder s CoinInfo
decodeCoinInfo = do
    tag <- decodeTag
    unless (tag == 40305) $
        fail $
            "coininfo: Expected coininfo (tag 40305), but found tag " ++ show tag
    mLen <- decodeMapLenOrIndef
    forM_ mLen $ \len ->
        unless (len == 1) $
            fail $
                "coininfo: Expected a map of size 1, but size was " ++ show len
    key <- decodeInt
    unless (key == 1) $
        fail $
            "coininfo: Expected type key (1), but found " ++ show key
    coinType <- decodeInt
    ci <- case coinType of
        919 -> return CoinInfoConcordium
        _ -> fail $ "coininfo: Unsupported coin type: " ++ show coinType
    when (isNothing mLen) $
        decodeBreakOr >>= \b ->
            unless b (fail "coininfo: Expected end of array")
    return ci

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

-- | A destination that can receive and hold protocol-level tokens.
--  Currently, this can only be a Concordium account address.
data TokenReceiver = ReceiverAccount
    { -- | The account address.
      receiverAccountAddress :: !AccountAddress,
      -- | Although the account can only be a Concordium address, this specifies whether the
      --  address type should be explicit in the CBOR encoding.
      receiverAccountCoinInfo :: !(Maybe CoinInfo)
    }
    deriving (Eq, Show)

instance AE.ToJSON TokenReceiver where
    toJSON ReceiverAccount{..} = do
        AE.object $
            [ -- Tag with type of receiver
              "type" AE..= AE.String "account",
              "recipient" AE..= receiverAccountAddress
            ]

instance AE.FromJSON TokenReceiver where
    parseJSON = AE.withObject "TokenReceiver" $ \o -> do
        let receiverAccountCoinInfo = Nothing
        type_string <- o AE..: "type"
        case (type_string :: String) of
            "account" -> do
                receiverAccountAddress <- o AE..: "recipient"
                return ReceiverAccount{..}
            _ -> fail ("Unknown TokenReceiver type " ++ type_string)

-- | Create a 'ReceiverAccount' from an 'AccountAddress'. The address type will be present in the
--  CBOR encoding.
accountTokenReceiver :: AccountAddress -> TokenReceiver
accountTokenReceiver addr =
    ReceiverAccount
        { receiverAccountAddress = addr,
          receiverAccountCoinInfo = Just CoinInfoConcordium
        }

-- | Create a 'ReceiverAccount' from an 'AccountAddress'. The address type will not be present in
--  the CBOR encoding.
accountTokenReceiverShort :: AccountAddress -> TokenReceiver
accountTokenReceiverShort addr =
    ReceiverAccount
        { receiverAccountAddress = addr,
          receiverAccountCoinInfo = Nothing
        }

-- | A builder for the 'ReceiverAccount' constructor.
data ReceiverAccountBuilder = ReceiverAccountBuilder
    { -- | Receiver account address.
      _rabAccountAddress :: Maybe AccountAddress,
      -- | Identifier for the address type.
      _rabCoinInfo :: Maybe CoinInfo
    }

makeLenses ''ReceiverAccountBuilder

-- | Empty 'ReceiverAccountBuilder'.
emptyReceiverAccountBuilder :: ReceiverAccountBuilder
emptyReceiverAccountBuilder = ReceiverAccountBuilder Nothing Nothing

-- | Decode a CBOR-encoded 'TokenReceiver'.
decodeTokenReceiver :: Decoder s TokenReceiver
decodeTokenReceiver = do
    tag <- decodeTag
    unless (tag == 40307) $
        fail $
            "token-receiver: Expected cryptocurrency address (tag 40307), but found tag " ++ show tag
    mLen <- decodeMapLenOrIndef
    builder <- case mLen of
        Nothing -> decodeIndefHelper decodeKV emptyReceiverAccountBuilder
        Just len -> decodeDefHelper decodeKV len emptyReceiverAccountBuilder
    case builder ^. rabAccountAddress of
        Nothing -> fail "token-receiver: data (3) field is missing"
        Just addr -> return $ ReceiverAccount addr (builder ^. rabCoinInfo)
  where
    decodeKV builder = do
        key <- decodeInt
        case key of
            1 -> mapValueDecoder "info (1)" decodeCoinInfo rabCoinInfo builder
            2 -> fail "token-receiver: type (2) field is not supported"
            3 -> mapValueDecoder "data (3)" decodeAccountAddress rabAccountAddress builder
            _ -> fail $ "token-receiver: unexpected map key " ++ show key

encodeTokenReceiver :: TokenReceiver -> Encoding
encodeTokenReceiver ReceiverAccount{..} =
    encodeTag 40307
        <> encodeMapDeterministic
            ( Map.empty
                & k 1 .~ (encodeCoinInfo <$> receiverAccountCoinInfo)
                & k 3 ?~ encodeAccountAddress receiverAccountAddress
            )
  where
    k = at . makeMapKeyEncoding . encodeWord

-- | A 'TaggableMemo' represents a 'Memo' that may optionally be tagged as CBOR-encoded.
--  Memos are often assumed to be CBOR-encoded, but the tag can be used to make this explicit.
data TaggableMemo
    = -- | The memo is represented as a byte string with no tag.
      UntaggedMemo {untaggedMemo :: !Memo}
    | -- | The memo is represented as a byte string with a tag indicating CBOR-encoded data.
      CBORMemo {cborMemo :: !Memo}
    deriving (Eq, Show)

instance AE.ToJSON TaggableMemo where
    toJSON UntaggedMemo{..} = do
        AE.object $
            [ "type" AE..= AE.String "raw",
              "memo" AE..= untaggedMemo
            ]
    toJSON CBORMemo{..} = do
        AE.object $
            [ "type" AE..= AE.String "cbor",
              "memo" AE..= cborMemo
            ]

instance AE.FromJSON TaggableMemo where
    parseJSON = AE.withObject "TaggableMemo" $ \o -> do
        type_string <- o AE..: "type"
        case (type_string :: String) of
            "raw" -> do
                untaggedMemo <- o AE..: "memo"
                return UntaggedMemo{..}
            "cbor" -> do
                cborMemo <- o AE..: "memo"
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
      ttRecipient :: !TokenReceiver,
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
      _ttbRecipient :: Maybe TokenReceiver,
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
    valDecoder k@"recipient" = Just $ mapValueDecoder k decodeTokenReceiver ttbRecipient
    valDecoder k@"memo" = Just $ mapValueDecoder k decodeTaggableMemo ttbMemo
    valDecoder _ = Nothing

-- | Encode a 'TokenTransferBody' as CBOR.
encodeTokenTransfer :: TokenTransferBody -> Encoding
encodeTokenTransfer TokenTransferBody{..} =
    encodeMapDeterministic $
        Map.empty
            & k "amount" ?~ encodeTokenAmount ttAmount
            & k "recipient" ?~ encodeTokenReceiver ttRecipient
            & k "memo" .~ (encodeTaggableMemo <$> ttMemo)
  where
    k = at . makeMapKeyEncoding . encodeString

-- | A token-holder operation.
newtype TokenHolderOperation = TokenHolderTransfer TokenTransferBody
    deriving (Eq, Show)

instance AE.ToJSON TokenHolderOperation where
    toJSON (TokenHolderTransfer body) = AE.toJSON body

instance AE.FromJSON TokenHolderOperation where
    parseJSON v = TokenHolderTransfer <$> AE.parseJSON v

-- | Decode a CBOR-encoded 'TokenHolderOperation'.
decodeTokenHolderOperation :: Decoder s TokenHolderOperation
decodeTokenHolderOperation = do
    maybeMapLen <- decodeMapLenOrIndef
    forM_ maybeMapLen $ \mapLen ->
        unless (mapLen == 1) $
            fail $
                "token-holder-operation: expected a map of size 1, but saw " ++ show mapLen
    opType <- decodeString
    res <- case opType of
        "transfer" -> TokenHolderTransfer <$> decodeTokenTransfer
        _ -> fail $ "token-holder-operation: unsupported operation type: " ++ show opType
    when (isNothing maybeMapLen) $ do
        isEnd <- decodeBreakOr
        unless isEnd $ fail "token-holder-operation: expected end of map"
    return res

-- | Encode a 'TokenHolderOperation' as CBOR.
encodeTokenHolderOperation :: TokenHolderOperation -> Encoding
encodeTokenHolderOperation (TokenHolderTransfer ttb) =
    encodeMapLen 1
        <> encodeString "transfer"
        <> encodeTokenTransfer ttb

-- | A token-holder transaction consists of a sequence of token-holder operations.
newtype TokenHolderTransaction = TokenHolderTransaction
    { tokenHolderTransactions :: Seq.Seq TokenHolderOperation
    }
    deriving (Eq, Show)

instance AE.ToJSON TokenHolderTransaction where
    toJSON = AE.toJSON . tokenHolderTransactions

instance AE.FromJSON TokenHolderTransaction where
    parseJSON v = TokenHolderTransaction <$> AE.parseJSON v

-- | Decode a CBOR-encoded 'TokenHolderTransaction'.
decodeTokenHolderTransaction :: Decoder s TokenHolderTransaction
decodeTokenHolderTransaction = TokenHolderTransaction <$> decodeSequence decodeTokenHolderOperation

-- | Parse a 'TokenHolderTransaction' from a 'LBS.ByteString'. The entire bytestring must
--  be consumed in the parsing.
tokenHolderTransactionFromBytes :: LBS.ByteString -> Either String TokenHolderTransaction
tokenHolderTransactionFromBytes lbs =
    case CBOR.deserialiseFromBytes decodeTokenHolderTransaction lbs of
        Left e -> Left (show e)
        Right ("", res) -> return res
        Right (remaining, _) ->
            Left $
                show (LBS.length remaining)
                    ++ " bytes remaining after parsing token-holder transaction"

-- | Encode a 'TokenHolderTransaction' as CBOR.
encodeTokenHolderTransaction :: TokenHolderTransaction -> Encoding
encodeTokenHolderTransaction = encodeSequence encodeTokenHolderOperation . tokenHolderTransactions

-- | CBOR-encode a 'TokenHolderTransaction' to a (strict) 'BS.ByteString'.
tokenHolderTransactionToBytes :: TokenHolderTransaction -> BS.ByteString
tokenHolderTransactionToBytes = CBOR.toStrictByteString . encodeTokenHolderTransaction

-- * Reject reasons

-- | Details provided by the token module in the event of rejecting a transaction.
data EncodedTokenRejectReason = EncodedTokenRejectReason
    { -- | The type of the reject reason. At most 255 bytes.
      etrrType :: !BSS.ShortByteString,
      -- | (Optional) CBOR-encoded details.
      etrrDetails :: !(Maybe BSS.ShortByteString)
    }
    deriving (Eq, Show)

-- | Reasons that a token-holder operation might be rejected by the Token Module.
data TokenHolderFailure
    = -- | The recipient address was not valid.
      RecipientNotFound
        { -- | The index in the list of operations of the failing operation.
          thfOperationIndex :: !Word64,
          -- | The recipient address that could not be resolved.
          thfRecipient :: !TokenReceiver
        }
    | -- | The balance of tokens on the sender account is insufficient to perform the operation.
      TokenBalanceInsufficient
        { -- | The index in the list of operations of the failing operation.
          thfOperationIndex :: !Word64,
          -- | The available balance of the sender.
          thfAvailableBalance :: !TokenAmount,
          -- | The minimum required balance to perform the operation.
          thfRequiredBalance :: !TokenAmount
        }
    | -- | The 'TokenHolderTransaction' could not be deserialized.
      DeserializationFailure
        { -- | (Optional) text description of the failure mode.
          thfCause :: !(Maybe Text)
        }
    deriving (Eq, Show)

-- | A builder for constructing 'TokenHolderFailure' values with the 'RecipientNotFound'
--  constructor.
data RecipientNotFoundBuilder = RecipientNotFoundBuilder
    { _rnfbTransactionIndex :: Maybe Word64,
      _rnfbRecipient :: Maybe TokenReceiver
    }

makeLenses ''RecipientNotFoundBuilder

-- | The empty 'RecipientNotFoundBuilder'.
emptyRecipientNotFoundBuilder :: RecipientNotFoundBuilder
emptyRecipientNotFoundBuilder = RecipientNotFoundBuilder Nothing Nothing

-- | Construct a 'TokenHolderFailure' from a 'RecipientNotFoundBuilder'.
--  This results in @Left err@ (where @err@ describes the failure reason) when a required parameter
--  is missing.
buildRecipientNotFound :: RecipientNotFoundBuilder -> Either String TokenHolderFailure
buildRecipientNotFound RecipientNotFoundBuilder{..} = do
    thfOperationIndex <- _rnfbTransactionIndex `orFail` "Missing \"index\""
    thfRecipient <- _rnfbRecipient `orFail` "Missing \"recipient\""
    return RecipientNotFound{..}

-- | A builder for constructing 'TokenHolderFailure' values with the 'TokenBalanceInsufficient'
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

-- | Construct a 'TokenHolderFailure' from a 'TokenBalanceInsufficientBuilder'.
--  This results in @Left err@ (where @err@ describes the failure reason) when a required parameter
--  is missing.
buildTokenBalanceInsufficient :: TokenBalanceInsufficientBuilder -> Either String TokenHolderFailure
buildTokenBalanceInsufficient TokenBalanceInsufficientBuilder{..} = do
    thfOperationIndex <- _tbibTransactionIndex `orFail` "Missing \"index\""
    thfAvailableBalance <- _tbibAvailableBalance `orFail` "Missing \"availableBalance\""
    thfRequiredBalance <- _tbibRequiredBalance `orFail` "Missing \"requiredBalance\""
    return TokenBalanceInsufficient{..}

-- | A builder for constructing 'TokenHolderFailure' values with the 'DeserializationFailure'
--  constructor.
newtype DeserializationFailureBuilder = DeserializationFailureBuilder
    { _dfbCause :: Maybe Text
    }

makeLenses ''DeserializationFailureBuilder

-- | The empty 'DeserializationFailureBuilder'.
emptyDeserializationFailureBuilder :: DeserializationFailureBuilder
emptyDeserializationFailureBuilder = DeserializationFailureBuilder Nothing

-- | Construct a 'TokenHolderFailure' from a 'DeserializationFailureBuilder'.
--  This results in @Left err@ (where @err@ describes the failure reason) when a required parameter
--  is missing.
buildDeserializationFailure :: DeserializationFailureBuilder -> Either String TokenHolderFailure
buildDeserializationFailure DeserializationFailureBuilder{..} = do
    let thfCause = _dfbCause
    return DeserializationFailure{..}

-- | Encode a 'TokenHolderFailure' as an 'EncodedTokenRejectReason'.
encodeTokenHolderFailure :: TokenHolderFailure -> EncodedTokenRejectReason
encodeTokenHolderFailure RecipientNotFound{..} =
    EncodedTokenRejectReason
        { etrrType = "recipientNotFound",
          etrrDetails =
            Just . BSS.toShort . CBOR.toStrictByteString . encodeMapDeterministic $
                Map.empty
                    & k "index" ?~ encodeWord64 thfOperationIndex
                    & k "recipient" ?~ encodeTokenReceiver thfRecipient
        }
  where
    k = at . makeMapKeyEncoding . encodeString
encodeTokenHolderFailure TokenBalanceInsufficient{..} =
    EncodedTokenRejectReason
        { etrrType = "tokenBalanceInsufficient",
          etrrDetails =
            Just . BSS.toShort . CBOR.toStrictByteString . encodeMapDeterministic $
                Map.empty
                    & k "index" ?~ encodeWord64 thfOperationIndex
                    & k "availableBalance" ?~ encodeTokenAmount thfAvailableBalance
                    & k "requiredBalance" ?~ encodeTokenAmount thfRequiredBalance
        }
  where
    k = at . makeMapKeyEncoding . encodeString
encodeTokenHolderFailure DeserializationFailure{..} =
    EncodedTokenRejectReason
        { etrrType = "deserializationFailure",
          etrrDetails =
            Just . BSS.toShort . CBOR.toStrictByteString . encodeMapDeterministic $
                Map.empty
                    & k "cause" .~ fmap encodeString thfCause
        }
  where
    k = at . makeMapKeyEncoding . encodeString

-- | Decode a CBOR-encoded 'TokenHolderFailure' given a string representing the type of the failure.
decodeTokenHolderFailure :: BSS.ShortByteString -> Decoder s TokenHolderFailure
decodeTokenHolderFailure "recipientNotFound" =
    decodeMap
        valDecoder
        buildRecipientNotFound
        emptyRecipientNotFoundBuilder
  where
    valDecoder k@"index" = Just $ mapValueDecoder k decodeWord64 rnfbTransactionIndex
    valDecoder k@"recipient" = Just $ mapValueDecoder k decodeTokenReceiver rnfbRecipient
    valDecoder _ = Nothing
decodeTokenHolderFailure "tokenBalanceInsufficient" =
    decodeMap
        valDecoder
        buildTokenBalanceInsufficient
        emptyTokenBalanceInsufficientBuilder
  where
    valDecoder k@"index" = Just $ mapValueDecoder k decodeWord64 tbibTransactionIndex
    valDecoder k@"availableBalance" = Just $ mapValueDecoder k decodeTokenAmount tbibAvailableBalance
    valDecoder k@"requiredBalance" = Just $ mapValueDecoder k decodeTokenAmount tbibRequiredBalance
    valDecoder _ = Nothing
decodeTokenHolderFailure "deserializationFailure" =
    decodeMap
        valDecoder
        buildDeserializationFailure
        emptyDeserializationFailureBuilder
  where
    valDecoder k@"cause" = Just $ mapValueDecoder k decodeString dfbCause
    valDecoder _ = Nothing
decodeTokenHolderFailure unknownType =
    fail $ "token-holder-failure: unsupported failure type: " ++ show unknownType

-- * Token Module state

-- | A representation of the global state information maintained by the token module.
--  The name and metadata fields are required, but all other state is optional and may or may not
--  be provided depending on whether the token module supports it.
data TokenModuleState = TokenModuleState
    { -- | The name of the token.
      tmsName :: !Text,
      -- | A URL pointing to the token metadata.
      tmsMetadata :: !Text,
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

-- | Encode a 'TokenModuleState' as CBOR. Any keys in 'tmsAdditional' that overlap with
--  standardized keys (e.g. "name", "metadata", "allowList", etc.) will be ignored.
encodeTokenModuleState :: TokenModuleState -> Encoding
encodeTokenModuleState TokenModuleState{..} =
    encodeMapDeterministic $
        additionalMap
            & k "name" ?~ encodeString tmsName
            & k "metadata" ?~ encodeString tmsMetadata
            & k "allowList" .~ fmap encodeBool tmsAllowList
            & k "denyList" .~ fmap encodeBool tmsDenyList
            & k "mintable" .~ fmap encodeBool tmsMintable
            & k "burnable" .~ fmap encodeBool tmsBurnable
  where
    additionalMap =
        Map.fromList
            [ (makeMapKeyEncoding (encodeString key), CBOR.encodeTerm val)
              | (key, val) <- Map.toList tmsAdditional
            ]
    k = at . makeMapKeyEncoding . encodeString

-- | CBOR-encode a 'TokenModuleState' to a (strict) 'BS.ByteString'.
--  This uses default values in the encoding.
tokenModuleStateToBytes :: TokenModuleState -> BS.ByteString
tokenModuleStateToBytes = CBOR.toStrictByteString . encodeTokenModuleState

-- | Decode a CBOR-encoded 'TokenModuleState'.
decodeTokenModuleState :: Decoder s TokenModuleState
decodeTokenModuleState = decodeMap decodeVal build Map.empty
  where
    decodeVal key = Just $ mapValueDecoder key CBOR.decodeTerm (at key)
    build :: Map.Map Text CBOR.Term -> Either String TokenModuleState
    build m0 = do
        (tmsName, m1) <- getAndClear "name" convertText m0
        (tmsMetadata, m2) <- getAndClear "metadata" convertText m1
        (tmsAllowList, m3) <- getMaybeAndClear "allowList" convertBool m2
        (tmsDenyList, m4) <- getMaybeAndClear "denyList" convertBool m3
        (tmsMintable, m5) <- getMaybeAndClear "mintable" convertBool m4
        (tmsBurnable, tmsAdditional) <- getMaybeAndClear "burnable" convertBool m5
        return TokenModuleState{..}
    getAndClear key convert m = do
        let (maybeTerm, m') = m & at key <<.~ Nothing
        term <- maybeTerm `orFail` ("Missing " ++ show key)
        val <- convert term `orFail` ("Invalid " ++ show key)
        return (val, m')
    getMaybeAndClear key convert m = do
        let (maybeTerm, m') = m & at key <<.~ Nothing
        maybeVal <- forM maybeTerm $ \term -> convert term `orFail` ("Invalid " ++ show key)
        return (maybeVal, m')
    convertText (CBOR.TString t) = Just t
    convertText (CBOR.TStringI t) = Just (LazyText.toStrict t)
    convertText _ = Nothing
    convertBool (CBOR.TBool b) = Just b
    convertBool _ = Nothing

-- | Parse a 'TokenModuleState' from a 'LBS.ByteString'. The entire bytestring must
--  be consumed in the parsing.
tokenModuleStateFromBytes :: LBS.ByteString -> Either String TokenModuleState
tokenModuleStateFromBytes lbs =
    case CBOR.deserialiseFromBytes decodeTokenModuleState lbs of
        Left e -> Left (show e)
        Right ("", res) -> return res
        Right (remaining, _) ->
            Left $
                show (LBS.length remaining) ++ " bytes remaining after parsing token module state"
