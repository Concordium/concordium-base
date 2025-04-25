{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TemplateHaskell #-}

module Concordium.Types.ProtocolLevelTokens.CBOR where

import Codec.CBOR.Decoding
import Codec.CBOR.Encoding
import qualified Codec.CBOR.Read as CBOR
import qualified Codec.CBOR.Write as CBOR
import Control.Monad
import qualified Data.Aeson as AE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Foldable
import Data.Function
import qualified Data.Map.Lazy as Map
import Data.Maybe
import Data.Scientific
import Data.Text
import Data.Word
import Lens.Micro.Platform

import Concordium.Types.Tokens

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
            Nothing -> decodeIndef emptyBuilder
            Just len -> decodeDef len emptyBuilder
    case runBuilder builder of
        Left e -> fail e
        Right r -> return r
  where
    decodeKV builder = do
        key <- decodeString
        case valDecoder key of
            Nothing -> fail $ "Unexpected key " ++ show key
            Just decoder -> decoder builder
    decodeIndef builder = do
        decodeBreakOr >>= \case
            True -> return builder
            False -> do
                builder' <- decodeKV builder
                decodeIndef builder'
    decodeDef n builder
        | n > 0 = decodeDef (n - 1) =<< decodeKV builder
        | otherwise = return builder

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

-- * Encoding helpers

-- | An 'Encoding' that represents a key in a CBOR map. The 'Ord' instance corresponds to
--  lexicographic ordering of the CBOR encodings, so that these can be used to order keys for
--  deterministic CBOR encoding.
data MapKeyEncoding = MapKeyEncoding
    { meEncoding :: Encoding,
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
