{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TemplateHaskell #-}

module Concordium.Types.ProtocolLevelTokens.CBOR where

import Codec.CBOR.Decoding
import Control.Monad
import Data.Maybe
import Data.Scientific
import Data.Text
import Data.Word
import Lens.Micro.Platform

import Concordium.Types.Queries.Tokens

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

orFail :: Maybe a -> b -> Either b a
orFail Nothing = Left
orFail (Just v) = const (Right v)

orDefault :: Maybe a -> a -> a
orDefault Nothing = id
orDefault (Just a) = const a

buildTokenInitializationParameters :: TokenInitializationParametersBuilder -> Either String TokenInitializationParameters
buildTokenInitializationParameters TokenInitializationParametersBuilder{..} = do
    tipName <- _tipbName `orFail` "Missing 'name'"
    tipMetadata <- _tipbMetadata `orFail` "Missing 'metadata'"
    let tipAllowList = _tipbAllowList `orDefault` False
    let tipDenyList = _tipbDenyList `orDefault` False
    let tipInitialSupply = _tipbInitialSupply
    let tipMintable = _tipbMintable `orDefault` False
    let tipBurnable = _tipbBurnable `orDefault` False
    return TokenInitializationParameters{..}

data MapValueDecoder s a = forall b.
      MapValueDecoder
    { mvdDecoder :: Decoder s b,
      mvdTrySet :: b -> a -> Maybe a
    }

-- | Given a 'Lens'' for a field in a builder, set the field to the given value if it is not
--  already present. If a value is already present, then this returns @Nothing@.
trySet :: Lens' a (Maybe b) -> b -> a -> Maybe a
trySet l = \v -> l (maybe (Just (Just v)) (const Nothing))

decodeMap :: (Text -> Maybe (MapValueDecoder s builder)) -> (builder -> Either String r) -> builder -> Decoder s r
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
            Just MapValueDecoder{..} -> do
                val <- mvdDecoder
                case mvdTrySet val builder of
                    Nothing -> fail $ "Key already set: " ++ show key
                    Just builder' -> return builder'
    decodeIndef builder = do
        decodeBreakOr >>= \case
            True -> return builder
            False -> do
                builder' <- decodeKV builder
                decodeIndef builder'
    decodeDef n builder
        | n > 0 = decodeDef (n - 1) =<< decodeKV builder
        | otherwise = return builder

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

decodeTokenInitializationParameters :: Decoder s TokenInitializationParameters
decodeTokenInitializationParameters =
    decodeMap
        valDecoder
        buildTokenInitializationParameters
        emptyTokenInitializationParametersBuilder
  where
    valDecoder "name" = Just $ MapValueDecoder decodeString (trySet tipbName)
    valDecoder "metadata" = Just $ MapValueDecoder decodeString (trySet tipbMetadata)
    valDecoder "allowList" = Just $ MapValueDecoder decodeBool (trySet tipbAllowList)
    valDecoder "denyList" = Just $ MapValueDecoder decodeBool (trySet tipbAllowList)
    valDecoder "initialSupply" = Just $ MapValueDecoder decodeTokenAmount (trySet tipbInitialSupply)
    valDecoder "mintable" = Just $ MapValueDecoder decodeBool (trySet tipbMintable)
    valDecoder "burnable" = Just $ MapValueDecoder decodeBool (trySet tipbBurnable)
    valDecoder _ = Nothing
