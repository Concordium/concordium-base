{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Types associated with protocol-level tokens.
module Concordium.Types.Tokens where

import Control.Monad
import qualified Data.Aeson as AE
import qualified Data.Aeson.Types as AE
import Data.Bits
import qualified Data.ByteString.Short as BSS
import qualified Data.Serialize as S
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Text.Read as T
import Data.Word

import qualified Concordium.Crypto.ByteStringHelpers as BSH

-- | The unique token identifier for a protocol-level token.
--  This is given as a symbol unique across the whole chain.
--  The byte string must be between 1 and 128 bytes long and only consist of a-z, A-Z, 0-9, `-`, `.` and `%`.
newtype TokenId = TokenId {tokenId :: BSS.ShortByteString}
    deriving (Eq, Ord)

instance Show TokenId where
    show (TokenId sbs) = T.unpack (T.decodeUtf8Lenient (BSS.fromShort sbs))

-- | Check if a byte represents an allowed character
isAllowedByte :: Word8 -> Bool
isAllowedByte w =
    (0x41 <= w && w <= 0x5A) -- 'A'-'Z'
        || (0x61 <= w && w <= 0x7A) -- 'a'-'z'
        || (0x30 <= w && w <= 0x39) -- '0'-'9'
        || w == 0x2D -- '-'
        || w == 0x2E -- '.'
        || w == 0x25 -- '%'

-- | Try to construct a valid 'TokenId' from a 'BSS.ShortByteString'.
--  This can fail if the string is shorter than 1 or longer than 128 bytes or does not consist of only
--  a-z, A-Z, 0-9, `-`, `.` and `%`.
--  In the event of a failure @Left err@ is returned, where @err@ describes the failure.
makeTokenId :: BSS.ShortByteString -> Either String TokenId
makeTokenId sbs
    | len < 1 = Left $ "TokenId length (" ++ show (BSS.length sbs) ++ ") must be at least 1"
    | len > 128 = Left $ "TokenId length (" ++ show (BSS.length sbs) ++ ") must be at most 128"
    | not (BSS.all isAllowedByte sbs) =
        Left "TokenId contains invalid characters"
    | otherwise = Right (TokenId sbs)
  where
    len = BSS.length sbs

instance S.Serialize TokenId where
    put (TokenId tid) = do
        S.putWord8 $ fromIntegral $ BSS.length tid
        S.putShortByteString tid
    get = do
        len <- S.getWord8
        sbs <- S.getShortByteString (fromIntegral len)
        case makeTokenId sbs of
            Left e -> fail e
            Right tokId -> return tokId

-- | Deserialize a 'TokenId' without checking the invariant that the string is valid UTF-8.
--  This should only be used where deserializing from a trusted source.
unsafeGetTokenId :: S.Get TokenId
unsafeGetTokenId = do
    len <- S.getWord8
    sbs <- S.getShortByteString (fromIntegral len)
    return (TokenId sbs)

instance AE.ToJSON TokenId where
    -- decodeUtf8 will throw an exception if it fails, but we should be safe since the TokenId
    -- should enforce valid UTF-8.
    toJSON TokenId{..} = AE.String $ T.decodeUtf8 $ BSS.fromShort tokenId

instance AE.FromJSON TokenId where
    parseJSON (AE.String text) = case makeTokenId (BSS.toShort $ T.encodeUtf8 text) of
        Right tid -> return tid
        Left err -> fail ("TokenId validation failed: " ++ err)
    parseJSON invalid = AE.prependFailure "parsing TokenId failed" (AE.typeMismatch "String" invalid)

-- | Represents the raw amount of a token. This is the amount of the token in its smallest unit.
newtype TokenRawAmount = TokenRawAmount {theTokenRawAmount :: Word64}
    deriving newtype (Eq, Ord, Show, Num, Real, Bounded, Enum, Integral)

instance AE.ToJSON TokenRawAmount where
    toJSON (TokenRawAmount amt) = AE.String $ T.pack $ show amt
instance AE.FromJSON TokenRawAmount where
    parseJSON = AE.withText "TokenRawAmount" $ \t -> do
        case T.decimal t of
            Right (i, "")
                | i > fromIntegral (maxBound :: TokenRawAmount) ->
                    fail "TokenRawAmount out of bounds."
                | otherwise -> return (fromInteger i)
            Left e -> fail $ "TokenRawAmount is not a valid decimal number: " ++ e
            _ -> fail "TokenRawAmount is not a valid decimal number."

-- | Serialization of 'TokenRawAmount' is as a variable length quantity (VLQ). We disallow
--  0-padding to enforce canonical serialization.
--
--  The VLQ encoding represents a value in big-endian base 128. Each byte of the encoding uses
--  the high-order bit to indicate if further bytes follow (when set). The remaining bits represent
--  the positional value in base 128.  See https://en.wikipedia.org/wiki/Variable-length_quantity
instance S.Serialize TokenRawAmount where
    put (TokenRawAmount amt) = do
        mapM_ S.putWord8 (chunk amt [])
      where
        chunk num []
            | num == 0 = [0]
            | otherwise = chunk (num `shiftR` 7) [fromIntegral $ num .&. 0x7f]
        chunk num l
            | num == 0 = l
            | otherwise = chunk (num `shiftR` 7) (fromIntegral (0x80 .|. (num .&. 0x7f)) : l)
    get = TokenRawAmount <$> loop 0
      where
        loop accum = do
            b <- S.getWord8
            when (b == 0x80 && accum == 0) $
                fail "Padding bytes are not allowed"
            -- The following test ensures that @accum * 128 <= maxBound@, i.e. the shift in
            -- computing @accum'@ will not overflow.
            when (accum > maxBound `shiftR` 7) $
                fail "Value out of range"
            let accum' = accum `shiftL` 7 .|. fromIntegral (b .&. 0x7f)
            if testBit b 7
                then loop accum'
                else return accum'

-- | The token amount representation.
--  The amount is computed as `amount = value * 10^(-decimals)`.
data TokenAmount = TokenAmount
    { -- | The value in the smallest unit of the token.
      taValue :: !TokenRawAmount,
      -- | The number of decimals in the token representation.
      taDecimals :: !Word8
    }
    deriving (Eq, Show)

instance AE.ToJSON TokenAmount where
    toJSON TokenAmount{..} =
        AE.object
            [ ("value", AE.String $ T.pack $ show taValue),
              ("decimals", AE.toJSON taDecimals)
            ]

instance AE.FromJSON TokenAmount where
    parseJSON = AE.withObject "TokenAmount" $ \o -> do
        taValue <- o AE..: "value"
        taDecimals <- o AE..: "decimals"
        return $ TokenAmount{..}

instance S.Serialize TokenAmount where
    put (TokenAmount{..}) = do
        S.put taValue
        S.putWord8 taDecimals
    get = do
        taValue <- S.get
        taDecimals <- S.getWord8
        return $ TokenAmount{..}

-- | Token event type string.
--  MUST be at most 255 bytes and SHOULD BE a valid UTF-8 string.
--
--  Serialization does not require or check for UTF-8 validity.
--  Converting to JSON will replace invalid UTF-8 bytes with the unicode replacement character,
--  which means that converting to JSON and back is only the identity for valid UTF-8.
newtype TokenEventType = TokenEventType {tokenEventTypeBytes :: BSS.ShortByteString}
    deriving newtype (Eq, Show)

instance AE.ToJSON TokenEventType where
    -- decodeUtf8 will throw an exception if it fails, but we should be safe since the TokenEventType
    -- should enforce valid UTF-8.
    toJSON TokenEventType{..} = AE.String $ T.decodeUtf8Lenient $ BSS.fromShort tokenEventTypeBytes

instance AE.FromJSON TokenEventType where
    parseJSON (AE.String text) = case makeTokenEventType $ BSS.toShort $ T.encodeUtf8 text of
        Right eventType -> return eventType
        Left err -> fail err
    parseJSON invalid = AE.prependFailure "parsing TokenEventType failed" (AE.typeMismatch "String" invalid)

-- | Try to construct a valid 'TokenEventType' from a 'BSS.ShortByteString'.
--  This can fail if the string is longer than 255 bytes or is not valid UTF-8.
--  In the event of a failure @Left err@ is returned, where @err@ describes the failure.
makeTokenEventType :: BSS.ShortByteString -> Either String TokenEventType
makeTokenEventType sbs
    | BSS.length sbs > 255 =
        Left $ "TokenEventType length (" ++ show (BSS.length sbs) ++ ") out of bounds."
    | Left decodeErr <- T.decodeUtf8' (BSS.fromShort sbs) =
        Left $ "TokenEventType is not valid UTF-8: " ++ show decodeErr
    | otherwise = Right $ TokenEventType sbs

instance S.Serialize TokenEventType where
    put (TokenEventType eventTypeString) = do
        S.putWord8 $ fromIntegral $ BSS.length eventTypeString
        S.putShortByteString eventTypeString
    get = do
        len <- S.getWord8
        sbs <- S.getShortByteString (fromIntegral len)
        return $ TokenEventType sbs

-- | The token events details produced by a token module.
-- Represented as some arbitrary CBOR encoding.
newtype TokenEventDetails = TokenEventDetails {tokenEventDetailsBytes :: BSS.ShortByteString}
    deriving (Eq)
    deriving (AE.ToJSON, AE.FromJSON, Show) via BSH.ShortByteStringHex

instance S.Serialize TokenEventDetails where
    get = do
        len <- S.getWord32be
        TokenEventDetails <$> S.getShortByteString (fromIntegral len)
    put (TokenEventDetails parameter) = do
        S.putWord32be (fromIntegral (BSS.length parameter))
        S.putShortByteString parameter
