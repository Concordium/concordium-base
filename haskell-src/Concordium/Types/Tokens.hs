{-# LANGUAGE DerivingStrategies #-}

-- | Types associated with protocol-level tokens.
module Concordium.Types.Tokens where

import Control.Monad
import qualified Data.Aeson as AE
import qualified Data.Aeson.Types as AE
import qualified Data.ByteString.Short as BSS
import Data.Scientific
import qualified Data.Serialize as S
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.Word

-- | The unique token identifier for a protocol-level token.
--  This is given as a symbol unique across the whole chain.
--  The byte string must be at most 255 bytes long and be a valid UTF-8 string.
newtype TokenId = TokenId {tokenSymbol :: BSS.ShortByteString}
    deriving newtype (Eq, Ord)

instance Show TokenId where
    show (TokenId sbs) =
        case T.decodeUtf8' (BSS.fromShort sbs) of
            Right txt -> T.unpack txt
            Left err -> "TokenId is not valid UTF-8: " ++ show err

-- | Try to construct a valid 'TokenId' from a 'BSS.ShortByteString'.
--  This can fail if the string is longer than 255 bytes or is not valid UTF-8.
--  In the event of a failure @Left err@ is returned, where @err@ describes the failure.
makeTokenId :: BSS.ShortByteString -> Either String TokenId
makeTokenId sbs
    | BSS.length sbs > 255 =
        Left $ "TokenId length (" ++ show (BSS.length sbs) ++ ") out of bounds."
    | Left decodeErr <- T.decodeUtf8' (BSS.fromShort sbs) =
        Left $ "TokenId is not valid UTF-8: " ++ show decodeErr
    | otherwise = Right $ TokenId sbs

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
    toJSON TokenId{..} = AE.String $ T.decodeUtf8 $ BSS.fromShort tokenSymbol

instance AE.FromJSON TokenId where
    parseJSON (AE.String text) = return $ TokenId $ BSS.toShort $ T.encodeUtf8 text
    parseJSON invalid = AE.prependFailure "parsing TokenId failed" (AE.typeMismatch "String" invalid)

-- | The token amount representation.
--  The amount is computed as `amount = digits * 10^(-nrDecimals)`.
data TokenAmount = TokenAmount
    { digits :: !Word64,
      nrDecimals :: !Word8
    }
    deriving (Eq, Show)

instance AE.ToJSON TokenAmount where
    toJSON TokenAmount{..} = AE.Number (scientific (fromIntegral digits) (-fromIntegral nrDecimals))

instance AE.FromJSON TokenAmount where
    parseJSON (AE.Number amt)
        | coefficient amt < 0 = fail "Token amount must be positive."
        | base10Exponent amt > 0 = do
            let digitsInteger = coefficient amt * 10 ^ base10Exponent amt
            when (digitsInteger > toInteger (maxBound :: Word64)) $
                fail "Token amount out of bounds."
            return TokenAmount{digits = fromInteger digitsInteger, nrDecimals = 0}
        | base10Exponent amt < -255 =
            fail "Token amount precision is out of range."
        | otherwise =
            return
                TokenAmount
                    { digits = fromInteger (coefficient amt),
                      nrDecimals = fromIntegral (-base10Exponent amt)
                    }
    parseJSON _ = fail "Token amount should be a number."
