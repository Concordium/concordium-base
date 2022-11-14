{-# LANGUAGE ScopedTypeVariables #-}

module Concordium.Crypto.ByteStringHelpers where

import Control.Monad
import qualified Data.ByteString.Base16 as BS16
import qualified Data.FixedByteString as FBS
import Data.Serialize
import Data.Text.Encoding as Text
import Data.Word
import Foreign.Ptr

import qualified Data.Aeson as AE
import qualified Data.Aeson.Types as AE
import qualified Data.Text as Text
import Prelude hiding (fail)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as BSS
import qualified Data.ByteString.Short.Internal as BSS
import qualified Data.ByteString.Unsafe as BSU
import Foreign.Marshal

byteStringToHex :: ByteString -> String
byteStringToHex b = BS8.unpack (BS16.encode b)

{-# INLINE withByteStringPtr #-}
withByteStringPtr :: ShortByteString -> (Ptr Word8 -> IO a) -> IO a
withByteStringPtr bs f = BSU.unsafeUseAsCString (BSS.fromShort bs) (f . castPtr)

{-# INLINE withByteStringPtrLen #-}

-- |NB: The passed in function must handle the case of the empty string gracefully.
-- In particular if the short bytestring is empty then the passed in pointer can be arbitrary.
withByteStringPtrLen :: ShortByteString -> (Ptr Word8 -> Int -> IO a) -> IO a
withByteStringPtrLen bs f = BSU.unsafeUseAsCStringLen (BSS.fromShort bs) (\(ptr, len) -> f (castPtr ptr) len)

{-# INLINE withAllocatedShortByteString #-}
withAllocatedShortByteString :: Int -> (Ptr Word8 -> IO a) -> IO (a, ShortByteString)
withAllocatedShortByteString n f =
    allocaBytes n $ \ptr -> do
        r <- f ptr
        sbs <- BSS.createFromPtr ptr n
        return (r, sbs)

fbsHex :: forall a. FBS.FixedLength a => FBS.FixedByteString a -> String
fbsHex = byteStringToHex . FBS.toByteString

fbsPut :: forall a. FBS.FixedLength a => FBS.FixedByteString a -> Put
fbsPut = putShortByteString . FBS.toShortByteString

fbsGet :: forall a. FBS.FixedLength a => Get (FBS.FixedByteString a)
fbsGet = FBS.fromShortByteString <$> getShortByteString (FBS.fixedLength (undefined :: a))

-- |Wrapper used to automatically derive Show instances in base16 for types
-- simply wrapping bytestrings.
newtype ByteStringHex = ByteStringHex ShortByteString
    deriving (Eq)

instance Show ByteStringHex where
    show (ByteStringHex s) = byteStringToHex (BSS.fromShort s)

-- |Wrapper used to automatically derive Show and JSON instances in base16 for
-- types simply wrapping fixed byte stringns.
newtype FBSHex a = FBSHex (FBS.FixedByteString a)

instance FBS.FixedLength a => Show (FBSHex a) where
    show (FBSHex s) = fbsHex s

instance FBS.FixedLength a => Serialize (FBSHex a) where
    put (FBSHex s) = fbsPut s
    get = FBSHex <$> fbsGet

instance FBS.FixedLength a => AE.ToJSON (FBSHex a) where
    toJSON = AE.String . serializeBase16

fbsHexFromText :: forall a. FBS.FixedLength a => Text.Text -> AE.Parser (FBSHex a)
fbsHexFromText t =
    case BS16.decode (Text.encodeUtf8 t) of
        Right bs ->
            if BS.length bs == FBS.fixedLength (undefined :: a)
                then return (FBSHex (FBS.fromByteString bs))
                else AE.typeMismatch "Decoded string not of correct length" (AE.String t)
        Left _ -> AE.typeMismatch "Not a valid Base16 encoding." (AE.String t)

instance FBS.FixedLength a => AE.FromJSON (FBSHex a) where
    parseJSON = AE.withText "FixedByteStringHex" $ fbsHexFromText

instance FBS.FixedLength a => AE.FromJSONKey (FBSHex a) where
    fromJSONKey = AE.FromJSONKeyTextParser fbsHexFromText

instance FBS.FixedLength a => AE.ToJSONKey (FBSHex a) where
    toJSONKey = AE.toJSONKeyText serializeBase16

-- |Type whose only purpose is to enable derivation of serialization instances.
newtype Short65K = Short65K ShortByteString

instance Serialize Short65K where
    put (Short65K bs) =
        putWord16be (fromIntegral (BSS.length bs))
            <> putShortByteString bs
    get = do
        l <- fromIntegral <$> getWord16be
        Short65K <$> getShortByteString l

instance Show Short65K where
    show (Short65K s) = byteStringToHex (BSS.fromShort s)

-- |JSON instances based on base16 encoding.
instance AE.ToJSON Short65K where
    toJSON v = AE.String (Text.pack (show v))

-- |JSON instances based on base16 encoding.
instance AE.FromJSON Short65K where
    parseJSON = AE.withText "Short65K" $ \t ->
        case BS16.decode (Text.encodeUtf8 t) of
            Right bs -> return (Short65K (BSS.toShort bs))
            Left _ -> AE.typeMismatch "Not a valid Base16 encoding." (AE.String t)

-- |JSON instances based on base16 encoding.
instance AE.ToJSON ByteStringHex where
    toJSON v = AE.String (Text.pack (show v))

-- |JSON instances based on base16 encoding.
instance AE.FromJSON ByteStringHex where
    parseJSON = AE.withText "ByteStringHex" $ \t ->
        case BS16.decode (Text.encodeUtf8 t) of
            Right bs -> return (ByteStringHex (BSS.toShort bs))
            Left _ -> AE.typeMismatch "Not a valid Base16 encoding." (AE.String t)

-- |Use the serialize instance of a type to deserialize. In contrast to
-- 'bsDeserializeBase16' this takes Text as input.
deserializeBase16 :: (Serialize a, MonadFail m) => Text.Text -> m a
deserializeBase16 = bsDeserializeBase16 . Text.encodeUtf8

-- |Try to decode a hex string and deserialize it with the provided instance.
bsDeserializeBase16 :: (Serialize a, MonadFail m) => BS.ByteString -> m a
bsDeserializeBase16 input =
    case BS16.decode input of
        Right bs ->
            case decode bs of
                Left er -> fail er
                Right r -> return r
        Left _ -> fail $ "Could not decode as base-16: " ++ show input

-- |Use the serialize instance to convert from base 16 to value, but add
-- explicit length as 4 bytes big endian in front.
deserializeBase16WithLength4 :: (Serialize a, MonadFail m) => Text.Text -> m a
deserializeBase16WithLength4 t =
    case BS16.decode (Text.encodeUtf8 t) of
        Right bs ->
            case decode (runPut (putWord32be (fromIntegral (BS.length bs))) <> bs) of
                Left er -> fail er
                Right r -> return r
        Left _ -> fail $ "Could not decode as base-16: " ++ show t

serializeBase16 :: (Serialize a) => a -> Text.Text
serializeBase16 = Text.decodeUtf8 . BS16.encode . encode

-- |Serialize a type whose serialization puts an explicit length up front.
-- The length is 4 bytes and is cut off by this function.
serializeBase16WithLength4 :: (Serialize a) => a -> Text.Text
serializeBase16WithLength4 = Text.decodeUtf8 . BS16.encode . BS.drop 4 . encode

-- |Newtype wrapper for deriving JSON and Show instances off of binary serialization.
newtype Base16JSONSerialize a = Base16JSONSerialize a

instance Serialize a => AE.ToJSON (Base16JSONSerialize a) where
    toJSON (Base16JSONSerialize a) = AE.String (serializeBase16 a)

instance Serialize a => AE.FromJSON (Base16JSONSerialize a) where
    parseJSON = fmap Base16JSONSerialize . AE.withText "Base16JSONSerialize" deserializeBase16

instance Serialize a => Show (Base16JSONSerialize a) where
    show (Base16JSONSerialize x) = Text.unpack $ serializeBase16 x
