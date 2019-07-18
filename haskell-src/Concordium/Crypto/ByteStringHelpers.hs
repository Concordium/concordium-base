{-# LANGUAGE ScopedTypeVariables #-}
module Concordium.Crypto.ByteStringHelpers where

import           Text.Printf
import           Data.ByteString hiding (length)
import qualified Data.ByteString as BS
import           Data.ByteString.Unsafe
import qualified Data.FixedByteString as FBS
import           Data.ByteString.Internal
import           Foreign.Ptr
import           Foreign.ForeignPtr
import           Data.Word
import qualified Data.List as L
import           Foreign.Storable
import           Foreign.Marshal.Utils
import           System.IO.Unsafe
import           Control.Monad
import Data.Serialize
import qualified Data.ByteString.Base16 as BS16
import Data.Text.Encoding as Text

import Control.Monad.Fail(MonadFail)
import qualified Data.Aeson as AE
import qualified Data.Aeson.Types as AE
import qualified Data.Text as Text
import Prelude hiding (fail)

wordToHex :: Word8 -> [Char]
wordToHex x = printf "%.2x" x


byteStringToHex :: ByteString -> String
byteStringToHex b= L.concatMap wordToHex ls
    where
        ls = unpack b

withByteStringPtr :: ByteString -> (Ptr Word8 -> IO a) -> IO a
withByteStringPtr b f =  withForeignPtr fptr $ \ptr -> f (ptr `plusPtr` off)
    where (fptr, off, _) = toForeignPtr b

unsafeEqForeignPtr :: (Storable a, Eq a) => Int -> ForeignPtr a -> ForeignPtr a -> Bool
unsafeEqForeignPtr n f1 f2 = unsafePerformIO $
    withForeignPtr f1 $
      \f1p -> withForeignPtr f2 $
        \f2p -> foldM (\acc k -> if acc then (==) <$> peekElemOff f1p k <*> peekElemOff f2p k else return False) True [0..n-1]

unsafeForeignPtrToList :: Storable a => Int -> ForeignPtr a -> [a]
unsafeForeignPtrToList n f = unsafePerformIO $ withForeignPtr f $ \p -> mapM (peekElemOff p) [0..n-1]

unsafeForeignPtrHex :: Int -> ForeignPtr Word8 -> String
unsafeForeignPtrHex n f = byteStringToHex . pack $ (unsafeForeignPtrToList n f)

fbsHex :: FBS.FixedLength a => FBS.FixedByteString a -> String
fbsHex = byteStringToHex . FBS.toByteString

fbsPut :: FBS.FixedLength a => FBS.FixedByteString a -> Put
fbsPut = putByteString . FBS.toByteString

fbsGet :: forall a . FBS.FixedLength a => Get (FBS.FixedByteString a)
fbsGet = FBS.fromByteString <$> getByteString (FBS.fixedLength (undefined :: a))

putForeignPtrWord8 :: Int -> ForeignPtr Word8 -> Put
putForeignPtrWord8 n fp = putWord32be (fromIntegral n) <> mapM_ putWord8 (unsafeForeignPtrToList n fp)

getForeignPtrWord8 :: Get (Int, ForeignPtr Word8)
getForeignPtrWord8 = do
  n <- fromIntegral <$> getWord32be
  bs <- getByteString n
  let r = unsafeDupablePerformIO $ do
        fp <- mallocForeignPtrBytes n
        withForeignPtr fp $
            \fpp ->
              unsafeUseAsCString bs $
                \bsp -> copyBytes (castPtr fpp) bsp n
        return fp
  return (n, r)

-- |This is a safe method as long as the first argument <= length of the list.
-- Giving the first argument makes the method more efficient in current use cases.
listToForeignPtr :: Int -> [Word8] -> ForeignPtr Word8
listToForeignPtr n wds = unsafeDupablePerformIO $ do
        fp <- mallocForeignPtrBytes n
        withForeignPtr fp $
            \fpp -> zipWithM_ (pokeByteOff fpp) [0..n-1] wds
        return fp

-- |Wrapper used to automatically derive Show instances in base16 for types
-- simply wrapping bytestrings.
newtype ByteStringHex = ByteStringHex ByteString

instance Show ByteStringHex where
  show (ByteStringHex s) = byteStringToHex s

-- |Wrapper used to automatically derive Show instances in base16 for types
-- simply wrapping fixed byte stringns.
newtype FBSHex a = FBSHex (FBS.FixedByteString a)

instance FBS.FixedLength a => Show (FBSHex a) where
  show (FBSHex s) = fbsHex s

instance FBS.FixedLength a => Serialize (FBSHex a) where
  put (FBSHex s) = fbsPut s
  get = FBSHex <$> fbsGet

-- |Type whose only purpose is to enable derivation of serialization instances.
newtype Short65K = Short65K ByteString

instance Serialize Short65K where
  put (Short65K bs) =
    putWord16be (fromIntegral (BS.length bs)) <>
    putByteString bs
  get = do
    l <- fromIntegral <$> getWord16be
    Short65K <$> getByteString l

-- |JSON instances based on base16 encoding.
instance AE.ToJSON ByteStringHex where
  toJSON v = AE.toJSON $ show v

-- |JSON instances based on base16 encoding.
instance AE.FromJSON ByteStringHex where
  parseJSON = AE.withText "ByteStringHex" $ \t ->
    let (bs, rest) = BS16.decode (Text.encodeUtf8 t)
    in if BS.null rest then return (ByteStringHex bs)
       else AE.typeMismatch "Not a valid Base16 encoding." (AE.String t)

-- |Use the serialize instance of a type to deserialize 
deserializeBase16 :: (Serialize a, MonadFail m) => Text.Text -> m a
deserializeBase16 t =
        if BS.null rest then
            case decode bs of
                Left er -> fail er
                Right r -> return r
        else
            fail $ "Could not decode as base-16: " ++ show t
    where
        (bs, rest) = BS16.decode (Text.encodeUtf8 t)

-- |Use the serialize instance to convert from base 16 to value, but add
-- explicit length as 4 bytes big endian in front.
deserializeBase16WithLength4 :: (Serialize a, MonadFail m) => Text.Text -> m a
deserializeBase16WithLength4 t =
        if BS.null rest then
            case decode (runPut (putWord32be (fromIntegral (BS.length bs))) <> bs) of
                Left er -> fail er
                Right r -> return r
        else
            fail $ "Could not decode as base-16: " ++ show t
    where
        (bs, rest) = BS16.decode (Text.encodeUtf8 t)


serializeBase16 :: (Serialize a) => a -> Text.Text
serializeBase16 = Text.decodeUtf8 . BS16.encode . encode

-- |Serialize a type whose serialization puts an explicit length up front.
-- The length is 4 bytes and is cut off by this function.
serializeBase16WithLength4 :: (Serialize a) => a -> Text.Text
serializeBase16WithLength4 = Text.decodeUtf8 . BS16.encode . BS.drop 4 . encode
