{-# LANGUAGE ScopedTypeVariables #-}
module Concordium.Crypto.ByteStringHelpers where

import           Text.Printf
import           Data.ByteString hiding (length)
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
