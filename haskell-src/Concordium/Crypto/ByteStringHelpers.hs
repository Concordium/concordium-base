module Concordium.Crypto.ByteStringHelpers where

import           Text.Printf
import           Data.ByteString
import qualified Data.FixedByteString as FBS
import           Data.ByteString.Internal
import           Foreign.Ptr
import           Foreign.ForeignPtr
import           Data.Word
import qualified Data.List as L
import           Foreign.Storable
import           System.IO.Unsafe
import           Control.Monad

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
