module Concordium.Crypto.Haskell.ByteStringHelpers where

import           Text.Printf
import           Data.ByteString
import           Data.ByteString.Internal
import           Foreign.Ptr
import           Foreign.ForeignPtr
import           Data.Word
import           Data.ByteString.Builder
import           Control.Monad
import qualified Data.List as L

wordToHex :: Word8 -> [Char]
wordToHex x = printf "%.2x" x


byteStringToHex :: ByteString -> String
byteStringToHex b= L.concatMap wordToHex ls
    where
        ls = unpack b

withByteStringPtr :: ByteString -> (Ptr Word8 -> IO a) -> IO a
withByteStringPtr b f =  withForeignPtr fptr $ \ptr -> f (ptr `plusPtr` off)
    where (fptr, off, _) = toForeignPtr b
