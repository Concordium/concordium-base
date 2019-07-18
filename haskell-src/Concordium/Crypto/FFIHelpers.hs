{-# LANGUAGE ForeignFunctionInterface #-}
module Concordium.Crypto.FFIHelpers where

import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.C.Types
import Foreign.Storable
import Foreign.Marshal.Alloc
import Data.Word
import Data.ByteString
import Data.ByteString.Unsafe

import System.IO.Unsafe

-- |Utility function shared by all instantations. Free an array of pointers of
-- given length. If the lenght does not correspond to the number of bytes
-- pointed to by the pointer the behaviour is undefined.
foreign import ccall unsafe "free_array_len"
   rs_free_array_len :: Ptr Word8 -> CSize -> IO ()

toBytesHelper ::  (Ptr a -> Ptr CSize -> IO (Ptr Word8)) -> ForeignPtr a -> ByteString
toBytesHelper f m = unsafeDupablePerformIO $ do
  withForeignPtr m $
      \m_ptr ->
        alloca $ \len_ptr -> do
        bytes_ptr <- f m_ptr len_ptr
        len <- peek len_ptr
        unsafePackCStringFinalizer bytes_ptr (fromIntegral len) (rs_free_array_len bytes_ptr len)

fromBytesHelper :: FinalizerPtr a -> (Ptr Word8 -> CSize -> IO (Ptr a)) -> ByteString -> Maybe (ForeignPtr a)
fromBytesHelper finalizer f bs = unsafeDupablePerformIO $ do
  ptr <- unsafeUseAsCStringLen bs $ \(ptr, len) -> f (castPtr ptr :: Ptr Word8) (fromIntegral len :: CSize)
  if ptr == nullPtr then
    return Nothing
  else Just <$> newForeignPtr finalizer ptr
