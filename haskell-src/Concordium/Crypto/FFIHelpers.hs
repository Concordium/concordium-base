module Concordium.Crypto.FFIHelpers where

import Data.ByteString
import Data.ByteString.Unsafe
import Data.Int
import Data.Word
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc
import Foreign.Ptr
import Foreign.Storable

import System.IO.Unsafe

-- |Utility function shared by all instantations. Free an array that was
-- allocated on the heap, of the given size.
foreign import ccall unsafe "free_array_len"
    rs_free_array_len :: Ptr Word8 -> Word64 -> IO ()

toBytesHelper :: (Ptr a -> Ptr CSize -> IO (Ptr Word8)) -> ForeignPtr a -> ByteString
toBytesHelper f m = unsafePerformIO $
    withForeignPtr m $
        \m_ptr ->
            alloca $ \len_ptr -> do
                bytes_ptr <- f m_ptr len_ptr
                len <- peek len_ptr
                unsafePackCStringFinalizer bytes_ptr (fromIntegral len) (rs_free_array_len bytes_ptr (fromIntegral len))

-- |NB: The passed function must handle the case of CSize == 0 gracefully without dereferencing the pointer.
-- since the pointer can be a null-pointer or otherwise a dangling pointer.
fromBytesHelper :: FinalizerPtr a -> (Ptr Word8 -> CSize -> IO (Ptr a)) -> ByteString -> Maybe (ForeignPtr a)
fromBytesHelper finalizer f bs = unsafePerformIO $ do
    ptr <- unsafeUseAsCStringLen bs $ \(ptr, len) -> f (castPtr ptr :: Ptr Word8) (fromIntegral len :: CSize)
    if ptr == nullPtr
        then return Nothing
        else Just <$> newForeignPtr finalizer ptr

toJSONHelper :: (Ptr a -> Ptr CSize -> IO (Ptr Word8)) -> ForeignPtr a -> ByteString
toJSONHelper = toBytesHelper

-- |NB: The passed function mussed handle the case of CSize == 0 gracefully without dereferencing the pointer.
-- since the pointer can be a null-pointer or otherwise a dangling pointer.
-- The passed in bytearray should be a utf8 encoding of a text string.
fromJSONHelper :: FinalizerPtr a -> (Ptr Word8 -> CSize -> IO (Ptr a)) -> ByteString -> Maybe (ForeignPtr a)
fromJSONHelper finalizer f bs = unsafePerformIO $ do
    ptr <- unsafeUseAsCStringLen bs $ \(ptr, len) -> f (castPtr ptr :: Ptr Word8) (fromIntegral len :: CSize)
    if ptr == nullPtr
        then return Nothing
        else Just <$> newForeignPtr finalizer ptr

eqHelper :: ForeignPtr a -> ForeignPtr a -> (Ptr a -> Ptr a -> IO Word8) -> Bool
eqHelper fp1 fp2 f = unsafeDupablePerformIO $ do
    withForeignPtr fp1 $ \p1 ->
        withForeignPtr fp2 $ \p2 -> do
            r <- f p1 p2
            return (r /= 0)

-- |The given function should return
--
--  * 0 if the arguments are to be considered equal
--  * 1 if the first argument is to be considered greater than the second
--  * -1 if the first argument is to be considered less than the second
cmpHelper :: ForeignPtr a -> ForeignPtr a -> (Ptr a -> Ptr a -> IO Int32) -> Ordering
cmpHelper fp1 fp2 f = unsafeDupablePerformIO $ do
    withForeignPtr fp1 $ \p1 ->
        withForeignPtr fp2 $ \p2 -> do
            r <- f p1 p2
            case r of
                0 -> return EQ
                1 -> return GT
                -1 -> return LT
                _ -> error "Should not happen. FFI import breaks precondition."
