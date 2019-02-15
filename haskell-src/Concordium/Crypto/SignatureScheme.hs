{-# INCLUDE <termios.h> #-}
{-# INCLUDE "termops.h" #-}
{-# LANGUAGE ForeignFunctionInterface #-}

module SignatureScheme where

import System.Random
import Data.ByteString
import Foreign.C
import Forieng.Ptr (Ptr,nullPtr)

hashUpdates :: forall a ba . (HashAlgorithm a, ByteArrayAccess ba)
            => Context a
            -> [ba]
            -> Context a
hashUpdates c l
    | null ls   = c
    | otherwise = Context $ B.copyAndFreeze c $ \(ctx :: Ptr (Context a)) ->
        mapM_ (\b -> B.withByteArray b $ \d -> hashInternalUpdate ctx d (fromIntegral $ B.length b)) ls
  where
    ls = filter (not . B.null) l

--hash:: ByteString -> ByteString allocAndFreeze sizeOfHash (\(hash::ptr) -> withByteArray (\(tohash::ptr) -> hacl_sha2_256 hash tohash len)
hash (PS ptr offset len) = allocAndFreeze 265 (\hash -> Hacl_SHA2_265_hash hash ptr len) 
--Hacl_SHA2_256_hash(uint8_t *hash1, uint8_t *input, uint32_t len)
--
foreign import ccall "Hacl_SHA2_256_hash" :: Ptr Word8 -> Ptr Word8 -> Word32 -> IO () 
data SignKey = SignKey ByteString

data VerifKey = VerifKey ByteString

