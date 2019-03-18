{-# LANGUAGE ForeignFunctionInterface , GeneralizedNewtypeDeriving #-}

module Concordium.Crypto.SHA256 where
import           Concordium.Crypto.ByteStringHelpers
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as B
import qualified Data.ByteString.Lazy       as L
import           Data.ByteString.Internal   (create, toForeignPtr)
import qualified Data.ByteString.Lazy.Char8 as LC
import           Data.ByteString.Builder
import           Foreign.Ptr
import           Foreign.ForeignPtr
import           Data.Word
import           System.IO.Unsafe
import           Control.Monad
import           Foreign.Marshal.Array
import           Foreign.Marshal.Alloc
import           Data.Serialize
import           Data.Hashable 

data SHA256Ctx

foreign import ccall unsafe "sha256_new"
   rs_sha256_init :: IO (Ptr SHA256Ctx)

foreign import ccall unsafe "&sha256_free"
   rs_sha256_free :: FunPtr (Ptr SHA256Ctx -> IO ())

foreign import ccall unsafe "sha256_input"
   rs_sha256_update :: Ptr SHA256Ctx -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "sha256_result"
   rs_sha256_final :: Ptr Word8 -> Ptr SHA256Ctx -> IO ()


createSha256Ctx :: IO (Maybe (ForeignPtr SHA256Ctx))
createSha256Ctx = do
  ptr <- rs_sha256_init
  if ptr /= nullPtr
    then do
      foreignPtr <- newForeignPtr_  ptr
      return $ Just foreignPtr
    else
      return Nothing

digestSize :: Int
digestSize = 32


-- |A SHA256 hash.  32 bytes.
newtype Hash = Hash B.ByteString deriving (Eq, Ord)

instance Serialize Hash where
    put (Hash h) = putByteString h
    get = Hash <$> getByteString digestSize 

instance Show Hash where
    show (Hash h) = LC.unpack (toLazyByteString $ byteStringHex h)


instance Hashable Hash where
    hashWithSalt s (Hash b) = hashWithSalt s b
    hash (Hash b) = case decode b of
        Left _ -> hashWithSalt 0 b
        Right v -> v


hash :: ByteString -> Hash
hash b = Hash $ unsafeDupablePerformIO $ 
                   do maybe_ctx <- createSha256Ctx
                      case maybe_ctx of
                        Nothing -> error "Failed to initialize hash"
                        Just ctx_ptr -> withForeignPtr ctx_ptr  (\ctx -> hash_update b ctx)  >>
                            withForeignPtr ctx_ptr  (\ctx -> hash_final ctx)


hash_final :: Ptr SHA256Ctx -> IO ByteString
hash_final ptr = create digestSize $ \hash -> rs_sha256_final hash ptr 

hash_update :: ByteString -> Ptr SHA256Ctx ->  IO ()
hash_update b ptr = withByteStringPtr b $ \message -> rs_sha256_update ptr message (fromIntegral $ B.length b) 

{-
hash_update_last :: Ptr Word32 -> ByteString -> IO ()
hash_update_last ptr x =  withByteStringPtr x $ \bsp -> c_hash_update_last ptr bsp (fromIntegral len)
                where len = B.length x
-}


hashLazy :: L.ByteString -> Hash
hashLazy b =  Hash $ unsafeDupablePerformIO $  
               do maybe_ctx <- createSha256Ctx   
                  case maybe_ctx of 
                    Nothing -> error "Failed to initialize hash"
                    Just ctx -> do x <- mapM_ (f ctx)  (L.toChunks b)  
                                   withForeignPtr ctx $ \ctx' -> hash_final ctx' 
       where 
         f ptr chunk = withForeignPtr ptr $ \ptr' -> hash_update chunk ptr'

hashTest ::FilePath ->  IO ()
hashTest path = do b <- L.readFile path
                   let (Hash b') = hashLazy b
                   putStrLn(byteStringToHex b')
