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

foreign import ccall "Hacl_SHA2_256.h Hacl_SHA2_256_hash"    c_hash        :: Ptr Word8 -> Ptr Word8 -> Word32 -> IO ()
foreign import ccall "Hacl_SHA2_256.h Hacl_SHA2_256_update_multi"  c_hash_update :: Ptr Word32 -> Ptr Word8 -> Word32 -> IO () 
foreign import ccall "Hacl_SHA2_256.h Hacl_SHA2_256_update_last"  c_hash_update_last :: Ptr Word32 -> Ptr Word8 ->  Word32 -> IO () 
foreign import ccall "Hacl_SHA2_256.h Hacl_SHA2_256_init"    c_hash_init   :: Ptr Word32 -> IO () 
foreign import ccall "Hacl_SHA2_256.h Hacl_SHA2_256_finish"    c_hash_finish   :: Ptr Word32 -> Ptr Word8 -> IO () 


digestSize :: Int
digestSize = 32
ctxSize :: Int
ctxSize = 137
blckSize :: Int
blckSize = 64

newtype Hash = Hash B.ByteString deriving (Eq, Ord, Serialize)

instance Show Hash where
    show (Hash h) = LC.unpack (toLazyByteString $ byteStringHex h)


instance Hashable Hash where
    hashWithSalt s (Hash b) = hashWithSalt s b
    hash (Hash b) = case decode b of
        Left _ -> hashWithSalt 0 b
        Right v -> v


hash :: ByteString -> Hash
hash b = Hash $ unsafeDupablePerformIO $ create digestSize $ \h -> withByteStringPtr b $ \input -> c_hash h input len 
     where len = fromIntegral $ B.length b

hash_update :: Ptr Word32 -> ByteString -> IO ByteString
hash_update ptr b = withByteStringPtr trimmed $ \t -> c_hash_update ptr t (fromIntegral $ numBlcks) >> return leftover 
    where  len = B.length b
           numBlcks = len `quot` blckSize
           (trimmed,leftover) = B.splitAt (numBlcks * blckSize ) b 

hash_update_last :: Ptr Word32 -> ByteString -> IO ()
hash_update_last ptr x =  withByteStringPtr x $ \bsp -> c_hash_update_last ptr bsp (fromIntegral len)
                where len = B.length x


hashLazy :: L.ByteString -> Hash
hashLazy b =  Hash $ unsafeDupablePerformIO $ create digestSize $ \hash -> 
               do state <- callocBytes (ctxSize * 4)   
                  _ <- c_hash_init state 
                  x <- foldM (f state) B.empty (L.toChunks b)  
                  _ <- hash_update_last state x  
                  c_hash_finish state hash 
                  free state
       where 
         f ptr leftover chunk = hash_update ptr (leftover `B.append` chunk)
hashTest ::FilePath ->  IO ()
hashTest path = do b <- L.readFile path
                   let (Hash b') = hashLazy b
                   putStrLn(byteStringToHex b')

