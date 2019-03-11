{-# LANGUAGE ForeignFunctionInterface , GeneralizedNewtypeDeriving, OverloadedStrings #-}

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
import           Data.Bits
import qualified Data.FixedByteString       as FBS

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

data DigestSize

instance FBS.FixedLength DigestSize where
    fixedLength _ = digestSize

-- |A SHA256 hash.  32 bytes.
newtype Hash = Hash (FBS.FixedByteString DigestSize) deriving (Eq, Ord, Bits, Bounded, Enum)

instance Serialize Hash where
    put (Hash h) = putByteString $ FBS.toByteString h
    get = Hash . FBS.fromByteString <$> getByteString digestSize 

instance Show Hash where
    show (Hash h) = LC.unpack (toLazyByteString $ byteStringHex $ FBS.toByteString h)

instance Hashable Hash where
    hashWithSalt s (Hash b) = hashWithSalt s (FBS.toByteString b)
    hash (Hash b) = let bs = FBS.toByteString b in case decode bs of
        Left _ -> hashWithSalt 0 bs
        Right v -> v


hash :: ByteString -> Hash
hash b = Hash $ FBS.unsafeCreate $ \h -> withByteStringPtr b $ \input -> c_hash h input len 
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
hashLazy b =  Hash $ FBS.unsafeCreate $ \hsh -> 
               do state <- callocBytes (ctxSize * 4)   
                  _ <- c_hash_init state 
                  x <- foldM (f state) B.empty (L.toChunks b)  
                  _ <- hash_update_last state x  
                  c_hash_finish state hsh 
                  free state
       where 
         f ptr leftover chunk = hash_update ptr (leftover `B.append` chunk)
hashTest ::FilePath ->  IO ()
hashTest path = do b <- L.readFile path
                   let (Hash b') = hashLazy b
                   putStrLn(byteStringToHex $ FBS.toByteString b')

-- |Convert a 'Hash' into a 'Double' value in the range [0,1].
-- This implementation takes the first 64-bit word (big-endian) and uses it
-- as the significand, with an exponent of -64.  Since the precision of a
-- 'Double' is only 53 bits, there is inevitably some loss.  This also means
-- that the outcome 1 is not possible.
hashToDouble :: Hash -> Double
hashToDouble (Hash h) = case runGet getWord64be (FBS.toByteString h) of
    Left e -> error e
    Right w -> encodeFloat (toInteger w) (-64)

-- |Convert a 'Hash' to an 'Int'.
hashToInt :: Hash -> Int
hashToInt (Hash h) = case runGet getInt64be (FBS.toByteString h) of
    Left e -> error e
    Right i -> fromIntegral i



