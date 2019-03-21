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
import           Data.FixedByteString  (FixedByteString)
import           Foreign.Storable           (peek)

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
    hash (Hash b) = unsafeDupablePerformIO $ FBS.withPtr b $ \p -> peek (castPtr p)

hash :: ByteString -> Hash
hash b = Hash $ unsafeDupablePerformIO $
                   do maybe_ctx <- createSha256Ctx
                      case maybe_ctx of
                        Nothing -> error "Failed to initialize hash"
                        Just ctx_ptr -> withForeignPtr ctx_ptr  (\ctx -> hash_update b ctx) >>
                                           withForeignPtr ctx_ptr  (\ctx -> hash_final ctx)

hash_update :: ByteString -> Ptr SHA256Ctx ->  IO ()
hash_update b ptr = withByteStringPtr b $ \message -> rs_sha256_update ptr message (fromIntegral $ B.length b)

hash_final :: Ptr SHA256Ctx -> IO (FixedByteString DigestSize)
hash_final ptr = FBS.create  $ \hash -> rs_sha256_final hash ptr


hashLazy :: L.ByteString -> Hash
hashLazy b = Hash $ unsafeDupablePerformIO $
                   do maybe_ctx <- createSha256Ctx
                      case maybe_ctx of
                        Nothing -> error "Failed to initialize hash"
                        Just ctx -> mapM_ (f ctx)  (L.toChunks b) >> 
                                    withForeignPtr ctx ( \ctx' -> hash_final ctx')
           where
             f ptr chunk = withForeignPtr ptr $ \ptr' -> hash_update chunk ptr'

    
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



