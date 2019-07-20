{-# LANGUAGE ForeignFunctionInterface , GeneralizedNewtypeDeriving, OverloadedStrings #-}

module Concordium.Crypto.SHA224 where
import           Concordium.Crypto.ByteStringHelpers
import           Data.ByteString            (ByteString)
import qualified Data.ByteString.Unsafe as B
import qualified Data.ByteString.Lazy       as L
import qualified Data.ByteString.Lazy.Char8 as LC
import           Data.ByteString.Builder
import           Foreign.Ptr
import           Foreign.ForeignPtr
import           Data.Word
import           System.IO.Unsafe
import           Control.Monad
import           Data.Serialize
import           Data.Hashable               
import           Data.Bits
import qualified Data.FixedByteString       as FBS
import           Data.FixedByteString       (FixedByteString)
import           Foreign.Storable           (peek)
import           Text.Read
import           Data.Char

data SHA224Ctx

foreign import ccall unsafe "sha224_new"
   rs_sha224_init :: IO (Ptr SHA224Ctx)

foreign import ccall unsafe "&sha224_free"
   rs_sha224_free :: FunPtr (Ptr SHA224Ctx -> IO ())

foreign import ccall unsafe "sha224_input"
   rs_sha224_update :: Ptr SHA224Ctx -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "sha224_result"
   rs_sha224_final :: Ptr Word8 -> Ptr SHA224Ctx -> IO ()


createSha224Ctx :: IO (Maybe (ForeignPtr SHA224Ctx))
createSha224Ctx = do
  ptr <- rs_sha224_init
  if ptr /= nullPtr
    then do
      foreignPtr <- newForeignPtr_ ptr
      return $ Just foreignPtr
    else
      return Nothing

digestSize :: Int
digestSize = 28

data DigestSize

instance FBS.FixedLength DigestSize where
    fixedLength _ = digestSize

-- |A SHA224 hash.  28 bytes.
newtype Hash = Hash (FBS.FixedByteString DigestSize) deriving (Eq, Ord, Bits, Bounded, Enum)

instance Serialize Hash where
    put (Hash h) = putShortByteString $ FBS.toShortByteString h
    get = Hash . FBS.fromShortByteString <$> getShortByteString digestSize 

instance Show Hash where
    show (Hash h) = LC.unpack (toLazyByteString $ byteStringHex $ FBS.toByteString h)

instance Read Hash where
    readPrec = Hash . FBS.pack <$> mapM (const readHexByte) [1..digestSize]
        where
            readHexByte = do
                ms <- nibble =<< Text.Read.get
                ls <- nibble =<< Text.Read.get
                return (shiftL ms 4 .|. ls)
            nibble c
                | '0' <= c && c <= '9' = return (fromIntegral $ ord c - ord '0')
                | 'a' <= c && c <= 'f' = return (fromIntegral $ ord c - ord 'a' + 10)
                | 'A' <= c && c <= 'F' = return (fromIntegral $ ord c - ord 'A' + 10)
                | otherwise = mzero
    readListPrec = readListPrecDefault

instance Hashable Hash where
    hashWithSalt s (Hash b) = hashWithSalt s (FBS.toByteString b)
    hash (Hash b) = unsafeDupablePerformIO $ FBS.withPtrReadOnly b $ \p -> peek (castPtr p)

hash :: ByteString -> Hash
hash b = Hash $ unsafeDupablePerformIO $
                   do maybe_ctx <- createSha224Ctx
                      case maybe_ctx of
                        Nothing -> error "Failed to initialize hash"
                        Just ctx_ptr -> withForeignPtr ctx_ptr  (\ctx -> hash_update b ctx) >>
                                           withForeignPtr ctx_ptr  (\ctx -> hash_final ctx)

hash_update :: ByteString -> Ptr SHA224Ctx ->  IO ()
hash_update b ptr = B.unsafeUseAsCStringLen b $ \(message, mlen) -> rs_sha224_update ptr (castPtr message) (fromIntegral mlen)

hash_final :: Ptr SHA224Ctx -> IO (FixedByteString DigestSize)
hash_final ptr = FBS.create  $ \hsh -> rs_sha224_final hsh ptr


hashLazy :: L.ByteString -> Hash
hashLazy b = Hash $ unsafeDupablePerformIO $
                   do maybe_ctx <- createSha224Ctx
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



