{-# LANGUAGE ForeignFunctionInterface #-}
module Concordium.Crypto.FFIDataTypes
  (PedersenKey, PsSigKey, ElgamalGen, ElgamalPublicKey, ElgamalCipher,
  generatePedersenKey, generatePsSigKey, generateElgamalGen, generateElgamalPublicKey, generateElgamalCipher,
  withPedersenKey, withPsSigKey, withElgamalGen, withElgamalPublicKey)
  where

import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.C.Types
import Data.Serialize

import Concordium.Crypto.ByteStringHelpers
import Concordium.Crypto.FFIHelpers

import Data.Word
import Data.ByteString as BS

newtype PedersenKey = PedersenKey (ForeignPtr PedersenKey)
newtype PsSigKey = PsSigKey (ForeignPtr PsSigKey)
newtype ElgamalGen = ElgamalGen (ForeignPtr ElgamalGen)
newtype ElgamalPublicKey = ElgamalPublicKey (ForeignPtr ElgamalPublicKey)
newtype ElgamalCipher = ElgamalCipher (ForeignPtr ElgamalCipher)

foreign import ccall unsafe "&pedersen_key_free" freePedersenKey :: FunPtr (Ptr PedersenKey -> IO ())
foreign import ccall unsafe "pedersen_key_to_bytes" toBytesPedersenKey :: Ptr PedersenKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "pedersen_key_from_bytes" fromBytesPedersenKey :: Ptr Word8 -> CSize -> IO (Ptr PedersenKey)
foreign import ccall unsafe "pedersen_key_gen" generatePedersenKeyPtr :: CSize -> IO (Ptr PedersenKey)

foreign import ccall unsafe "&ps_sig_key_free" freePsSigKey :: FunPtr (Ptr PsSigKey -> IO ())
foreign import ccall unsafe "ps_sig_key_to_bytes" toBytesPsSigKey :: Ptr PsSigKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "ps_sig_key_from_bytes" fromBytesPsSigKey :: Ptr Word8 -> CSize -> IO (Ptr PsSigKey)
foreign import ccall unsafe "ps_sig_key_gen" generatePsSigKeyPtr :: CSize -> IO (Ptr PsSigKey)

foreign import ccall unsafe "&elgamal_gen_free" freeElgamalGen :: FunPtr (Ptr ElgamalGen -> IO ())
foreign import ccall unsafe "elgamal_gen_to_bytes" toBytesElgamalGen :: Ptr ElgamalGen -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "elgamal_gen_from_bytes" fromBytesElgamalGen :: Ptr Word8 -> CSize -> IO (Ptr ElgamalGen)
foreign import ccall unsafe "elgamal_gen_gen" generateElgamalGenPtr :: IO (Ptr ElgamalGen)

foreign import ccall unsafe "&elgamal_pub_key_free" freeElgamalPublicKey :: FunPtr (Ptr ElgamalPublicKey -> IO ())
foreign import ccall unsafe "elgamal_pub_key_to_bytes" toBytesElgamalPublicKey :: Ptr ElgamalPublicKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "elgamal_pub_key_from_bytes" fromBytesElgamalPublicKey :: Ptr Word8 -> CSize -> IO (Ptr ElgamalPublicKey)
foreign import ccall unsafe "elgamal_pub_key_gen" generateElgamalPublicKeyPtr :: IO (Ptr ElgamalPublicKey)

foreign import ccall unsafe "&elgamal_cipher_free" freeElgamalCipher :: FunPtr (Ptr ElgamalCipher -> IO ())
foreign import ccall unsafe "elgamal_cipher_to_bytes" toBytesElgamalCipher :: Ptr ElgamalCipher -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "elgamal_cipher_from_bytes" fromBytesElgamalCipher :: Ptr Word8 -> CSize -> IO (Ptr ElgamalCipher)
foreign import ccall unsafe "elgamal_cipher_gen" generateElgamalCipherPtr :: IO (Ptr ElgamalCipher)

withPedersenKey :: PedersenKey -> (Ptr PedersenKey -> IO b) -> IO b
withPedersenKey (PedersenKey fp) = withForeignPtr fp

withPsSigKey :: PsSigKey -> (Ptr PsSigKey -> IO b) -> IO b
withPsSigKey (PsSigKey fp) = withForeignPtr fp

withElgamalGen :: ElgamalGen -> (Ptr ElgamalGen -> IO b) -> IO b
withElgamalGen (ElgamalGen fp) = withForeignPtr fp

withElgamalPublicKey :: ElgamalPublicKey -> (Ptr ElgamalPublicKey -> IO b) -> IO b
withElgamalPublicKey (ElgamalPublicKey fp) = withForeignPtr fp

-- |NOTE: This instance is different than the rust one. We add explicit length
-- information up front.
instance Serialize PedersenKey where
  get = do
    v <- getWord32be
    bs <- getByteString (fromIntegral v)
    case fromBytesHelper freePedersenKey fromBytesPedersenKey bs of
      Nothing -> fail "Cannot decode cipher."
      Just x -> return $ PedersenKey x

  put (PedersenKey e) = let bs = toBytesHelper toBytesPedersenKey $ e
                        in putByteString (runPut (putWord32be (fromIntegral (BS.length bs))) <> bs)

instance Show PedersenKey where
  show = byteStringToHex . BS.drop 4 . encode

-- |This instance should only be used for testing
instance Eq PedersenKey where
  key == key' = encode key == encode key'

generatePedersenKey :: Int -> IO PedersenKey
generatePedersenKey n = do
  ptr <- generatePedersenKeyPtr (fromIntegral n)
  PedersenKey <$> newForeignPtr freePedersenKey ptr



-- |NOTE: This instance is different than the rust one. We add explicit length
-- information up front.
instance Serialize PsSigKey where
  get = do
    v <- getWord32be
    bs <- getByteString (fromIntegral v)
    case fromBytesHelper freePsSigKey fromBytesPsSigKey bs of
      Nothing -> fail "Cannot decode cipher."
      Just x -> return $ PsSigKey x

  put (PsSigKey e) = let bs = toBytesHelper toBytesPsSigKey $ e
                     in putByteString (runPut (putWord32be (fromIntegral (BS.length bs))) <> bs)

instance Show PsSigKey where
  show = byteStringToHex . BS.drop 4 . encode

-- |This instance should only be used for testing
instance Eq PsSigKey where
  key == key' = encode key == encode key'

generatePsSigKey :: Int -> IO PsSigKey
generatePsSigKey n = do
  ptr <- generatePsSigKeyPtr (fromIntegral n)
  PsSigKey <$> newForeignPtr freePsSigKey ptr


elgamalGroupLen :: Int
elgamalGroupLen = 48

instance Serialize ElgamalGen where
  get = do
    bs <- getByteString elgamalGroupLen
    case fromBytesHelper freeElgamalGen fromBytesElgamalGen bs of
      Nothing -> fail "Cannot decode cipher."
      Just x -> return $ ElgamalGen x

  put (ElgamalGen e) =
    let bs = toBytesHelper toBytesElgamalGen $ e
    in putByteString bs

instance Show ElgamalGen where
  show = byteStringToHex . encode

-- |This instance should only be used for testing
instance Eq ElgamalGen where
  key == key' = encode key == encode key'

generateElgamalGen :: IO ElgamalGen
generateElgamalGen = do
  ptr <- generateElgamalGenPtr
  ElgamalGen <$> newForeignPtr freeElgamalGen ptr

-- |NOTE: This instance is different than the rust one. We add explicit length
-- information up front.
instance Serialize ElgamalPublicKey where
  get = do
    bs <- getByteString elgamalGroupLen
    case fromBytesHelper freeElgamalPublicKey fromBytesElgamalPublicKey bs of
      Nothing -> fail "Cannot decode cipher."
      Just x -> return $ ElgamalPublicKey x

  put (ElgamalPublicKey e) =
    let bs = toBytesHelper toBytesElgamalPublicKey $ e
    in putByteString bs

instance Show ElgamalPublicKey where
  show = byteStringToHex . encode

-- |This instance should only be used for testing
instance Eq ElgamalPublicKey where
  key == key' = encode key == encode key'

generateElgamalPublicKey :: IO ElgamalPublicKey
generateElgamalPublicKey = do
  ptr <- generateElgamalPublicKeyPtr
  ElgamalPublicKey <$> newForeignPtr freeElgamalPublicKey ptr

-- |NOTE: This instance is different than the rust one. We add explicit length
-- information up front.
instance Serialize ElgamalCipher where
  get = do
    bs <- getByteString (2 * elgamalGroupLen)
    case fromBytesHelper freeElgamalCipher fromBytesElgamalCipher bs of
      Nothing -> fail "Cannot decode cipher."
      Just x -> return $ ElgamalCipher x

  put (ElgamalCipher e) =
    let bs = toBytesHelper toBytesElgamalCipher $ e
    in putByteString bs

instance Show ElgamalCipher where
  show = byteStringToHex . encode

-- |This instance should only be used for testing
instance Eq ElgamalCipher where
  key == key' = encode key == encode key'

generateElgamalCipher :: IO ElgamalCipher
generateElgamalCipher = do
  ptr <- generateElgamalCipherPtr
  ElgamalCipher <$> newForeignPtr freeElgamalCipher ptr
