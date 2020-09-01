{-# LANGUAGE ForeignFunctionInterface #-}
module Concordium.Crypto.FFIDataTypes
  (PedersenKey, PsSigKey, ElgamalSecond, ElgamalSecondSecret, ElgamalPublicKey, ElgamalCipher,
  generatePedersenKey, generatePsSigKey, generateElgamalPublicKey, generateElgamalPublicKeyFromSeed, generateElgamalSecondSecretFromSeed,
  generateElgamalCipher,withPedersenKey, withPsSigKey, withElgamalSecond, withElgamalPublicKey, withElgamalCipher,
  zeroElgamalCipher, unsafeMakeCipher, generateElgamalSecondFromSeed)
  where

import Concordium.Crypto.ByteStringHelpers
import Concordium.Crypto.FFIHelpers

import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.C.Types
import Data.Word
import Data.ByteString as BS
import Data.Serialize
import System.IO.Unsafe (unsafeDupablePerformIO)
import Control.DeepSeq

import qualified Data.Aeson as AE

newtype PedersenKey = PedersenKey (ForeignPtr PedersenKey)
newtype PsSigKey = PsSigKey (ForeignPtr PsSigKey)
-- | Second component of the elgamal public key (i.e., public key minus the
-- generator).
newtype ElgamalSecond = ElgamalSecond (ForeignPtr ElgamalSecond)
newtype ElgamalSecondSecret = ElgamalSecondSecret (ForeignPtr ElgamalSecondSecret)
newtype ElgamalPublicKey = ElgamalPublicKey (ForeignPtr ElgamalPublicKey)
newtype ElgamalCipher = ElgamalCipher (ForeignPtr ElgamalCipher)

-- |Instances for benchmarking
instance NFData PedersenKey where
    rnf = (`seq` ())
instance NFData PsSigKey where
    rnf = (`seq` ())
instance NFData ElgamalSecond where
    rnf = (`seq` ())
instance NFData ElgamalPublicKey where
    rnf = (`seq` ())
instance NFData ElgamalCipher where
    rnf = (`seq` ())

foreign import ccall unsafe "&pedersen_key_free" freePedersenKey :: FunPtr (Ptr PedersenKey -> IO ())
foreign import ccall unsafe "pedersen_key_to_bytes" toBytesPedersenKey :: Ptr PedersenKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "pedersen_key_from_bytes" fromBytesPedersenKey :: Ptr Word8 -> CSize -> IO (Ptr PedersenKey)
foreign import ccall unsafe "pedersen_key_gen" generatePedersenKeyPtr :: CSize -> IO (Ptr PedersenKey)

foreign import ccall unsafe "&ps_sig_key_free" freePsSigKey :: FunPtr (Ptr PsSigKey -> IO ())
foreign import ccall unsafe "ps_sig_key_to_bytes" toBytesPsSigKey :: Ptr PsSigKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "ps_sig_key_from_bytes" fromBytesPsSigKey :: Ptr Word8 -> CSize -> IO (Ptr PsSigKey)
foreign import ccall unsafe "ps_sig_key_gen" generatePsSigKeyPtr :: CSize -> IO (Ptr PsSigKey)

foreign import ccall unsafe "&elgamal_second_free" freeElgamalSecond :: FunPtr (Ptr ElgamalSecond -> IO ())
foreign import ccall unsafe "elgamal_second_to_bytes" toBytesElgamalSecond :: Ptr ElgamalSecond -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "elgamal_second_from_bytes" fromBytesElgamalSecond :: Ptr Word8 -> CSize -> IO (Ptr ElgamalSecond)

foreign import ccall unsafe "&elgamal_second_secret_free" freeElgamalSecondSecret :: FunPtr (Ptr ElgamalSecondSecret -> IO ())
foreign import ccall unsafe "elgamal_second_secret_to_bytes" toBytesElgamalSecondSecret :: Ptr ElgamalSecondSecret -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "elgamal_second_secret_from_bytes" fromBytesElgamalSecondSecret :: Ptr Word8 -> CSize -> IO (Ptr ElgamalSecondSecret)
foreign import ccall unsafe "elgamal_second_secret_gen_seed" generateElgamalSecondSecretFromSeedPtr :: Word64 -> IO (Ptr ElgamalSecondSecret)

foreign import ccall unsafe "derive_elgamal_second_public" deriveElgamalSecondPublicPtr :: Ptr ElgamalSecondSecret -> IO (Ptr ElgamalSecond)

foreign import ccall unsafe "&elgamal_pub_key_free" freeElgamalPublicKey :: FunPtr (Ptr ElgamalPublicKey -> IO ())
foreign import ccall unsafe "elgamal_pub_key_to_bytes" toBytesElgamalPublicKey :: Ptr ElgamalPublicKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "elgamal_pub_key_from_bytes" fromBytesElgamalPublicKey :: Ptr Word8 -> CSize -> IO (Ptr ElgamalPublicKey)
foreign import ccall unsafe "elgamal_pub_key_gen" generateElgamalPublicKeyPtr :: IO (Ptr ElgamalPublicKey)
foreign import ccall unsafe "elgamal_pub_key_gen_seed" generateElgamalPublicKeyFromSeedPtr :: Word64 -> IO (Ptr ElgamalPublicKey)

foreign import ccall unsafe "&elgamal_cipher_free" freeElgamalCipher :: FunPtr (Ptr ElgamalCipher -> IO ())
foreign import ccall unsafe "elgamal_cipher_to_bytes" toBytesElgamalCipher :: Ptr ElgamalCipher -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "elgamal_cipher_from_bytes" fromBytesElgamalCipher :: Ptr Word8 -> CSize -> IO (Ptr ElgamalCipher)
foreign import ccall unsafe "elgamal_cipher_gen" generateElgamalCipherPtr :: IO (Ptr ElgamalCipher)
foreign import ccall unsafe "elgamal_cipher_zero" zeroElgamalCipherPtr :: IO (Ptr ElgamalCipher)

withPedersenKey :: PedersenKey -> (Ptr PedersenKey -> IO b) -> IO b
withPedersenKey (PedersenKey fp) = withForeignPtr fp

withPsSigKey :: PsSigKey -> (Ptr PsSigKey -> IO b) -> IO b
withPsSigKey (PsSigKey fp) = withForeignPtr fp

withElgamalSecond :: ElgamalSecond -> (Ptr ElgamalSecond -> IO b) -> IO b
withElgamalSecond (ElgamalSecond fp) = withForeignPtr fp

withElgamalSecondSecret :: ElgamalSecondSecret -> (Ptr ElgamalSecondSecret -> IO b) -> IO b
withElgamalSecondSecret (ElgamalSecondSecret fp) = withForeignPtr fp

withElgamalCipher :: ElgamalCipher -> (Ptr ElgamalCipher -> IO b) -> IO b
withElgamalCipher (ElgamalCipher fp) = withForeignPtr fp

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

instance AE.ToJSON PedersenKey where
  toJSON v = AE.String (serializeBase16WithLength4 v)

instance AE.FromJSON PedersenKey where
  parseJSON = AE.withText "PedersenKey in base16" deserializeBase16WithLength4

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

instance AE.ToJSON PsSigKey where
  toJSON v = AE.String (serializeBase16WithLength4 v)

instance AE.FromJSON PsSigKey where
  parseJSON = AE.withText "PsSigKey in base16" deserializeBase16WithLength4

generatePsSigKey :: Int -> IO PsSigKey
generatePsSigKey n = do
  ptr <- generatePsSigKeyPtr (fromIntegral n)
  PsSigKey <$> newForeignPtr freePsSigKey ptr


elgamalGroupLen :: Int
elgamalGroupLen = 48

instance Serialize ElgamalSecond where
  get = do
    bs <- getByteString elgamalGroupLen
    case fromBytesHelper freeElgamalSecond fromBytesElgamalSecond bs of
      Nothing -> fail "Cannot decode second component of the elgamal public key."
      Just x -> return $ ElgamalSecond  x

  put (ElgamalSecond e) =
    let bs = toBytesHelper toBytesElgamalSecond $ e
    in putByteString bs

instance Show ElgamalSecond where
  show = byteStringToHex . encode

-- |This instance should only be used for testing
instance Eq ElgamalSecond where
  key == key' = encode key == encode key'

instance AE.ToJSON ElgamalSecond where
  toJSON v = AE.String (serializeBase16 v)

instance AE.FromJSON ElgamalSecond where
  parseJSON = AE.withText "Elgamal generator in base16" deserializeBase16

instance Serialize ElgamalPublicKey where
  get = do
    bs <- getByteString (2 * elgamalGroupLen)
    case fromBytesHelper freeElgamalPublicKey fromBytesElgamalPublicKey bs of
      Nothing -> fail "Cannot decode cipher."
      Just x -> return $ ElgamalPublicKey x

  put (ElgamalPublicKey e) =
    let bs = toBytesHelper toBytesElgamalPublicKey e
    in putByteString bs

instance Show ElgamalPublicKey where
  show = byteStringToHex . encode

-- |This instance should only be used for testing
instance Eq ElgamalPublicKey where
  key == key' = encode key == encode key'

instance AE.ToJSON ElgamalPublicKey where
  toJSON v = AE.String (serializeBase16 v)

instance AE.FromJSON ElgamalPublicKey where
  parseJSON = AE.withText "Elgamal public key in base16" deserializeBase16

generateElgamalPublicKey :: IO ElgamalPublicKey
generateElgamalPublicKey = do
  ptr <- generateElgamalPublicKeyPtr
  ElgamalPublicKey <$> newForeignPtr freeElgamalPublicKey ptr

{-# WARNING generateElgamalPublicKeyFromSeed "Not cryptographically secure, do not use in production." #-}
generateElgamalPublicKeyFromSeed :: Word64 -> ElgamalPublicKey
generateElgamalPublicKeyFromSeed seed = unsafeDupablePerformIO $ do
  ptr <- generateElgamalPublicKeyFromSeedPtr seed
  ElgamalPublicKey <$> newForeignPtr freeElgamalPublicKey ptr

{-# WARNING generateElgamalSecondFromSeed "Not cryptographically secure, do not use in production." #-}
generateElgamalSecondFromSeed :: Word64 -> ElgamalSecond
generateElgamalSecondFromSeed = deriveElgamalSecondPublic . generateElgamalSecondSecretFromSeed 

instance Serialize ElgamalSecondSecret where
  get = do
    bs <- getByteString 32 -- 32 is the scalar size
    case fromBytesHelper freeElgamalSecondSecret fromBytesElgamalSecondSecret bs of
      Nothing -> fail "Cannot decode second component of the elgamal public key."
      Just x -> return $ ElgamalSecondSecret  x

  put (ElgamalSecondSecret e) =
    let bs = toBytesHelper toBytesElgamalSecondSecret $ e
    in putByteString bs

instance Show ElgamalSecondSecret where
  show = byteStringToHex . encode

-- |This instance should only be used for testing
instance Eq ElgamalSecondSecret where
  key == key' = encode key == encode key'

instance AE.ToJSON ElgamalSecondSecret where
  toJSON v = AE.String (serializeBase16 v)

instance AE.FromJSON ElgamalSecondSecret where
  parseJSON = AE.withText "Elgamal generator in base16" deserializeBase16

{-# WARNING deriveElgamalSecondPublic "Only intended for testing." #-}
deriveElgamalSecondPublic :: ElgamalSecondSecret -> ElgamalSecond
deriveElgamalSecondPublic s = unsafeDupablePerformIO $ withElgamalSecondSecret s $ \sPtr -> do
  ptr <- deriveElgamalSecondPublicPtr sPtr
  ElgamalSecond <$> newForeignPtr freeElgamalSecond ptr

{-# WARNING generateElgamalSecondSecretFromSeed "Not cryptographically secure, do not use in production." #-}
generateElgamalSecondSecretFromSeed :: Word64 -> ElgamalSecondSecret
generateElgamalSecondSecretFromSeed seed = unsafeDupablePerformIO $ do
  ptr <- generateElgamalSecondSecretFromSeedPtr seed
  ElgamalSecondSecret <$> newForeignPtr freeElgamalSecondSecret ptr


instance Serialize ElgamalCipher where
  get = do
    bs <- getByteString (2 * elgamalGroupLen)
    case fromBytesHelper freeElgamalCipher fromBytesElgamalCipher bs of
      Nothing -> fail "Cannot decode cipher."
      Just x -> return $ ElgamalCipher x

  put (ElgamalCipher e) =
    let bs = toBytesHelper toBytesElgamalCipher e
    in putByteString bs

instance Show ElgamalCipher where
  show = byteStringToHex . encode

-- |This instance should only be used for testing
instance Eq ElgamalCipher where
  key == key' = encode key == encode key'

instance AE.ToJSON ElgamalCipher where
  toJSON v = AE.String (serializeBase16 v)

instance AE.FromJSON ElgamalCipher where
  parseJSON = AE.withText "Elgamal cipher in base16" deserializeBase16

generateElgamalCipher :: IO ElgamalCipher
generateElgamalCipher = do
  ptr <- generateElgamalCipherPtr
  unsafeMakeCipher ptr

-- |Encryption of 0 in the exponent, with randomness 0.
zeroElgamalCipher :: ElgamalCipher
zeroElgamalCipher = unsafeDupablePerformIO $ do
  ptr <- zeroElgamalCipherPtr
  unsafeMakeCipher ptr

-- |Construct an Elgamal cipher from a pointer to it.
-- This is unsafe in two different ways
--
-- - if the pointer is Null or does not point to an `ElgamalCipher` structure the behaviour is undefined.
-- - if this function is called twice on the same value it will lead to a double free.
unsafeMakeCipher :: Ptr ElgamalCipher -> IO ElgamalCipher
unsafeMakeCipher ptr = ElgamalCipher <$> newForeignPtr freeElgamalCipher ptr
