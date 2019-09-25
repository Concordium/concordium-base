{-# LANGUAGE ForeignFunctionInterface #-}
module Concordium.Crypto.BlsSignature
  (BlsPublicKey, BlsSecretKey, BlsSignature,
  generateBlsSecretKey, generateBlsSecretKeyFromSeed, deriveBlsPublicKey, sign, verify, aggregate, verifyAggregate, emptySignature)
  where

import Concordium.Crypto.FFIHelpers
import Concordium.Crypto.ByteStringHelpers

import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.Marshal.Array
import Foreign.C.Types
import Data.Word
import Data.ByteString
import Data.ByteString.Unsafe as BS
import System.IO.Unsafe
import Data.Serialize


newtype BlsPublicKey = BlsPublicKey (ForeignPtr BlsPublicKey)
newtype BlsSecretKey = BlsSecretKey (ForeignPtr BlsSecretKey)
newtype BlsSignature = BlsSignature (ForeignPtr BlsSignature)

foreign import ccall unsafe "&bls_free_sk" freeBlsSecretKey :: FunPtr (Ptr BlsSecretKey -> IO ())
foreign import ccall unsafe "bls_generate_secretkey" generateBlsSecretKeyPtr :: IO (Ptr BlsSecretKey)
foreign import ccall unsafe "bls_sk_to_bytes" toBytesBlsSecretKey :: Ptr BlsSecretKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "bls_sk_from_bytes" fromBytesBlsSecretKey :: Ptr Word8 -> CSize -> IO (Ptr BlsSecretKey)
foreign import ccall unsafe "bls_sk_eq" equalsBlsSecretKey :: Ptr BlsSecretKey -> Ptr BlsSecretKey -> IO Word8

foreign import ccall unsafe "&bls_free_pk" freeBlsPublicKey :: FunPtr (Ptr BlsPublicKey -> IO ())
foreign import ccall unsafe "bls_derive_publickey" deriveBlsPublicKeyPtr :: Ptr BlsSecretKey -> IO (Ptr BlsPublicKey)
foreign import ccall unsafe "bls_pk_to_bytes" toBytesBlsPublicKey :: Ptr BlsPublicKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "bls_pk_from_bytes" fromBytesBlsPublicKey :: Ptr Word8 -> CSize -> IO (Ptr BlsPublicKey)
foreign import ccall unsafe "bls_pk_eq" equalsBlsPublicKey :: Ptr BlsPublicKey -> Ptr BlsPublicKey -> IO Word8

foreign import ccall unsafe "&bls_free_sig" freeBlsSignature :: FunPtr (Ptr BlsSignature -> IO ())
foreign import ccall unsafe "bls_sig_to_bytes" toBytesBlsSignature :: Ptr BlsSignature -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "bls_sig_from_bytes" fromBytesBlsSignature :: Ptr Word8 -> CSize -> IO (Ptr BlsSignature)
foreign import ccall unsafe "bls_empty_sig" emptyBlsSig :: IO (Ptr BlsSignature)
foreign import ccall unsafe "bls_sig_eq" equalsBlsSignature :: Ptr BlsSignature -> Ptr BlsSignature -> IO Word8

foreign import ccall unsafe "bls_sign" signBls :: Ptr Word8 -> CSize -> Ptr BlsSecretKey -> IO (Ptr BlsSignature)
foreign import ccall unsafe "bls_verify" verifyBls :: Ptr Word8 -> CSize -> Ptr BlsPublicKey -> Ptr BlsSignature -> IO Bool
foreign import ccall unsafe "bls_aggregate" aggregateBls :: Ptr BlsSignature -> Ptr BlsSignature -> IO (Ptr BlsSignature)
foreign import ccall unsafe "bls_verify_aggregate" verifyBlsAggregate :: Ptr Word8 -> CSize -> Ptr (Ptr BlsPublicKey) -> CSize -> Ptr BlsSignature -> IO Bool

withBlsSecretKey :: BlsSecretKey -> (Ptr BlsSecretKey -> IO b) -> IO b
withBlsSecretKey (BlsSecretKey fp) = withForeignPtr fp

withBlsPublicKey :: BlsPublicKey -> (Ptr BlsPublicKey -> IO b) -> IO b
withBlsPublicKey (BlsPublicKey fp) = withForeignPtr fp

withBlsSignature :: BlsSignature -> (Ptr BlsSignature -> IO b) -> IO b
withBlsSignature (BlsSignature fp) = withForeignPtr fp

secretKeySize :: Int
secretKeySize = 32

publicKeySize :: Int
publicKeySize = 96

signatureSize :: Int
signatureSize = 48

instance Serialize BlsSecretKey where
  get = do
    bs <- getByteString secretKeySize
    case fromBytesHelper freeBlsSecretKey fromBytesBlsSecretKey bs of
      Nothing -> fail "Cannot decode BlsSecretKey"
      Just x -> return $ BlsSecretKey x

  put (BlsSecretKey p) =
    let bs = toBytesHelper toBytesBlsSecretKey p
    in putByteString bs

instance Show BlsSecretKey where
  show = byteStringToHex . encode
  --showsPrec p (BlsSecretKey fp) = showsPrec p fp

instance Eq BlsSecretKey where
  BlsSecretKey p1 == BlsSecretKey p2 = eqHelper p1 p2 equalsBlsSecretKey

instance Serialize BlsPublicKey where
  get = do
    bs <- getByteString publicKeySize
    case fromBytesHelper freeBlsPublicKey fromBytesBlsPublicKey bs of
      Nothing -> fail "Cannot decode BlsPublicKey"
      Just x -> return $ BlsPublicKey x

  put (BlsPublicKey p) =
    let bs = toBytesHelper toBytesBlsPublicKey p
    in putByteString bs

instance Show BlsPublicKey where
  show = byteStringToHex . encode

instance Eq BlsPublicKey where
  BlsPublicKey p1 == BlsPublicKey p2 = eqHelper p1 p2 equalsBlsPublicKey

instance Serialize BlsSignature where
  get = do
    bs <- getByteString signatureSize
    case fromBytesHelper freeBlsSignature fromBytesBlsSignature bs of
      Nothing -> fail "Cannot decode BlsSignature"
      Just x -> return $ BlsSignature x

  put (BlsSignature p) =
    let bs = toBytesHelper toBytesBlsSignature p
    in putByteString bs

instance Show BlsSignature where
  show = byteStringToHex . encode

instance Eq BlsSignature where
  BlsSignature p1 == BlsSignature p2 = eqHelper p1 p2 equalsBlsSignature

-- TODO: implement Ord for all types
-- TODO (maybe) FromJSON, ToJSON for all types

generateBlsSecretKey :: IO BlsSecretKey
generateBlsSecretKey = do
  ptr <- generateBlsSecretKeyPtr
  BlsSecretKey <$> newForeignPtr freeBlsSecretKey ptr

deriveBlsPublicKey :: BlsSecretKey -> BlsPublicKey
deriveBlsPublicKey sk = BlsPublicKey <$> unsafeDupablePerformIO $ do
  pkptr <- withBlsSecretKey sk $ \sk' -> deriveBlsPublicKeyPtr sk'
  newForeignPtr freeBlsPublicKey pkptr

emptySignature :: BlsSignature
emptySignature = BlsSignature <$> unsafeDupablePerformIO $ do
  sigptr <- emptyBlsSig
  newForeignPtr freeBlsSignature sigptr

sign :: ByteString -> BlsSecretKey -> BlsSignature
sign m sk = BlsSignature <$> unsafeDupablePerformIO $ do
  sigptr <- BS.unsafeUseAsCStringLen m $ \(m', mlen) ->
    withBlsSecretKey sk $ \sk' ->
    signBls (castPtr m') (fromIntegral mlen) sk'
  newForeignPtr freeBlsSignature sigptr

verify :: ByteString -> BlsPublicKey -> BlsSignature -> Bool
verify m pk sig = unsafeDupablePerformIO $ do
  BS.unsafeUseAsCStringLen m $ \(m', mlen) ->
    withBlsPublicKey pk $ \pk' ->
    withBlsSignature sig $ \sig' ->
    verifyBls (castPtr m') (fromIntegral mlen) pk' sig'

aggregate :: BlsSignature -> BlsSignature -> BlsSignature
aggregate sig1 sig2 = BlsSignature <$> unsafeDupablePerformIO $ do
  sigptr <- withBlsSignature sig1 $ \sig1' ->
    withBlsSignature sig2 $ \sig2' ->
    aggregateBls sig1' sig2'
  newForeignPtr freeBlsSignature sigptr

--- Verify a signature on bytestring under the list of public keys
--- The order of the public key list is irrelevant to the result
verifyAggregate :: ByteString -> [BlsPublicKey] -> BlsSignature -> Bool
verifyAggregate m pks sig = unsafeDupablePerformIO $ do
  BS.unsafeUseAsCStringLen m $ \(m', mlen) ->
    withBlsSignature sig $ \sig' ->
    withKeyArray [] pks $ \arrlen -> \headptr ->
      verifyBlsAggregate (castPtr m') (fromIntegral mlen) headptr (fromIntegral arrlen) sig'
    where
      withKeyArray ps [] f = withArrayLen ps f
      withKeyArray ps (pk:pks_) f = withBlsPublicKey pk $ \pk' -> withKeyArray (pk':ps) pks_ f

-- The following functions are only for testing purposes
-- Provides deterministic key generation from seed.
foreign import ccall unsafe "bls_generate_secretkey_from_seed" generateBlsSecretKeyPtrFromSeed :: CSize -> IO (Ptr BlsSecretKey)

generateBlsSecretKeyFromSeed :: CSize -> BlsSecretKey
generateBlsSecretKeyFromSeed seed = unsafeDupablePerformIO $ do
  ptr <- generateBlsSecretKeyPtrFromSeed seed
  (BlsSecretKey <$> newForeignPtr freeBlsSecretKey ptr)
