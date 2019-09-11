{-# LANGUAGE ForeignFunctionInterface #-}
module Concordium.Crypto.BlsSignature
  (BlsPublicKey, BlsSecretKey, BlsSignature,
  generateBlsSecretKey, deriveBlsPublicKey) -- sign, verify, aggregate, verifyAggregate
  where

import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.Marshal.Array
import Foreign.C.Types
import Data.Serialize
import Data.List as List
import Data.Word
import Data.ByteString
import Data.ByteString.Unsafe as BS
import System.IO.Unsafe

newtype BlsPublicKey = BlsPublicKey (ForeignPtr BlsPublicKey)
newtype BlsSecretKey = BlsSecretKey (ForeignPtr BlsSecretKey)
newtype BlsSignature = BlsSignature (ForeignPtr BlsSignature)

foreign import ccall unsafe "&bls_free_sk" freeBlsSecretKey :: FunPtr (Ptr BlsSecretKey -> IO ())
foreign import ccall unsafe "bls_generate_secretkey" generateBlsSecretKeyPtr :: IO (Ptr BlsSecretKey)
foreign import ccall unsafe "bls_secret_to_bytes" toBytesBlsSecretKey :: Ptr BlsSecretKey -> IO (Ptr Word8)
foreign import ccall unsafe "bls_sk_from_bytes" fromBytesBlsSecretKey :: Ptr Word8 -> IO (Ptr BlsSecretKey)

foreign import ccall unsafe "&bls_free_pk" freeBlsPublicKey :: FunPtr (Ptr BlsPublicKey -> IO ())
foreign import ccall unsafe "bls_derive_publickey" deriveBlsPublicKeyPtr :: Ptr BlsSecretKey -> IO (Ptr BlsPublicKey)
foreign import ccall unsafe "bls_pk_to_bytes" toBytesBlsPublicKey :: Ptr BlsPublicKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "bls_pk_from_bytes" fromBytesBlsPublicKey :: Ptr Word8 -> IO (Ptr BlsPublicKey)

foreign import ccall unsafe "&bls_free_sig" freeBlsSignature :: FunPtr (Ptr BlsSignature -> IO ())
foreign import ccall unsafe "bls_sig_to_bytes" toBytesBlsSignature :: Ptr BlsSignature -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "bls_sig_from_bytes" fromBytesBlsSignature :: Ptr Word8 -> IO (Ptr BlsSignature)

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

generateBlsSecretKey :: IO BlsSecretKey
generateBlsSecretKey = do
  ptr <- generateBlsSecretKeyPtr
  BlsSecretKey <$> newForeignPtr freeBlsSecretKey ptr

deriveBlsPublicKey :: BlsSecretKey -> BlsPublicKey
deriveBlsPublicKey sk = BlsPublicKey <$> unsafeDupablePerformIO $ do
  pkptr <- withBlsSecretKey sk $ \sk' -> deriveBlsPublicKeyPtr sk'
  newForeignPtr freeBlsPublicKey pkptr

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

verifyAggregate :: ByteString -> [BlsPublicKey] -> BlsSignature -> Bool
verifyAggregate m pks sig = unsafeDupablePerformIO $ do
  BS.unsafeUseAsCStringLen m $ \(m', mlen) ->
    withBlsSignature sig $ \sig' ->
    withKeyArray [] pks $ \arrlen -> \headptr ->
      verifyBlsAggregate (castPtr m') (fromIntegral mlen) headptr (fromIntegral arrlen) sig'
    where
      withKeyArray ps [] f = withArrayLen ps f
      withKeyArray ps (pk:pks) f = withBlsPublicKey pk $ \pk' -> withKeyArray (pk':ps) pks f

--
