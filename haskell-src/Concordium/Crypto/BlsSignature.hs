{-# LANGUAGE ForeignFunctionInterface #-}
module Concordium.Crypto.BlsSignature
  (PublicKey, SecretKey, Signature,
  generateSecretKey, generateSecretKeyFromSeed, derivePublicKey, sign, verify, aggregate, verifyAggregate, emptySignature)
  where

import Concordium.Crypto.FFIHelpers
import Concordium.Crypto.ByteStringHelpers

import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.Marshal.Array
import Foreign.C.Types
import Data.Word
import Data.Int
import Data.ByteString
import Data.ByteString.Unsafe as BS
import System.IO.Unsafe
import Data.Serialize
import qualified Data.Aeson as AE


newtype PublicKey = PublicKey (ForeignPtr PublicKey)
newtype SecretKey = SecretKey (ForeignPtr SecretKey)
newtype Signature = Signature (ForeignPtr Signature)

foreign import ccall unsafe "&bls_free_sk" freeSecretKey :: FunPtr (Ptr SecretKey -> IO ())
foreign import ccall unsafe "bls_generate_secretkey" generateSecretKeyPtr :: IO (Ptr SecretKey)
foreign import ccall unsafe "bls_sk_to_bytes" toBytesSecretKey :: Ptr SecretKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "bls_sk_from_bytes" fromBytesSecretKey :: Ptr Word8 -> CSize -> IO (Ptr SecretKey)
foreign import ccall unsafe "bls_sk_eq" equalsSecretKey :: Ptr SecretKey -> Ptr SecretKey -> IO Word8
foreign import ccall unsafe "bls_sk_cmp" cmpSecretKey :: Ptr SecretKey -> Ptr SecretKey -> IO Int32

foreign import ccall unsafe "&bls_free_pk" freePublicKey :: FunPtr (Ptr PublicKey -> IO ())
foreign import ccall unsafe "bls_derive_publickey" derivePublicKeyPtr :: Ptr SecretKey -> IO (Ptr PublicKey)
foreign import ccall unsafe "bls_pk_to_bytes" toBytesPublicKey :: Ptr PublicKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "bls_pk_from_bytes" fromBytesPublicKey :: Ptr Word8 -> CSize -> IO (Ptr PublicKey)
foreign import ccall unsafe "bls_pk_eq" equalsPublicKey :: Ptr PublicKey -> Ptr PublicKey -> IO Word8
foreign import ccall unsafe "bls_pk_cmp" cmpPublicKey :: Ptr PublicKey -> Ptr PublicKey -> IO Int32

foreign import ccall unsafe "&bls_free_sig" freeSignature :: FunPtr (Ptr Signature -> IO ())
foreign import ccall unsafe "bls_sig_to_bytes" toBytesSignature :: Ptr Signature -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "bls_sig_from_bytes" fromBytesSignature :: Ptr Word8 -> CSize -> IO (Ptr Signature)
foreign import ccall unsafe "bls_empty_sig" emptyBlsSig :: IO (Ptr Signature)
foreign import ccall unsafe "bls_sig_eq" equalsSignature :: Ptr Signature -> Ptr Signature -> IO Word8
foreign import ccall unsafe "bls_sig_cmp" cmpSignature :: Ptr Signature -> Ptr Signature -> IO Int32

foreign import ccall unsafe "bls_sign" signBls :: Ptr Word8 -> CSize -> Ptr SecretKey -> IO (Ptr Signature)
foreign import ccall unsafe "bls_verify" verifyBls :: Ptr Word8 -> CSize -> Ptr PublicKey -> Ptr Signature -> IO Bool
foreign import ccall unsafe "bls_aggregate" aggregateBls :: Ptr Signature -> Ptr Signature -> IO (Ptr Signature)
foreign import ccall unsafe "bls_verify_aggregate" verifyBlsAggregate :: Ptr Word8 -> CSize -> Ptr (Ptr PublicKey) -> CSize -> Ptr Signature -> IO Bool

withSecretKey :: SecretKey -> (Ptr SecretKey -> IO b) -> IO b
withSecretKey (SecretKey fp) = withForeignPtr fp

withPublicKey :: PublicKey -> (Ptr PublicKey -> IO b) -> IO b
withPublicKey (PublicKey fp) = withForeignPtr fp

withSignature :: Signature -> (Ptr Signature -> IO b) -> IO b
withSignature (Signature fp) = withForeignPtr fp

secretKeySize :: Int
secretKeySize = 32

publicKeySize :: Int
publicKeySize = 96

signatureSize :: Int
signatureSize = 48


-- SecretKey implementations

instance Serialize SecretKey where
  get = do
    bs <- getByteString secretKeySize
    case fromBytesHelper freeSecretKey fromBytesSecretKey bs of
      Nothing -> fail "Cannot decode SecretKey"
      Just x -> return $ SecretKey x

  put (SecretKey p) =
    let bs = toBytesHelper toBytesSecretKey p
    in putByteString bs

instance Show SecretKey where
  show = byteStringToHex . encode
  --showsPrec p (SecretKey fp) = showsPrec p fp

instance Eq SecretKey where
  SecretKey p1 == SecretKey p2 = eqHelper p1 p2 equalsSecretKey

instance Ord SecretKey where
  compare (SecretKey sk1) (SecretKey sk2) =
    cmpHelper sk1 sk2 cmpSecretKey

instance AE.FromJSON SecretKey where
  parseJSON = AE.withText "Bls.SecretKey" deserializeBase16

instance AE.ToJSON SecretKey where
  toJSON v = AE.String (serializeBase16 v)


-- PublicKey implementations

instance Serialize PublicKey where
  get = do
    bs <- getByteString publicKeySize
    case fromBytesHelper freePublicKey fromBytesPublicKey bs of
      Nothing -> fail "Cannot decode PublicKey"
      Just x -> return $ PublicKey x

  put (PublicKey p) =
    let bs = toBytesHelper toBytesPublicKey p
    in putByteString bs

instance Show PublicKey where
  show = byteStringToHex . encode

instance Eq PublicKey where
  PublicKey p1 == PublicKey p2 = eqHelper p1 p2 equalsPublicKey

instance Ord PublicKey where
  compare (PublicKey pk1) (PublicKey pk2) =
    cmpHelper pk1 pk2 cmpPublicKey

instance AE.FromJSON PublicKey where
  parseJSON = AE.withText "Bls.PublicKey" deserializeBase16

instance AE.ToJSON PublicKey where
  toJSON v = AE.String (serializeBase16 v)


-- Signature implementations

instance Serialize Signature where
  get = do
    bs <- getByteString signatureSize
    case fromBytesHelper freeSignature fromBytesSignature bs of
      Nothing -> fail "Cannot decode Signature"
      Just x -> return $ Signature x

  put (Signature p) =
    let bs = toBytesHelper toBytesSignature p
    in putByteString bs

instance Show Signature where
  show = byteStringToHex . encode

instance Eq Signature where
  Signature p1 == Signature p2 = eqHelper p1 p2 equalsSignature

instance Ord Signature where
  compare (Signature sig1) (Signature sig2) =
    cmpHelper sig1 sig2 cmpSignature

instance AE.FromJSON Signature where
  parseJSON = AE.withText "Bls.Signature" deserializeBase16

instance AE.ToJSON Signature where
  toJSON v = AE.String (serializeBase16 v)


-- Signature scheme implementation

generateSecretKey :: IO SecretKey
generateSecretKey = do
  ptr <- generateSecretKeyPtr
  SecretKey <$> newForeignPtr freeSecretKey ptr

derivePublicKey :: SecretKey -> PublicKey
derivePublicKey sk = PublicKey <$> unsafeDupablePerformIO $ do
  pkptr <- withSecretKey sk $ \sk' -> derivePublicKeyPtr sk'
  newForeignPtr freePublicKey pkptr

emptySignature :: Signature
emptySignature = Signature <$> unsafeDupablePerformIO $ do
  sigptr <- emptyBlsSig
  newForeignPtr freeSignature sigptr

sign :: ByteString -> SecretKey -> Signature
sign m sk = Signature <$> unsafeDupablePerformIO $ do
  sigptr <- BS.unsafeUseAsCStringLen m $ \(m', mlen) ->
    withSecretKey sk $ \sk' ->
    signBls (castPtr m') (fromIntegral mlen) sk'
  newForeignPtr freeSignature sigptr

verify :: ByteString -> PublicKey -> Signature -> Bool
verify m pk sig = unsafeDupablePerformIO $ do
  BS.unsafeUseAsCStringLen m $ \(m', mlen) ->
    withPublicKey pk $ \pk' ->
    withSignature sig $ \sig' ->
    verifyBls (castPtr m') (fromIntegral mlen) pk' sig'

aggregate :: Signature -> Signature -> Signature
aggregate sig1 sig2 = Signature <$> unsafeDupablePerformIO $ do
  sigptr <- withSignature sig1 $ \sig1' ->
    withSignature sig2 $ \sig2' ->
    aggregateBls sig1' sig2'
  newForeignPtr freeSignature sigptr

--- Verify a signature on bytestring under the list of public keys
--- The order of the public key list is irrelevant to the result
verifyAggregate :: ByteString -> [PublicKey] -> Signature -> Bool
verifyAggregate m pks sig = unsafeDupablePerformIO $ do
  BS.unsafeUseAsCStringLen m $ \(m', mlen) ->
    withSignature sig $ \sig' ->
    withKeyArray [] pks $ \arrlen -> \headptr ->
      verifyBlsAggregate (castPtr m') (fromIntegral mlen) headptr (fromIntegral arrlen) sig'
    where
      withKeyArray ps [] f = withArrayLen ps f
      withKeyArray ps (pk:pks_) f = withPublicKey pk $ \pk' -> withKeyArray (pk':ps) pks_ f

-- The following functions are only for testing purposes
-- Provides deterministic key generation from seed.
foreign import ccall unsafe "bls_generate_secretkey_from_seed" generateSecretKeyPtrFromSeed :: CSize -> IO (Ptr SecretKey)

generateSecretKeyFromSeed :: CSize -> SecretKey
generateSecretKeyFromSeed seed = unsafeDupablePerformIO $ do
  ptr <- generateSecretKeyPtrFromSeed seed
  (SecretKey <$> newForeignPtr freeSecretKey ptr)
