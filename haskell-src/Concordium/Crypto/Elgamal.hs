{-# LANGUAGE DerivingVia #-}
module Concordium.Crypto.Elgamal where

import           Concordium.Crypto.ByteStringHelpers
import           Data.ByteString            (ByteString)
import           Data.ByteString.Unsafe
import           Data.ByteString.Internal
import           Foreign.Ptr
import           Foreign.ForeignPtr
import           Data.Word
import Data.Int
import System.IO.Unsafe
import Foreign.Storable
import Foreign.Marshal.Alloc
import Foreign.C.Types
import Data.Serialize

u64CipherSize :: Int
u64CipherSize = 6144

data ElgamalSecretKeyStruct
data ElgamalPublicKeyStruct
data ElgamalMessageStruct
data ElgamalCipherStruct

newtype ElgamalSecretKey = ESK (ForeignPtr ElgamalSecretKeyStruct)
newtype ElgamalPublicKey = EPK (ForeignPtr ElgamalPublicKeyStruct)
newtype ElgamalCipher = EC (ForeignPtr ElgamalCipherStruct)
newtype ElgamalMessage = EM (ForeignPtr ElgamalMessageStruct)

newtype Cipher = Cipher ByteString deriving Show via ByteStringHex

foreign import ccall unsafe "&free_message_g1"
   rs_free_message_g1 :: FunPtr (Ptr ElgamalMessageStruct -> IO ())
foreign import ccall unsafe "&free_cipher_g1"
   rs_free_cipher_g1 :: FunPtr (Ptr ElgamalCipherStruct -> IO ())
foreign import ccall unsafe "&free_secret_key_g1"
   rs_free_secret_key_g1 :: FunPtr (Ptr ElgamalSecretKeyStruct -> IO ())
foreign import ccall unsafe "&free_public_key_g1"
   rs_free_public_key_g1 :: FunPtr (Ptr ElgamalPublicKeyStruct -> IO ())

foreign import ccall unsafe "free_array_len"
   rs_free_array_len :: Ptr Word8 -> CSize -> IO ()

foreign import ccall unsafe "new_secret_key_g1"
   rs_new_secret_key_g1 :: IO (Ptr ElgamalSecretKeyStruct)
foreign import ccall unsafe "derive_public_key_g1"
   rs_derive_public_key_g1 :: Ptr ElgamalSecretKeyStruct -> Ptr ElgamalPublicKeyStruct
foreign import ccall unsafe "encrypt_g1"
   rs_encrypt_g1 :: Ptr ElgamalPublicKeyStruct -> Ptr ElgamalMessageStruct -> IO (Ptr ElgamalCipherStruct)
foreign import ccall unsafe "decrypt_g1"
   rs_decrypt_g1 :: Ptr ElgamalSecretKeyStruct -> Ptr ElgamalCipherStruct -> IO (Ptr ElgamalMessageStruct)

foreign import ccall unsafe "encrypt_u64_g1"
   rs_encrypt_word64_g1 :: Ptr ElgamalPublicKeyStruct -> Word64 -> Ptr Word8 -> IO ()
foreign import ccall unsafe "decrypt_u64_g1"
   rs_decrypt_word64_g1 :: Ptr ElgamalSecretKeyStruct -> Ptr Word8 -> Ptr Word64 -> Int32

foreign import ccall unsafe "decrypt_u64_unsafe_g1"
   rs_decrypt_word64_unsafe_g1 :: Ptr ElgamalSecretKeyStruct -> Ptr Word8 -> Word64

foreign import ccall unsafe "message_to_bytes_g1"
   rs_message_to_bytes_g1 :: Ptr ElgamalMessageStruct -> Ptr CSize -> IO (Ptr Word8)

foreign import ccall unsafe "public_key_to_bytes_g1"
   rs_public_key_to_bytes_g1 :: Ptr ElgamalPublicKeyStruct -> Ptr CSize -> IO (Ptr Word8)

foreign import ccall unsafe "secret_key_to_bytes_g1"
   rs_secret_key_to_bytes_g1 :: Ptr ElgamalSecretKeyStruct -> Ptr CSize -> IO (Ptr Word8)

foreign import ccall unsafe "cipher_to_bytes_g1"
   rs_cipher_to_bytes_g1 :: Ptr ElgamalCipherStruct -> Ptr CSize -> IO (Ptr Word8)

foreign import ccall unsafe "bytes_to_message_g1"
   rs_bytes_to_message_g1 :: Ptr Word8 -> CSize -> IO (Ptr ElgamalMessageStruct)

foreign import ccall unsafe "bytes_to_secret_key_g1"
   rs_bytes_to_secret_key_g1 :: Ptr Word8 -> CSize -> IO (Ptr ElgamalSecretKeyStruct)

foreign import ccall unsafe "bytes_to_public_key_g1"
   rs_bytes_to_public_key_g1 :: Ptr Word8 -> CSize -> IO (Ptr ElgamalPublicKeyStruct)

foreign import ccall unsafe "bytes_to_cipher_g1"
   rs_bytes_to_cipher_g1 :: Ptr Word8 -> CSize -> IO (Ptr ElgamalCipherStruct)


newSecretKey :: IO (Maybe ElgamalSecretKey)
newSecretKey  = do 
    ptr <- rs_new_secret_key_g1
    if ptr /= nullPtr
    then Just . ESK <$> newForeignPtr rs_free_secret_key_g1 ptr
    else return Nothing

publicKey :: ElgamalSecretKey -> ElgamalPublicKey
publicKey sk = unsafeDupablePerformIO $ do
    ptr <- withSecretKey sk (return . rs_derive_public_key_g1)
    if ptr /= nullPtr
    then EPK <$> newForeignPtr rs_free_public_key_g1 ptr
    -- this should not happen unless a catastrophic failure happens, such as out-of-memory
    else error "Failed to generate public key: nullPtr"

encrypt :: ElgamalPublicKey -> ElgamalMessage -> IO ElgamalCipher
encrypt pk m = do
  ptr <- withPublicKey pk $
         \pk_ptr -> withMessage m $
         rs_encrypt_g1 pk_ptr
  EC <$> newForeignPtr rs_free_cipher_g1 ptr


decrypt :: ElgamalSecretKey -> ElgamalCipher -> ElgamalMessage
decrypt sk c = unsafeDupablePerformIO $ do
  ptr <- withSecretKey sk $
         \sk_ptr -> withCipher c $
         rs_decrypt_g1 sk_ptr
  EM <$> newForeignPtr rs_free_message_g1 ptr


encrypt_word64 :: ElgamalPublicKey -> Word64 ->  IO Cipher
encrypt_word64 pk n =
    do b <- create u64CipherSize (\cipher -> (withPublicKey pk (\pk' -> rs_encrypt_word64_g1 pk' n cipher)))
       return (Cipher b)

messageToBytes :: ElgamalMessage -> ByteString
messageToBytes (EM m) = toBytesHelper rs_message_to_bytes_g1 m

publicKeyToBytes :: ElgamalPublicKey -> ByteString
publicKeyToBytes (EPK pk) = toBytesHelper rs_public_key_to_bytes_g1 pk

secretKeyToBytes :: ElgamalSecretKey -> ByteString
secretKeyToBytes (ESK sk) = toBytesHelper rs_secret_key_to_bytes_g1 sk

cipherToBytes :: ElgamalCipher -> ByteString
cipherToBytes (EC c) = toBytesHelper rs_cipher_to_bytes_g1 c

toBytesHelper ::  (Ptr a -> Ptr CSize -> IO (Ptr Word8)) -> ForeignPtr a -> ByteString
toBytesHelper f m = unsafeDupablePerformIO $ do
  withForeignPtr m $
      \m_ptr ->
        alloca $ \len_ptr -> do
        bytes_ptr <- f m_ptr len_ptr
        len <- peek len_ptr
        unsafePackCStringFinalizer bytes_ptr (fromIntegral len) (rs_free_array_len bytes_ptr len)

fromBytesHelper :: FinalizerPtr a -> (Ptr Word8 -> CSize -> IO (Ptr a)) -> ByteString -> Maybe (ForeignPtr a)
fromBytesHelper finalizer f bs = unsafeDupablePerformIO $ do
  ptr <- unsafeUseAsCStringLen bs $ \(ptr, len) -> f (castPtr ptr :: Ptr Word8) (fromIntegral len :: CSize)
  if ptr == nullPtr then
    return Nothing
  else Just <$> newForeignPtr finalizer ptr

messageFromBytes :: ByteString -> Maybe ElgamalMessage
messageFromBytes bs =
  EM <$> fromBytesHelper rs_free_message_g1 rs_bytes_to_message_g1 bs

cipherFromBytes :: ByteString -> Maybe ElgamalCipher
cipherFromBytes bs =
  EC <$> fromBytesHelper rs_free_cipher_g1 rs_bytes_to_cipher_g1 bs

publicKeyFromBytes :: ByteString -> Maybe ElgamalPublicKey
publicKeyFromBytes bs =
  EPK <$> fromBytesHelper rs_free_public_key_g1 rs_bytes_to_public_key_g1 bs

secretKeyFromBytes :: ByteString -> Maybe ElgamalSecretKey
secretKeyFromBytes bs =
  ESK <$> fromBytesHelper rs_free_secret_key_g1 rs_bytes_to_secret_key_g1 bs

data DecryptWord64Result =
  CipherMalformed
  | DecryptWord64Success !Word64

withSecretKey :: ElgamalSecretKey -> (Ptr ElgamalSecretKeyStruct -> IO b) -> IO b
withSecretKey (ESK sk) = withForeignPtr sk

withPublicKey :: ElgamalPublicKey -> (Ptr ElgamalPublicKeyStruct -> IO b) -> IO b
withPublicKey (EPK pk) = withForeignPtr pk

withMessage :: ElgamalMessage -> (Ptr ElgamalMessageStruct -> IO b) -> IO b
withMessage (EM m) = withForeignPtr m

withCipher :: ElgamalCipher -> (Ptr ElgamalCipherStruct -> IO b) -> IO b
withCipher (EC c) = withForeignPtr c

decrypt_word64 :: ElgamalSecretKey -> Cipher -> DecryptWord64Result 
decrypt_word64 sk (Cipher c) = unsafeDupablePerformIO $
  withByteStringPtr c $
    \cipher ->
      alloca (\result_ptr -> do 
                suc <- withSecretKey sk (\sk' -> return (rs_decrypt_word64_g1 sk' cipher result_ptr))
                case suc of
                  -1 -> return CipherMalformed
                  _ -> do DecryptWord64Success <$> peek result_ptr
             )

instance Show ElgamalCipher where
  show = byteStringToHex . cipherToBytes

instance Show ElgamalMessage where
  show = byteStringToHex . messageToBytes

instance Show ElgamalPublicKey where
  show = byteStringToHex . publicKeyToBytes

instance Show ElgamalSecretKey where
  show = byteStringToHex . secretKeyToBytes

cipherLength :: Int
cipherLength = 96

secretKeyLength :: Int
secretKeyLength = 32

publicKeyLength :: Int
publicKeyLength = 48

messageLength :: Int
messageLength = 48

instance Serialize ElgamalCipher where
  get = do
    bs <- getByteString cipherLength
    case cipherFromBytes bs of
      Nothing -> fail "Cannot decode cipher."
      Just x -> return x

  put = putByteString . cipherToBytes

instance Serialize ElgamalSecretKey where
  get = do
    bs <- getByteString secretKeyLength
    case secretKeyFromBytes bs of
      Nothing -> fail "Cannot decode secret key."
      Just x -> return x

  put = putByteString . secretKeyToBytes


instance Serialize ElgamalPublicKey where
  get = do
    bs <- getByteString publicKeyLength
    case publicKeyFromBytes bs of
      Nothing -> fail "Cannot decode public key."
      Just x -> return x

  put = putByteString . publicKeyToBytes

instance Serialize ElgamalMessage where
  get = do
    bs <- getByteString messageLength
    case messageFromBytes bs of
      Nothing -> fail "Cannot decode message."
      Just x -> return x

  put = putByteString . messageToBytes
