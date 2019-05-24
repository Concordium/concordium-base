module Concordium.Crypto.Elgamal where

import           Concordium.Crypto.ByteStringHelpers
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as B
import           Data.ByteString.Internal
import           Foreign.Ptr
import           Foreign.ForeignPtr
import           Data.Word
import           System.IO.Unsafe
import           Control.Monad
import           Data.Serialize
import           Data.Hashable
import           Data.Bits
import           Foreign.Storable           (peek)
import           Text.Read
import           Data.Char

u64CipherSize = 6144

data ElgamalSecretKeyData
data ElgamalPublicKeyData
data Cipher = Cipher ByteString

type ElgamalSecretKey = ForeignPtr ElgamalSecretKeyData 
type ElgamalPublicKey = ForeignPtr ElgamalPublicKeyData 

foreign import ccall unsafe "new_secret_key"
   rs_new_secret_key :: IO (Ptr ElgamalSecretKeyData)

foreign import ccall unsafe "&secret_key_free"
   rs_secret_key_free :: FunPtr (Ptr ElgamalSecretKeyData -> IO ())

foreign import ccall unsafe "public_key"
   rs_public_key :: Ptr ElgamalSecretKeyData -> IO (Ptr ElgamalPublicKeyData) 

foreign import ccall unsafe "&public_key_free"
   rs_public_key_free :: FunPtr (Ptr ElgamalPublicKeyData -> IO ())

foreign import ccall unsafe "encrypt_u64"
   rs_encrypt_word64 :: Ptr ElgamalPublicKeyData -> Word64 -> Ptr Word8 -> IO ()


foreign import ccall unsafe "decrypt_u64"
   rs_decrypt_word64 :: Ptr ElgamalSecretKeyData -> Ptr Word8 -> Word32 -> IO Word64 


foreign import ccall unsafe "decrypt_u64_unsafe"
   rs_decrypt_word64_unsafe :: Ptr ElgamalSecretKeyData -> Ptr Word8 -> Word32 -> IO ()

newSecretKey :: IO (ElgamalSecretKey)
newSecretKey  = do 
    ptr <- rs_new_secret_key
    if ptr /= nullPtr
       then do 
           fp <- newForeignPtr rs_secret_key_free ptr
           return fp
       else
           error "Failed to generate private key" 

publicKey :: ElgamalSecretKey -> IO (ElgamalPublicKey)
publicKey sk =  do 
    ptr <- withForeignPtr sk (\sk' -> rs_public_key sk')
    if ptr /= nullPtr
       then do 
           fp <- newForeignPtr rs_public_key_free ptr
           return fp
       else 
            error "Failed to generate public key"

encrypt_word64 :: ElgamalPublicKey -> Word64 ->  IO Cipher
encrypt_word64 pk n = do b <-create u64CipherSize (\cipher -> (withForeignPtr pk (\pk' -> rs_encrypt_word64 pk' n cipher)))
                         return (Cipher b)

decrypt_word64 :: ElgamalSecretKey -> Cipher -> IO Word64 
decrypt_word64 sk (Cipher c) = withByteStringPtr c $ \cipher -> (withForeignPtr sk (\sk' -> rs_decrypt_word64 sk' cipher (fromIntegral $ B.length c)))

