{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleInstances #-}
module Concordium.Crypto.Elgamal.TH (
  ElgamalSecretKey,
  ElgamalPublicKey,
  ElgamalMessageStruct,
  ElgamalCipherStruct,
  Cipher(..),
  mkElgamal,
  Parameters(..)
  )
  where

import Concordium.Crypto.ByteStringHelpers
import Data.ByteString(ByteString)
import Data.ByteString.Unsafe
import Data.ByteString.Internal
import Foreign.Ptr
import Foreign.ForeignPtr
import Data.Word
import Data.Int
import System.IO.Unsafe
import Foreign.Storable
import Foreign.Marshal.Alloc
import Foreign.C.Types
import Data.Serialize
import Language.Haskell.TH

-- |Utility function shared by all instantations. Free an array of pointers of
-- given length. If the lenght does not correspond to the number of bytes
-- pointed to by the pointer the behaviour is undefined.
foreign import ccall unsafe "free_array_len"
   rs_free_array_len :: Ptr Word8 -> CSize -> IO ()

-- |The type parameter is a phantom one representing the underlying group of the elgamal scheme.
data ElgamalSecretKeyStruct a
data ElgamalPublicKeyStruct a
data ElgamalMessageStruct a
data ElgamalCipherStruct a
  
newtype ElgamalSecretKey a = ESK (ForeignPtr (ElgamalSecretKeyStruct a))
newtype ElgamalPublicKey a = EPK (ForeignPtr (ElgamalPublicKeyStruct a))
newtype ElgamalCipher a = EC (ForeignPtr (ElgamalCipherStruct a))
newtype ElgamalMessage a = EM (ForeignPtr (ElgamalMessageStruct a))
  
newtype Cipher a = Cipher ByteString deriving Show via ByteStringHex

-- TODO: Possibly the word64 family of functions should be adapted to teh style of others.
-- Right now they do automatic serialization/deserialization themselves, and probably we want to
-- split that away into its own operation.

mkForeignImports :: InternalParameters -> Q [Dec]
mkForeignImports InternalParameters{parameters=Parameters{..},..} =
  mapM (\(cname, name, ty) -> forImpD cCall unsafe cname name ty) $ [
    ('&':cFreeMessageName, freeMessageName, [t| FunPtr (Ptr (ElgamalMessageStruct $(conT tagName)) -> IO ())|]),
    ('&':cFreeCipherName, freeCipherName, [t| FunPtr (Ptr (ElgamalCipherStruct $(conT tagName)) -> IO ())|]),
    ('&':cFreePublicKeyName, freePublicKeyName, [t| FunPtr (Ptr (ElgamalPublicKeyStruct $(conT tagName)) -> IO ())|]),
    ('&':cFreeSecretKeyName, freeSecretKeyName, [t| FunPtr (Ptr (ElgamalSecretKeyStruct $(conT tagName)) -> IO ())|]),
    (cNewSecretKeyName, newSecretKeyName, [t| IO (Ptr (ElgamalSecretKeyStruct $(conT tagName)))|]),
    (cDerivePublicKeyName, derivePublicKeyName, [t| Ptr (ElgamalSecretKeyStruct $(conT tagName)) -> Ptr (ElgamalPublicKeyStruct $(conT tagName))|]),
    (cEncryptName, encryptName,  [t|Ptr (ElgamalPublicKeyStruct $(conT tagName)) -> Ptr (ElgamalMessageStruct $(conT tagName)) -> IO (Ptr (ElgamalCipherStruct $(conT tagName)))|]),
    (cDecryptName, decryptName, [t|Ptr (ElgamalSecretKeyStruct $(conT tagName)) -> Ptr (ElgamalCipherStruct $(conT tagName)) -> IO (Ptr (ElgamalMessageStruct $(conT tagName)))|]),
    (cEncryptWord64Name, encryptWord64Name, [t|Ptr (ElgamalPublicKeyStruct $(conT tagName)) -> Word64 -> Ptr Word8 -> IO ()|]),
    (cDecryptWord64Name, decryptWord64Name, [t| Ptr (ElgamalSecretKeyStruct $(conT tagName)) -> Ptr Word8 -> Ptr Word64 -> Int32|]),
    (cDecryptWord64UnsafeName, decryptWord64UnsafeName, [t|Ptr (ElgamalSecretKeyStruct $(conT tagName)) -> Ptr Word8 -> Word64|]),
    (cMessageToBytesName, messageToBytesName, [t|Ptr (ElgamalMessageStruct $(conT tagName)) -> Ptr CSize -> IO (Ptr Word8)|]),
    (cCipherToBytesName, cipherToBytesName, [t|Ptr (ElgamalCipherStruct $(conT tagName)) -> Ptr CSize -> IO (Ptr Word8)|]),
    (cPublicKeyToBytesName, publicKeyToBytesName, [t|Ptr (ElgamalPublicKeyStruct $(conT tagName)) -> Ptr CSize -> IO (Ptr Word8)|]),
    (cSecretKeyToBytesName, secretKeyToBytesName, [t|Ptr (ElgamalSecretKeyStruct $(conT tagName)) -> Ptr CSize -> IO (Ptr Word8)|]),
    (cBytesToMessageName, bytesToMessageName, [t|Ptr Word8 -> CSize -> IO (Ptr (ElgamalMessageStruct $(conT tagName)))|]),
    (cBytesToCipherName, bytesToCipherName, [t|Ptr Word8 -> CSize -> IO (Ptr (ElgamalCipherStruct $(conT tagName)))|]),
    (cBytesToPublicKeyName, bytesToPublicKeyName, [t|Ptr Word8 -> CSize -> IO (Ptr (ElgamalPublicKeyStruct $(conT tagName)))|]),
    (cBytesToSecretKeyName, bytesToSecretKeyName, [t|Ptr Word8 -> CSize -> IO (Ptr (ElgamalSecretKeyStruct $(conT tagName)))|])]


mkTerms :: InternalParameters -> Q [Dec]
mkTerms InternalParameters{parameters=Parameters{..},..} = [d|
  newSecretKey :: IO (Maybe (ElgamalSecretKey $(conT tagName)))
  newSecretKey  = do 
    ptr <- $(varE newSecretKeyName)
    if ptr /= nullPtr
    then Just . ESK <$> newForeignPtr $(varE freeSecretKeyName) ptr
    else return Nothing

  publicKey :: (ElgamalSecretKey $(conT tagName)) -> (ElgamalPublicKey $(conT tagName))
  publicKey sk = unsafeDupablePerformIO $ do
      ptr <- withSecretKey sk (return . $(varE derivePublicKeyName))
      if ptr /= nullPtr
      then EPK <$> newForeignPtr $(varE freePublicKeyName) ptr
      -- this should not happen unless a catastrophic failure happens, such as out-of-memory
      else error "Failed to generate public key: nullPtr"

  encrypt :: (ElgamalPublicKey $(conT tagName)) -> (ElgamalMessage $(conT tagName)) -> IO (ElgamalCipher $(conT tagName))
  encrypt pk m = do
    ptr <- withPublicKey pk $
           \pk_ptr -> withMessage m $
           $(varE encryptName) pk_ptr
    EC <$> newForeignPtr $(varE freeCipherName) ptr


  decrypt :: (ElgamalSecretKey $(conT tagName)) -> (ElgamalCipher $(conT tagName)) -> (ElgamalMessage $(conT tagName))
  decrypt sk c = unsafeDupablePerformIO $ do
    ptr <- withSecretKey sk $
           \sk_ptr -> withCipher c $
           $(varE decryptName) sk_ptr
    EM <$> newForeignPtr $(varE freeMessageName) ptr


  encrypt_word64 :: (ElgamalPublicKey $(conT tagName)) -> Word64 ->  IO (Cipher $(conT tagName))
  encrypt_word64 pk n =
      do b <- create u64CipherSize (\cipher -> (withPublicKey pk (\pk' -> $(varE encryptWord64Name) pk' n cipher)))
         return (Cipher b)

  messageToBytes :: (ElgamalMessage $(conT tagName)) -> ByteString
  messageToBytes (EM m) = toBytesHelper $(varE messageToBytesName) m

  publicKeyToBytes :: (ElgamalPublicKey $(conT tagName)) -> ByteString
  publicKeyToBytes (EPK pk) = toBytesHelper $(varE publicKeyToBytesName) pk
  
  secretKeyToBytes :: (ElgamalSecretKey $(conT tagName)) -> ByteString
  secretKeyToBytes (ESK sk) = toBytesHelper $(varE secretKeyToBytesName) sk
  
  cipherToBytes :: (ElgamalCipher $(conT tagName)) -> ByteString
  cipherToBytes (EC c) = toBytesHelper $(varE cipherToBytesName) c
  
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
  
  messageFromBytes :: ByteString -> Maybe (ElgamalMessage $(conT tagName))
  messageFromBytes bs =
    EM <$> fromBytesHelper $(varE freeMessageName) $(varE bytesToMessageName) bs
  
  cipherFromBytes :: ByteString -> Maybe (ElgamalCipher $(conT tagName))
  cipherFromBytes bs =
    EC <$> fromBytesHelper $(varE freeCipherName) $(varE bytesToCipherName) bs
  
  publicKeyFromBytes :: ByteString -> Maybe (ElgamalPublicKey $(conT tagName))
  publicKeyFromBytes bs =
    EPK <$> fromBytesHelper $(varE freePublicKeyName) $(varE bytesToPublicKeyName) bs
  
  secretKeyFromBytes :: ByteString -> Maybe (ElgamalSecretKey $(conT tagName))
  secretKeyFromBytes bs =
    ESK <$> fromBytesHelper $(varE freeSecretKeyName) $(varE bytesToSecretKeyName) bs

  data DecryptWord64Result =
    CipherMalformed
    | DecryptWord64Success !Word64

  withSecretKey :: (ElgamalSecretKey $(conT tagName)) -> (Ptr (ElgamalSecretKeyStruct $(conT tagName)) -> IO b) -> IO b
  withSecretKey (ESK sk) = withForeignPtr sk
  
  withPublicKey :: (ElgamalPublicKey $(conT tagName)) -> (Ptr (ElgamalPublicKeyStruct $(conT tagName)) -> IO b) -> IO b
  withPublicKey (EPK pk) = withForeignPtr pk
  
  withMessage :: (ElgamalMessage $(conT tagName)) -> (Ptr (ElgamalMessageStruct $(conT tagName)) -> IO b) -> IO b
  withMessage (EM m) = withForeignPtr m
  
  withCipher :: (ElgamalCipher $(conT tagName)) -> (Ptr (ElgamalCipherStruct $(conT tagName)) -> IO b) -> IO b
  withCipher (EC c) = withForeignPtr c

  decryptWord64 :: (ElgamalSecretKey $(conT tagName)) -> Cipher $(conT tagName) -> DecryptWord64Result 
  decryptWord64 sk (Cipher c) = unsafeDupablePerformIO $
    withByteStringPtr c $
      \cipher ->
        alloca (\result_ptr -> do 
                  suc <- withSecretKey sk (\sk' -> return ($(varE decryptWord64Name) sk' cipher result_ptr))
                  if suc == -1 then
                    return CipherMalformed
                  else DecryptWord64Success <$> peek result_ptr
               )

  instance Show (ElgamalCipher $(conT tagName)) where
    show = byteStringToHex . cipherToBytes
  
  instance Show (ElgamalMessage $(conT tagName)) where
    show = byteStringToHex . messageToBytes
  
  instance Show (ElgamalPublicKey $(conT tagName)) where
    show = byteStringToHex . publicKeyToBytes
  
  instance Show (ElgamalSecretKey $(conT tagName)) where
    show = byteStringToHex . secretKeyToBytes

  instance Serialize (ElgamalCipher $(conT tagName)) where
    get = do
      bs <- getByteString cipherLength
      case cipherFromBytes bs of
        Nothing -> fail "Cannot decode cipher."
        Just x -> return x
  
    put = putByteString . cipherToBytes
  
  instance Serialize (ElgamalSecretKey $(conT tagName)) where
    get = do
      bs <- getByteString secretKeyLength
      case secretKeyFromBytes bs of
        Nothing -> fail "Cannot decode secret key."
        Just x -> return x
  
    put = putByteString . secretKeyToBytes
  
  
  instance Serialize (ElgamalPublicKey $(conT tagName)) where
    get = do
      bs <- getByteString publicKeyLength
      case publicKeyFromBytes bs of
        Nothing -> fail "Cannot decode public key."
        Just x -> return x
  
    put = putByteString . publicKeyToBytes
  
  instance Serialize (ElgamalMessage $(conT tagName)) where
    get = do
      bs <- getByteString messageLength
      case messageFromBytes bs of
        Nothing -> fail "Cannot decode message."
        Just x -> return x
  
    put = putByteString . messageToBytes

  u64CipherSize :: Int
  u64CipherSize = 64 * cipherLength

  word64CipherToBytes :: Cipher $(conT tagName) -> ByteString
  word64CipherToBytes (Cipher c) = c

  word64CipherFromBytes :: Cipher $(conT tagName) -> ByteString
  word64CipherFromBytes (Cipher c) = c

  |]

data Parameters = Parameters {
  cipherLength :: Int,
  secretKeyLength :: Int,
  publicKeyLength :: Int,
  messageLength :: Int,
  cFreeMessageName :: String,
  cFreeCipherName :: String,
  cFreePublicKeyName :: String,
  cFreeSecretKeyName :: String,
  cNewSecretKeyName :: String,
  cDerivePublicKeyName :: String,
  cEncryptName :: String,
  cDecryptName :: String,
  cEncryptWord64Name :: String,
  cDecryptWord64Name :: String,
  cDecryptWord64UnsafeName :: String,
  cMessageToBytesName :: String,
  cCipherToBytesName :: String,
  cPublicKeyToBytesName :: String,
  cSecretKeyToBytesName :: String,
  cBytesToMessageName :: String,
  cBytesToCipherName :: String,
  cBytesToPublicKeyName :: String,
  cBytesToSecretKeyName :: String,
  tagName :: Name
  }

data InternalParameters = InternalParameters {
  freeMessageName :: Name,         
  freeCipherName :: Name,
  freePublicKeyName :: Name,
  freeSecretKeyName :: Name,
  newSecretKeyName :: Name,
  derivePublicKeyName :: Name,
  encryptName :: Name,
  decryptName :: Name,
  encryptWord64Name :: Name,
  decryptWord64Name :: Name,
  decryptWord64UnsafeName :: Name,
  messageToBytesName :: Name,
  cipherToBytesName :: Name,
  publicKeyToBytesName :: Name,
  secretKeyToBytesName :: Name,
  bytesToMessageName :: Name,
  bytesToCipherName :: Name,
  bytesToPublicKeyName :: Name,
  bytesToSecretKeyName :: Name,
  parameters :: Parameters
  }


mkElgamal :: Parameters -> Q [Dec]
mkElgamal parameters@Parameters{..} =
  let iparams = InternalParameters{
    freeMessageName = mkName cFreeMessageName,
    freeCipherName = mkName cFreeCipherName,
    freePublicKeyName = mkName cFreePublicKeyName,
    freeSecretKeyName = mkName cFreeSecretKeyName,
    newSecretKeyName = mkName cNewSecretKeyName,
    derivePublicKeyName = mkName cDerivePublicKeyName,
    encryptName = mkName cEncryptName,
    decryptName = mkName cDecryptName,
    encryptWord64Name = mkName cEncryptWord64Name,
    decryptWord64Name = mkName cDecryptWord64Name,
    decryptWord64UnsafeName = mkName cDecryptWord64UnsafeName,
    messageToBytesName = mkName cMessageToBytesName,
    cipherToBytesName = mkName cCipherToBytesName,
    publicKeyToBytesName = mkName cPublicKeyToBytesName,
    secretKeyToBytesName = mkName cSecretKeyToBytesName,
    bytesToMessageName = mkName cBytesToMessageName,
    bytesToCipherName = mkName cBytesToCipherName,
    bytesToPublicKeyName = mkName cBytesToPublicKeyName,
    bytesToSecretKeyName = mkName cBytesToSecretKeyName,
    ..
    } in
  do imps <- mkForeignImports iparams
     tms <- mkTerms iparams
     return (imps ++ tms)
