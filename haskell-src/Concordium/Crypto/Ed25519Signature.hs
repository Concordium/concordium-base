{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}
{-# OPTIONS_HADDOCK not-home #-}

-- |This module provides a prototype implementation of
-- EDDSA scheme of Curve Ed25519
--  IRTF RFC 8032
module Concordium.Crypto.Ed25519Signature where

import Concordium.Crypto.ByteStringHelpers
import Concordium.Crypto.FFIHelpers
import Control.DeepSeq
import qualified Data.Aeson as AE
import Data.ByteString (ByteString)
import qualified Data.ByteString.Short as BSS
import qualified Data.ByteString.Unsafe as BS
import Data.Int
import Data.Serialize
import qualified Data.Text as Text
import Data.Word
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Ptr
import System.IO.Unsafe

foreign import ccall unsafe "eddsa_priv_key" genPrivateKey :: IO (Ptr SignKey)
foreign import ccall unsafe "eddsa_pub_key" derivePublicFFI :: Ptr SignKey -> IO (Ptr VerifyKey)
foreign import ccall unsafe "eddsa_sign" signFFI :: Ptr Word8 -> Word32 -> Ptr SignKey -> Ptr VerifyKey -> Ptr Word8 -> IO ()
foreign import ccall unsafe "eddsa_verify" verifyFFI :: Ptr Word8 -> Word32 -> Ptr VerifyKey -> Ptr Word8 -> CSize -> IO Int32
foreign import ccall unsafe "&eddsa_public_free" freeVerifyKey :: FunPtr (Ptr VerifyKey -> IO ())
foreign import ccall unsafe "eddsa_public_to_bytes" toBytesVerifyKey :: Ptr VerifyKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "eddsa_public_from_bytes" fromBytesVerifyKey :: Ptr Word8 -> CSize -> IO (Ptr VerifyKey)
foreign import ccall unsafe "&eddsa_sign_free" freeSignKey :: FunPtr (Ptr SignKey -> IO ())
foreign import ccall unsafe "eddsa_sign_to_bytes" toBytesSignKey :: Ptr SignKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "eddsa_sign_from_bytes" fromBytesSignKey :: Ptr Word8 -> CSize -> IO (Ptr SignKey)

-- Taken from https://docs.rs/ed25519-dalek/1.0.0-pre.2/src/ed25519_dalek/constants.rs.html#13
signKeySize :: Int
signKeySize = 32
verifyKeySize :: Int
verifyKeySize = 32
signatureSize :: Int
signatureSize = 64

newtype SignKey = SignKey (ForeignPtr SignKey)
newtype VerifyKey = VerifyKey (ForeignPtr VerifyKey)

-- |We compare key serializations. DO NOT USE IN PRODUCTION
instance Eq SignKey where
    v1 == v2 = encode v1 == encode v2

-- Ord instance compares serialized strings
instance Ord VerifyKey where
    compare x y = compare (encode x) (encode y)

-- |Display in base 16.
instance Show SignKey where
    show signKey = Text.unpack (serializeBase16 signKey)

instance Serialize SignKey where
    get = do
        bs <- getByteString signKeySize
        case fromBytesHelper freeSignKey fromBytesSignKey bs of
            Nothing -> fail "Cannot decode signing key."
            Just x -> return (SignKey x)

    put (SignKey e) =
        let bs = toBytesHelper toBytesSignKey e
        in  putByteString bs

instance AE.ToJSON SignKey where
    toJSON v = AE.String (serializeBase16 v)

instance AE.FromJSON SignKey where
    parseJSON = AE.withText "Signing key in base16" deserializeBase16

-- |We compare key serializations.
instance Eq VerifyKey where
    v1 == v2 = encode v1 == encode v2

-- |Display in base 16.
instance Show VerifyKey where
    show vfKey = Text.unpack (serializeBase16 vfKey)

instance Serialize VerifyKey where
    get = do
        bs <- getByteString verifyKeySize
        case fromBytesHelper freeVerifyKey fromBytesVerifyKey bs of
            Nothing -> fail "Cannot decode verification key."
            Just x -> return $ VerifyKey x

    put (VerifyKey e) =
        let bs = toBytesHelper toBytesVerifyKey e
        in  putByteString bs

instance AE.ToJSON VerifyKey where
    toJSON v = AE.String (serializeBase16 v)

instance AE.FromJSON VerifyKey where
    parseJSON = AE.withText "Verification key in base16" deserializeBase16

-- Instances for benchmarking
instance NFData SignKey where
    rnf = (`seq` ())
instance NFData VerifyKey where
    rnf = (`seq` ())

withSignKey :: SignKey -> (Ptr SignKey -> IO b) -> IO b
withSignKey (SignKey sk) = withForeignPtr sk
withVerifyKey :: VerifyKey -> (Ptr VerifyKey -> IO b) -> IO b
withVerifyKey (VerifyKey vfkey) = withForeignPtr vfkey

newPrivKey :: IO SignKey
newPrivKey = SignKey <$> (newForeignPtr freeSignKey =<< genPrivateKey)

deriveVerifyKey :: SignKey -> VerifyKey
deriveVerifyKey sk = VerifyKey . unsafePerformIO $ withSignKey sk $ \signKeyPtr -> newForeignPtr freeVerifyKey =<< derivePublicFFI signKeyPtr

newKeyPair :: IO (SignKey, VerifyKey)
newKeyPair = do
    signKey <- newPrivKey
    let verifyKey = deriveVerifyKey signKey
    return (signKey, verifyKey)

sign :: SignKey -> VerifyKey -> ByteString -> BSS.ShortByteString
sign signKey verifyKey m = unsafePerformIO $
    withSignKey signKey $ \signKeyPtr ->
        withVerifyKey verifyKey $ \verifyKeyPtr ->
            BS.unsafeUseAsCStringLen m $ \(m', mlen) -> do
                -- this use of unsafe is fine because the sign function
                -- checks the length before dereferencing the data pointer
                ((), s) <- withAllocatedShortByteString signatureSize $ signFFI (castPtr m') (fromIntegral mlen) signKeyPtr verifyKeyPtr
                return s

verify :: VerifyKey -> ByteString -> BSS.ShortByteString -> Bool
verify vf m sig = (BSS.length sig == signatureSize) && (suc > 0)
  where
    suc = unsafePerformIO $!
        BS.unsafeUseAsCStringLen m $ \(m', mlen) ->
            -- this use of unsafe is fine because the rust verify function
            -- checks the length before dereferencing the data pointer
            withVerifyKey vf $ \verifyKeyPtr ->
                withByteStringPtrLen sig (\sigPtr sigLen -> verifyFFI (castPtr m') (fromIntegral mlen) verifyKeyPtr sigPtr (fromIntegral sigLen))
