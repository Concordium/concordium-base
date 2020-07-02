{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE LambdaCase #-}
module Concordium.ID.AnonymityRevoker
  (ArInfo, arInfoToJSON, jsonToArInfo, withArInfo, arIdentity)
  where

import Concordium.Crypto.FFIHelpers

import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.C.Types
import Data.Word
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BSL
import Data.Serialize
import Control.DeepSeq
import System.IO.Unsafe

import Concordium.ID.Types

import qualified Data.Aeson as AE

newtype ArInfo = ArInfo (ForeignPtr ArInfo)

foreign import ccall unsafe "&ar_info_free" freeArInfo :: FunPtr (Ptr ArInfo -> IO ())
foreign import ccall unsafe "ar_info_to_bytes" arInfoToBytes :: Ptr ArInfo -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "ar_info_from_bytes" arInfoFromBytes :: Ptr Word8 -> CSize -> IO (Ptr ArInfo)
foreign import ccall unsafe "ar_info_to_json" arInfoToJSONFFI :: Ptr ArInfo -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "ar_info_from_json" arInfoFromJSONFFI :: Ptr Word8 -> CSize -> IO (Ptr ArInfo)
foreign import ccall unsafe "ar_info_ar_identity" arIdentityFFI :: Ptr ArInfo -> IO ArIdentity

withArInfo :: ArInfo -> (Ptr ArInfo -> IO b) -> IO b
withArInfo (ArInfo fp) = withForeignPtr fp

-- This instance is different from the Rust one, it puts the length information up front.
instance Serialize ArInfo where
  get = do
    v <- getWord32be
    bs <- getByteString (fromIntegral v)
    case fromBytesHelper freeArInfo arInfoFromBytes bs of
      Nothing -> fail "Cannot decode ArInfo."
      Just x -> return $! (ArInfo x)

  put (ArInfo e) = let bs = toBytesHelper arInfoToBytes e
                   in putWord32be (fromIntegral (BS.length bs)) <> putByteString bs

-- NB: This Eq instance should onoly be used for testing. It is not guaranteed
-- to be semantically meaningful.
instance Eq ArInfo where
  (ArInfo e1) == (ArInfo e2) = tob e1 == tob e2
    where
      tob = toBytesHelper arInfoToBytes

-- Show instance uses the JSON instance to pretty print the structure.
instance Show ArInfo where
  show = BS8.unpack . arInfoToJSON

jsonToArInfo :: BS.ByteString -> Maybe ArInfo
jsonToArInfo bs = ArInfo <$> fromJSONHelper freeArInfo arInfoFromJSONFFI bs

arInfoToJSON :: ArInfo -> BS.ByteString
arInfoToJSON (ArInfo ar) = toJSONHelper arInfoToJSONFFI ar

arIdentity :: ArInfo -> ArIdentity
arIdentity arInfo = unsafeDupablePerformIO $ withArInfo arInfo arIdentityFFI

-- *JSON instances
-- These JSON instances are very inefficient and should not be used in
-- performance critical contexts, however they are fine for loading
-- configuration data, or similar one-off uses.
-- Use `arInfoToJSON` for direct serialization to bytestring.

instance AE.FromJSON ArInfo where
  parseJSON v@(AE.Object _) =
    -- this is a terrible hack to avoid writing duplicate instances
    -- hack in the sense of performance
    case jsonToArInfo (BSL.toStrict (AE.encode v)) of
      Nothing -> fail "Could not decode ArInfo."
      Just arInfo -> return arInfo
  parseJSON _ = fail "ArInfo: Expected object."

instance AE.ToJSON ArInfo where
  toJSON arInfo =
    case AE.decodeStrict (arInfoToJSON arInfo) of
      Nothing -> error "Internal error: Rust serialization does not produce valid JSON."
      Just v -> v

-- Instances for benchmarking
instance NFData ArInfo where
    rnf = (`seq` ())
