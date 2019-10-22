{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE LambdaCase #-}
module Concordium.ID.IdentityProvider
  (IpInfo, ipInfoToJSON, jsonToIpInfo, withIpInfo)
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

import qualified Data.Aeson as AE

newtype IpInfo = IpInfo (ForeignPtr IpInfo)

foreign import ccall unsafe "&ip_info_free" freeIpInfo :: FunPtr (Ptr IpInfo -> IO ())
foreign import ccall unsafe "ip_info_to_bytes" ipInfoToBytes :: Ptr IpInfo -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "ip_info_from_bytes" ipInfoFromBytes :: Ptr Word8 -> CSize -> IO (Ptr IpInfo)
foreign import ccall unsafe "ip_info_to_json" ipInfoToJSONFFI :: Ptr IpInfo -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "ip_info_from_json" ipInfoFromJSONFFI :: Ptr Word8 -> CSize -> IO (Ptr IpInfo)

withIpInfo :: IpInfo -> (Ptr IpInfo -> IO b) -> IO b
withIpInfo (IpInfo fp) = withForeignPtr fp

-- This instance is different from the Rust one, it puts the length information up front.
instance Serialize IpInfo where
  get = do
    v <- getWord32be
    bs <- getByteString (fromIntegral v)
    case fromBytesHelper freeIpInfo ipInfoFromBytes bs of
      Nothing -> fail "Cannot decode IpInfo."
      Just x -> return $! (IpInfo x)

  put (IpInfo e) = let bs = toBytesHelper ipInfoToBytes e
                   in putWord32be (fromIntegral (BS.length bs)) <> putByteString bs

-- Show instance uses the JSON instance to pretty print the structure.
instance Show IpInfo where
  show = BS8.unpack . ipInfoToJSON

jsonToIpInfo :: BS.ByteString -> Maybe IpInfo
jsonToIpInfo bs = IpInfo <$> fromJSONHelper freeIpInfo ipInfoFromJSONFFI bs

ipInfoToJSON :: IpInfo -> BS.ByteString
ipInfoToJSON (IpInfo ip) = toJSONHelper ipInfoToJSONFFI ip

-- These JSON instances are very inefficient and should not be used in
-- performance critical contexts, however they are fine for loading
-- configuration data, or similar one-off uses.

instance AE.FromJSON IpInfo where
  parseJSON v@(AE.Object _) =
    -- this is a terrible hack to avoid writing duplicate instances
    -- hack in the sense of performance
    case jsonToIpInfo (BSL.toStrict (AE.encode v)) of
      Nothing -> fail "Could not decode IpInfo."
      Just ipinfo -> return ipinfo
  parseJSON _ = fail "IpInfo: Expected object."

instance AE.ToJSON IpInfo where
  toJSON ipinfo =
    case AE.decodeStrict (ipInfoToJSON ipinfo) of
      Nothing -> error "Internal error: Rust serialization does not produce valid JSON."
      Just v -> v
