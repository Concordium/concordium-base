{-# LANGUAGE ScopedTypeVariables #-}
module Concordium.ID.IdentityProvider
  (IpInfo, ipInfoToJSON, jsonToIpInfo, withIpInfo, ipIdentity)
  where

import Concordium.Crypto.FFIHelpers

import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.C.Types
import Data.Word
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Binary.Builder as BB
import Concordium.ID.Types
import Concordium.Types.HashableTo (HashableTo, getHash, MHashableTo)
import qualified Concordium.Crypto.SHA256 as H
import Data.Serialize
import System.IO.Unsafe
import Control.DeepSeq

import qualified Data.Aeson as AE
import qualified Data.Aeson.Encoding as AE

newtype IpInfo = IpInfo (ForeignPtr IpInfo)

foreign import ccall unsafe "&ip_info_free" freeIpInfo :: FunPtr (Ptr IpInfo -> IO ())
foreign import ccall safe "ip_info_to_bytes" ipInfoToBytes :: Ptr IpInfo -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall safe "ip_info_from_bytes" ipInfoFromBytes :: Ptr Word8 -> CSize -> IO (Ptr IpInfo)
foreign import ccall safe "ip_info_to_json" ipInfoToJSONFFI :: Ptr IpInfo -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall safe "ip_info_from_json" ipInfoFromJSONFFI :: Ptr Word8 -> CSize -> IO (Ptr IpInfo)
foreign import ccall unsafe "ip_info_ip_identity" ipIdentityFFI :: Ptr IpInfo -> IO IdentityProviderIdentity

withIpInfo :: IpInfo -> (Ptr IpInfo -> IO b) -> IO b
withIpInfo (IpInfo fp) = withForeignPtr fp

-- This instance is different from the Rust one, it puts the length information up front.
-- The binary serialization of identity providers is not used anywhere on the rust side,
-- and it is only used for
--   - block state storage
--   - genesis block
-- on the Haskell side.
instance Serialize IpInfo where
  get = do
    v <- getWord32be
    bs <- getByteString (fromIntegral v)
    case fromBytesHelper freeIpInfo ipInfoFromBytes bs of
      Nothing -> fail "Cannot decode IpInfo."
      Just x -> return $! (IpInfo x)

  put (IpInfo e) = let bs = toBytesHelper ipInfoToBytes e
                   in putWord32be (fromIntegral (BS.length bs)) <> putByteString bs

-- NB: This Eq instance should only be used for testing. It is not guaranteed
-- to be semantically meaningful.
instance Eq IpInfo where
  (IpInfo e1) == (IpInfo e2) = tob e1 == tob e2
    where
      tob = toBytesHelper ipInfoToBytes

-- Show instance uses the JSON instance to pretty print the structure.
instance Show IpInfo where
  show = BS8.unpack . ipInfoToJSON

instance HashableTo H.Hash IpInfo where
  getHash = H.hash . encode

instance Monad m => MHashableTo m H.Hash IpInfo

jsonToIpInfo :: BS.ByteString -> Maybe IpInfo
jsonToIpInfo bs = IpInfo <$> fromJSONHelper freeIpInfo ipInfoFromJSONFFI bs

ipInfoToJSON :: IpInfo -> BS.ByteString
ipInfoToJSON (IpInfo ip) = toJSONHelper ipInfoToJSONFFI ip

ipIdentity :: IpInfo -> IdentityProviderIdentity
ipIdentity ipInfo = unsafeDupablePerformIO $ withIpInfo ipInfo ipIdentityFFI

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
  toEncoding = AE.unsafeToEncoding . BB.fromByteString . ipInfoToJSON


-- Instances for benchmarking
instance NFData IpInfo where
    rnf = (`seq` ())
