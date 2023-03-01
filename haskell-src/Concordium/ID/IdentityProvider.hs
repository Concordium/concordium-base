{-# LANGUAGE ScopedTypeVariables #-}

module Concordium.ID.IdentityProvider (IpInfo, createIpInfo, ipInfoToJSON, jsonToIpInfo, withIpInfo, ipIdentity, ipName, ipUrl, ipDescription, ipVerifyKey, ipCdiVerifyKey)
where

import Concordium.Crypto.FFIHelpers

import qualified Concordium.Crypto.SHA256 as H
import Concordium.ID.Types
import Concordium.Types.HashableTo (HashableTo, MHashableTo, getHash)
import Control.DeepSeq
import qualified Data.Binary.Builder as BB
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BSL
import Data.Serialize
import Data.Text (Text)
import qualified Data.Text.Encoding as Text
import Data.Word
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Ptr
import System.IO.Unsafe

import qualified Data.Aeson as AE
import qualified Data.Aeson.Encoding as AE
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)

newtype IpInfo = IpInfo (ForeignPtr IpInfo)

foreign import ccall unsafe "&ip_info_free" freeIpInfo :: FunPtr (Ptr IpInfo -> IO ())
foreign import ccall safe "ip_info_to_bytes" ipInfoToBytes :: Ptr IpInfo -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall safe "ip_info_from_bytes" ipInfoFromBytes :: Ptr Word8 -> CSize -> IO (Ptr IpInfo)
foreign import ccall safe "ip_info_to_json" ipInfoToJSONFFI :: Ptr IpInfo -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall safe "ip_info_from_json" ipInfoFromJSONFFI :: Ptr Word8 -> CSize -> IO (Ptr IpInfo)
foreign import ccall unsafe "ip_info_ip_identity" ipIdentityFFI :: Ptr IpInfo -> IO IdentityProviderIdentity
foreign import ccall unsafe "ip_info_name" ipNameFFI :: Ptr IpInfo -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "ip_info_url" ipUrlFFI :: Ptr IpInfo -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "ip_info_description" ipDescriptionFFI :: Ptr IpInfo -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "ip_info_verify_key" ipVerifyKeyFFI :: Ptr IpInfo -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "ip_info_cdi_verify_key" ipCdiVerifyKeyFFI :: Ptr IpInfo -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "ip_info_create"
    createIpInfoFFI ::
        -- |The identity of the identity provider.
        IdentityProviderIdentity ->
        -- |Pointer to a byte array which is the serialization of a
        -- @ed25519_dalek::PublicKey@ Rust-instance and its length.
        Ptr Word8 ->
        CSize ->
        -- |Pointer to a byte array which is the serialization of a
        -- @ps_sig::PublicKey<Bls12>@ Rust-instance and its length.
        Ptr Word8 ->
        CSize ->
        -- |Pointer to a byte array which is the serialization of an
        -- utf8 encoded string and its length.
        Ptr Word8 ->
        CSize ->
        -- |Pointer to a byte array which is the serialization of an
        -- utf8 encoded string and its length.
        Ptr Word8 ->
        CSize ->
        -- |Pointer to a byte array which is the serialization of an
        -- utf8 encoded string and its length.
        Ptr Word8 ->
        CSize ->
        -- |Pointer to an @IpInfo@ Rust instance with its corresponding fields set
        -- to deserializations of the the above. This is a null-pointer on failure.
        IO (Ptr IpInfo)

-- |Create an @IpInfo@ instance from constituent parts.
createIpInfo ::
    -- |The identity of the identity provider.
    IdentityProviderIdentity ->
    -- |Serialized Pointcheval-Sanders public key.
    BS.ByteString ->
    -- |Serialized Ed25519 public key.
    BS.ByteString ->
    -- |Name of the identity provider.
    Text ->
    -- |URL of the identity provider.
    Text ->
    -- |Description of the provider.
    Text ->
    -- |If the public keys cannot be deserialized this returns @Nothing@. Otherwise a @IpInfo@ is returned.
    Maybe IpInfo
createIpInfo idIdentity verifyKey cdiVerifyKey name url desc =
    unsafePerformIO
        ( do
            -- Note that empty strings correspond to arbitrary pointers being passed
            -- to the Rust side. This is handled on the Rust side by checking the
            -- lengths, so this is safe.
            ptr <- unsafeUseAsCStringLen verifyKey $ \(vkPtr, vkLen) ->
                unsafeUseAsCStringLen cdiVerifyKey $ \(cvkPtr, cvkLen) ->
                    unsafeUseAsCStringLen (Text.encodeUtf8 name) $ \(nPtr, nLen) ->
                        unsafeUseAsCStringLen (Text.encodeUtf8 url) $ \(urlPtr, urlLen) ->
                            unsafeUseAsCStringLen (Text.encodeUtf8 desc) $ \(descPtr, descLen) ->
                                createIpInfoFFI
                                    idIdentity
                                    (castPtr vkPtr)
                                    (fromIntegral vkLen)
                                    (castPtr cvkPtr)
                                    (fromIntegral cvkLen)
                                    (castPtr nPtr)
                                    (fromIntegral nLen)
                                    (castPtr urlPtr)
                                    (fromIntegral urlLen)
                                    (castPtr descPtr)
                                    (fromIntegral descLen)
            if ptr == nullPtr
                then return Nothing
                else Just . IpInfo <$> newForeignPtr freeIpInfo ptr
        )

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

    put (IpInfo e) =
        let bs = toBytesHelper ipInfoToBytes e
        in  putWord32be (fromIntegral (BS.length bs)) <> putByteString bs

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

-- |Get the description name of the IP.
--  Using Text.decodeUtf8 which can throw an exception,
--  but the AR name is represented as a String in Rust, so it is safe.
ipName :: IpInfo -> Text
ipName (IpInfo ip) = Text.decodeUtf8 $ toBytesHelper ipNameFFI ip

-- |Get the description URL of the IP.
--  Using Text.decodeUtf8 which can throw an exception,
--  but the AR name is represented as a String in Rust, so it is safe.
ipUrl :: IpInfo -> Text
ipUrl (IpInfo ip) = Text.decodeUtf8 $ toBytesHelper ipUrlFFI ip

-- |Get the description text of the IP.
--  Using Text.decodeUtf8 which can throw an exception,
--  but the AR name is represented as a String in Rust, so it is safe.
ipDescription :: IpInfo -> Text
ipDescription (IpInfo ip) = Text.decodeUtf8 $ toBytesHelper ipDescriptionFFI ip

-- |Get the verify key of the IP as bytes.
--  The function is currently only used for returning protobuf data in the gRPC2 api.
--  That is why it returns bytes instead of structured data.
ipVerifyKey :: IpInfo -> BS.ByteString
ipVerifyKey (IpInfo ip) = toBytesHelper ipVerifyKeyFFI ip

-- |Get the cdi verify key of the IP as bytes.
--  The function is currently only used for returning protobuf data in the gRPC2 api.
--  That is why it returns bytes instead of a structured data.
ipCdiVerifyKey :: IpInfo -> BS.ByteString
ipCdiVerifyKey (IpInfo ip) = toBytesHelper ipCdiVerifyKeyFFI ip

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
