{-# LANGUAGE ScopedTypeVariables #-}

module Concordium.ID.AnonymityRevoker (ArInfo, arInfoToJSON, jsonToArInfo, withArInfo, arIdentity, arName, arUrl, arDescription, arPublicKey)
where

import Concordium.Crypto.FFIHelpers

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

import qualified Concordium.Crypto.SHA256 as H
import Concordium.ID.Types
import Concordium.Types.HashableTo (HashableTo, MHashableTo, getHash)

import qualified Data.Aeson as AE
import qualified Data.Aeson.Encoding as AE

newtype ArInfo = ArInfo (ForeignPtr ArInfo)

foreign import ccall unsafe "&ar_info_free" freeArInfo :: FunPtr (Ptr ArInfo -> IO ())
foreign import ccall safe "ar_info_to_bytes" arInfoToBytes :: Ptr ArInfo -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall safe "ar_info_from_bytes" arInfoFromBytes :: Ptr Word8 -> CSize -> IO (Ptr ArInfo)
foreign import ccall safe "ar_info_to_json" arInfoToJSONFFI :: Ptr ArInfo -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall safe "ar_info_from_json" arInfoFromJSONFFI :: Ptr Word8 -> CSize -> IO (Ptr ArInfo)
foreign import ccall unsafe "ar_info_ar_identity" arIdentityFFI :: Ptr ArInfo -> IO ArIdentity
foreign import ccall unsafe "ar_info_name" arNameFFI :: Ptr ArInfo -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "ar_info_url" arUrlFFI :: Ptr ArInfo -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "ar_info_description" arDescriptionFFI :: Ptr ArInfo -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "ar_info_public_key" arPublicKeyFFI :: Ptr ArInfo -> Ptr CSize -> IO (Ptr Word8)

withArInfo :: ArInfo -> (Ptr ArInfo -> IO b) -> IO b
withArInfo (ArInfo fp) = withForeignPtr fp

-- This instance is different from the Rust one, it puts the length information up front.
-- The binary serialization of anonymity revokers is not used anywhere on the rust side,
-- and it is only used for
--   - block state storage
--   - genesis block
-- on the Haskell side.
instance Serialize ArInfo where
    get = do
        v <- getWord32be
        bs <- getByteString (fromIntegral v)
        case fromBytesHelper freeArInfo arInfoFromBytes bs of
            Nothing -> fail "Cannot decode ArInfo."
            Just x -> return (ArInfo x)

    put (ArInfo e) =
        let bs = toBytesHelper arInfoToBytes e
        in  putWord32be (fromIntegral (BS.length bs)) <> putByteString bs

-- NB: This Eq instance should only be used for testing. It is not guaranteed
-- to be semantically meaningful.
instance Eq ArInfo where
    (ArInfo e1) == (ArInfo e2) = tob e1 == tob e2
      where
        tob = toBytesHelper arInfoToBytes

-- Show instance uses the JSON instance to pretty print the structure.
instance Show ArInfo where
    show = BS8.unpack . arInfoToJSON

instance HashableTo H.Hash ArInfo where
    getHash = H.hash . encode

instance Monad m => MHashableTo m H.Hash ArInfo

jsonToArInfo :: BS.ByteString -> Maybe ArInfo
jsonToArInfo bs = ArInfo <$> fromJSONHelper freeArInfo arInfoFromJSONFFI bs

arInfoToJSON :: ArInfo -> BS.ByteString
arInfoToJSON (ArInfo ar) = toJSONHelper arInfoToJSONFFI ar

arIdentity :: ArInfo -> ArIdentity
arIdentity arInfo = unsafeDupablePerformIO $ withArInfo arInfo arIdentityFFI

-- |Get the description name of the AR.
--  Using Text.decodeUtf8 which can throw an exception,
--  but the AR name is represented as a String in Rust, so it is safe.
arName :: ArInfo -> Text
arName (ArInfo ar) = Text.decodeUtf8 $ toBytesHelper arNameFFI ar

-- |Get the description URL of the AR.
--  Using Text.decodeUtf8 which can throw an exception,
--  but the AR URL is represented as a String in Rust, so it is safe.
arUrl :: ArInfo -> Text
arUrl (ArInfo ar) = Text.decodeUtf8 $ toBytesHelper arUrlFFI ar

-- |Get the description string of the AR.
--  Using Text.decodeUtf8 which can throw an exception,
--  but the AR description is represented as a String in Rust, so it is safe.
arDescription :: ArInfo -> Text
arDescription (ArInfo ar) = Text.decodeUtf8 $ toBytesHelper arDescriptionFFI ar

-- |Get the public key of the AR as bytes.
--  The function is currently only used for returning protobuf data in the gRPC2 api.
--  That is why it returns bytes instead of structured data.
arPublicKey :: ArInfo -> BS.ByteString
arPublicKey (ArInfo ar) = toBytesHelper arPublicKeyFFI ar

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
    toEncoding = AE.unsafeToEncoding . BB.fromByteString . arInfoToJSON

-- Instances for benchmarking
instance NFData ArInfo where
    rnf = (`seq` ())
