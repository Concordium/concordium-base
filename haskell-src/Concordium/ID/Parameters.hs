module Concordium.ID.Parameters (GlobalContext, globalContextToJSON, jsonToGlobalContext, withGlobalContext, dummyGlobalContext)
where

import Concordium.Crypto.FFIHelpers

import Control.DeepSeq
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BSL
import Data.Serialize
import Data.Word
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Ptr

import qualified Data.Aeson as AE
import System.IO.Unsafe

-- |Cryptographic parameters needed to verify on-chain proofs, e.g.,
-- group parameters (generators), commitment keys, in the future also
-- common reference strings, etc.
newtype GlobalContext = GlobalContext (ForeignPtr GlobalContext)

foreign import ccall unsafe "&global_context_free" freeGlobalContext :: FunPtr (Ptr GlobalContext -> IO ())
foreign import ccall unsafe "dummy_generate_global_context" dummyGenerateGlobalContextPtr :: IO (Ptr GlobalContext)
foreign import ccall safe "global_context_to_bytes" globalContextToBytes :: Ptr GlobalContext -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall safe "global_context_from_bytes" globalContextFromBytes :: Ptr Word8 -> CSize -> IO (Ptr GlobalContext)
foreign import ccall safe "global_context_to_json" globalContextToJSONFFI :: Ptr GlobalContext -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall safe "global_context_from_json" globalContextFromJSONFFI :: Ptr Word8 -> CSize -> IO (Ptr GlobalContext)

withGlobalContext :: GlobalContext -> (Ptr GlobalContext -> IO b) -> IO b
withGlobalContext (GlobalContext fp) = withForeignPtr fp

-- This instance is different from the Rust one, it puts the length information up front.
instance Serialize GlobalContext where
    get = do
        v <- getWord32be
        bs <- getByteString (fromIntegral v)
        case fromBytesHelper freeGlobalContext globalContextFromBytes bs of
            Nothing -> fail "Cannot decode GlobalContext."
            Just x -> return (GlobalContext x)

    put (GlobalContext e) =
        let bs = toBytesHelper globalContextToBytes e
        in  putWord32be (fromIntegral (BS.length bs)) <> putByteString bs

-- NB: This instance should only be used for testing. It is not guaranteed to be
-- semantically meaningful.
instance Eq GlobalContext where
    (GlobalContext e1) == (GlobalContext e2) = tob e1 == tob e2
      where
        tob = toBytesHelper globalContextToBytes

-- Show instance uses the JSON instance to pretty print the structure.
instance Show GlobalContext where
    show = BS8.unpack . globalContextToJSON

jsonToGlobalContext :: BS.ByteString -> Maybe GlobalContext
jsonToGlobalContext bs = GlobalContext <$> fromJSONHelper freeGlobalContext globalContextFromJSONFFI bs

globalContextToJSON :: GlobalContext -> BS.ByteString
globalContextToJSON (GlobalContext ip) = toJSONHelper globalContextToJSONFFI ip

-- |Create a global context structure. This is a constant value, but quite expensive to generate.
{-# NOINLINE dummyGlobalContext #-}
{-# WARNING dummyGlobalContext "Do not use in production." #-}
dummyGlobalContext :: GlobalContext
dummyGlobalContext = GlobalContext $ unsafePerformIO (newForeignPtr freeGlobalContext =<< dummyGenerateGlobalContextPtr)

-- These JSON instances are very inefficient and should not be used in
-- performance critical contexts, however they are fine for loading
-- configuration data, or similar one-off uses.

instance AE.FromJSON GlobalContext where
    parseJSON v@(AE.Object _) =
        -- this is a terrible hack to avoid writing duplicate instances
        -- hack in the sense of performance
        case jsonToGlobalContext (BSL.toStrict (AE.encode v)) of
            Nothing -> fail "Could not decode GlobalContext."
            Just ipinfo -> return ipinfo
    parseJSON _ = fail "GlobalContext: Expected object."

instance AE.ToJSON GlobalContext where
    toJSON ipinfo =
        case AE.decodeStrict (globalContextToJSON ipinfo) of
            Nothing -> error "Internal error: Rust serialization does not produce valid JSON."
            Just v -> v

-- Instances for benchmarking
instance NFData GlobalContext where
    rnf = (`seq` ())
