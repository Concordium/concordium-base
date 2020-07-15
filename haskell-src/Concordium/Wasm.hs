{-# LANGUAGE DerivingVia #-}
module Concordium.Wasm where

import Data.Word
import Data.ByteString(ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Short(ShortByteString)
import qualified Data.ByteString.Short as BSS
import Data.Serialize
import qualified Data.Aeson as AE
import Data.Text(Text)
import qualified Data.Text.Encoding as Text

import Concordium.Crypto.ByteStringHelpers(ByteStringHex(..))
import qualified Concordium.Crypto.SHA256 as H

import Concordium.Types
import Concordium.Types.HashableTo

-- |Web assembly module in binary format.
data WasmModule = WasmModule {
  -- |Version of the Wasm standard and on-chain API this module corresponds to.
  wasmVersion :: Word32,
  -- |Source in binary wasm format.
  wasmSource :: ByteString
  } deriving(Eq, Show)

getModuleRef :: WasmModule -> ModuleRef
getModuleRef wm = ModuleRef (getHash wm)

-- |Name of an init method inside a module.
-- TODO: Naming scheme enforcement.
newtype InitName = InitName { initName :: Text }
    deriving(Eq, Show)
    deriving(AE.ToJSON, AE.FromJSON) via Text

-- |Name of a receive method inside a module.
-- TODO: Naming scheme enforcement.
newtype ReceiveName = ReceiveName { receiveName :: Text }
    deriving (Eq, Show)
    deriving(AE.ToJSON, AE.FromJSON) via Text

-- |Parameter to either an init method or to a receive method.
newtype Parameter = Parameter { parameter :: ShortByteString }
    deriving(Eq, Show)
    deriving(AE.ToJSON, AE.FromJSON) via ByteStringHex

instance Serialize WasmModule where
  put WasmModule{..} =
    putWord32be wasmVersion <>
    putByteStringWord32 wasmSource

  get = do
    wasmVersion <- getWord32be
    wasmSource <- getByteStringWord32
    return WasmModule{..}

instance HashableTo H.Hash WasmModule where
  -- Hash the serialization directly, perhaps this needs to be revisited in the future.
  getHash wm = H.hash (encode wm)

instance Serialize InitName where
  put = putByteStringWord32 . Text.encodeUtf8 . initName
  get = do
    bs <- getByteStringWord32
    case Text.decodeUtf8' bs of
      Left _ -> fail "Not a valid utf-8 encoding."
      Right t -> return (InitName t)

instance Serialize ReceiveName where
  put = putByteStringWord32 . Text.encodeUtf8 . receiveName
  get = do
    bs <- getByteStringWord32
    case Text.decodeUtf8' bs of
      Left _ -> fail "Not a valid utf-8 encoding."
      Right t -> return (ReceiveName t)

instance Serialize Parameter where
  put = putShortByteStringWord32 . parameter
  get = Parameter <$> getShortByteStringWord32

-- |Get a bytestring with length serialized as big-endian 4 bytes.
getByteStringWord32 :: Get ByteString
getByteStringWord32 = do
  len <- fromIntegral <$> getWord32be
  getByteString len

-- |Put a bytestring with length serialized as big-endian 4 bytes.
-- This function assumes the string length fits into 4 bytes.
putByteStringWord32 :: Putter ByteString
putByteStringWord32 bs =
  let len = fromIntegral (BS.length bs)
  in putWord32be len <> putByteString bs


-- |Get a bytestring with length serialized as big-endian 4 bytes.
getShortByteStringWord32 :: Get ShortByteString
getShortByteStringWord32 = do
  len <- fromIntegral <$> getWord32be
  getShortByteString len

-- |Put a bytestring with length serialized as big-endian 4 bytes.
-- This function assumes the string length fits into 4 bytes.
putShortByteStringWord32 :: Putter ShortByteString
putShortByteStringWord32 bs =
  let len = fromIntegral (BSS.length bs)
  in putWord32be len <> putShortByteString bs
