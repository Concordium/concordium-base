{-|
  Module      : Concordium.Contants
  Description : Constants for serialization, various limits, etc.
-}
module Concordium.Constants where

import Data.Word

-- |Maximum number of incoming encrypted amounts on an account before we start
-- aggregating the oldest one.
maxNumIncoming :: Int
maxNumIncoming = 32

-- |Maximum size of a transaction payload.
-- NB: This must accommodate all payload types.
maxPayloadSize :: Word32
maxPayloadSize = 100 * 1024 -- 100kB

-- * Web assembly related constants

-- |Maximum length of the parameter to init and receive methods.
maxParameterLen :: Word16
maxParameterLen = 1024

-- |Maximum module size of a V0 module.
maxWasmModuleSizeV0 :: Word32
maxWasmModuleSizeV0 = 65536 -- 64kB

-- |Maximum module size of a V1 module.
maxWasmModuleSizeV1 :: Word32
maxWasmModuleSizeV1 = 8 * 65536 -- 512kB

-- |Maximum byte size of function names.
-- Must stay in sync with MAX_FUNC_NAME_SIZE from wasm-transform.
maxFuncNameSize :: Int
maxFuncNameSize = 100

