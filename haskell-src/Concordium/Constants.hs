{-# LANGUAGE GADTs #-}
{-|
  Module      : Concordium.Contants
  Description : Constants for serialization, various limits, etc.
-}
module Concordium.Constants where

import Data.Word
import Concordium.Types.ProtocolVersion

-- |Maximum number of incoming encrypted amounts on an account before we start
-- aggregating the oldest one.
maxNumIncoming :: Int
maxNumIncoming = 32

-- |Maximum size of a transaction payload allowed by each protocol version.
-- NB: This must accommodate all payload types valid in that protocol version.
maxPayloadSize :: SProtocolVersion pv -> Word32
maxPayloadSize SP1 = 100 * 1024 -- 100kB
maxPayloadSize SP2 = 100 * 1024 -- 100kB
maxPayloadSize SP3 = 100 * 1024 -- 100kB
maxPayloadSize SP4 = maxWasmModuleSizeV1 + 1 + 4 + 4 -- +1 for the payload tag, +4 for the length, +4 for the module version

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

