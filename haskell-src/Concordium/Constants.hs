{-# LANGUAGE GADTs #-}

-- |
--  Module      : Concordium.Contants
--  Description : Constants for serialization, various limits, etc.
module Concordium.Constants where

import Concordium.Types.ProtocolVersion
import Data.Word

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
maxPayloadSize SP5 = maxPayloadSize SP4
maxPayloadSize SP6 = maxPayloadSize SP4

-- * Web assembly related constants

-- |Maximum length of the parameter to init and receive methods.
-- The limit was changed from `1024` to `65535` in P5.
maxParameterLen :: SProtocolVersion pv -> Word16
maxParameterLen SP1 = 1024
maxParameterLen SP2 = 1024
maxParameterLen SP3 = 1024
maxParameterLen SP4 = 1024
maxParameterLen SP5 = 65535
maxParameterLen SP6 = 65535

-- |Whether the number of logs and size of return values should be limited.
-- The limits have been removed in P5 and onward.
limitLogsAndReturnValues :: SProtocolVersion pv -> Bool
limitLogsAndReturnValues SP1 = True
limitLogsAndReturnValues SP2 = True
limitLogsAndReturnValues SP3 = True
limitLogsAndReturnValues SP4 = True
limitLogsAndReturnValues SP5 = False
limitLogsAndReturnValues SP6 = False

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
