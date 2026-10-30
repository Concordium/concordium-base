{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

-- | Types associated with protocol-level locks.
module Concordium.Types.Locks where

import Control.Monad (guard)
import qualified Data.Aeson as AE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.Serialize as S
import Data.Word

import Data.Base58Encoding
import qualified Data.ULEB128 as ULEB128

-- | Lock identifier: a trio of numbers that together uniquely identify a lock.
data LockId = LockId
    { liAccountIndex :: !Word64,
      liSequenceNumber :: !Word64,
      liCreationOrder :: !Word64
    }
    deriving (Eq)

instance Show LockId where
    show = BS8.unpack . lockIdToBytes

instance Read LockId where
    readsPrec _ s = case lockIdFromBytes (BS8.pack s) of
        Just lockId -> [(lockId, "")]
        Nothing -> []

instance AE.ToJSON LockId where
    toJSON LockId{..} =
        AE.object
            [ "accountIndex" AE..= liAccountIndex,
              "sequenceNumber" AE..= liSequenceNumber,
              "creationOrder" AE..= liCreationOrder
            ]

instance AE.FromJSON LockId where
    parseJSON = AE.withObject "LockId" $ \o -> do
        liAccountIndex <- o AE..: "accountIndex"
        liSequenceNumber <- o AE..: "sequenceNumber"
        liCreationOrder <- o AE..: "creationOrder"
        return LockId{..}

instance S.Serialize LockId where
    put LockId{..} = do
        S.putWord64be liAccountIndex
        S.putWord64be liSequenceNumber
        S.putWord64be liCreationOrder
    get = do
        liAccountIndex <- S.getWord64be
        liSequenceNumber <- S.getWord64be
        liCreationOrder <- S.getWord64be
        return LockId{..}

lockIdVersion :: Word8
lockIdVersion = 3

lockIdToBytes :: LockId -> BS.ByteString
lockIdToBytes LockId{..} =
    raw . base58CheckEncode . BS.cons lockIdVersion $
        ULEB128.encode liAccountIndex
            <> ULEB128.encode liSequenceNumber
            <> ULEB128.encode liCreationOrder

lockIdFromBytes :: BS.ByteString -> Maybe LockId
lockIdFromBytes bs = do
    decoded <- base58CheckDecode' bs
    (version, payload) <- BS.uncons decoded
    guard (version == lockIdVersion)
    (liAccountIndex, payload1) <- ULEB128.decode payload
    (liSequenceNumber, payload2) <- ULEB128.decode payload1
    (liCreationOrder, payload3) <- ULEB128.decode payload2
    guard (BS.null payload3)
    return LockId{..}
