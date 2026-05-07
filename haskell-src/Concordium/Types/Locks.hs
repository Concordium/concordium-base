{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

-- | Types associated with protocol-level locks.
module Concordium.Types.Locks where

import qualified Data.Aeson as AE
import qualified Data.Serialize as S
import Data.Word
import Text.ParserCombinators.ReadP

-- | Lock identifier: a trio of numbers that together uniquely identify a lock.
data LockId = LockId
    { liAccountIndex :: !Word64,
      liSequenceNumber :: !Word64,
      liCreationOrder :: !Word64
    }
    deriving (Eq)

instance Show LockId where
    show LockId{..} =
        "P"
            ++ show liAccountIndex
            ++ "L"
            ++ show liSequenceNumber
            ++ "T"
            ++ show liCreationOrder
            ++ "L"

instance Read LockId where
    readsPrec _ = readP_to_S $ do
        _ <- char 'P'
        liAccountIndex <- readS_to_P reads
        _ <- char 'L'
        liSequenceNumber <- readS_to_P reads
        _ <- char 'T'
        liCreationOrder <- readS_to_P reads
        _ <- char 'L'
        return LockId{..}

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
