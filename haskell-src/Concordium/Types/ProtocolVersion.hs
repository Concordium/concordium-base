{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE KindSignatures #-}

-- |This module contains the 'ProtocolVersion' datatype, which enumerates the
-- (supported) versions of the protocol for the consensus layer and up.
-- For the most part, 'ProtocolVersion' should be used at the kind level, and
-- its constructors promoted to types (as @'P1@).
--
-- In addition to 'ProtocolVersion' we define the GADT 'SProtocolVersion',
-- which is indexed by the protocol version.
-- i.e. @SProtocolVersion :: ProtocolVersion -> Type@. For each protocol version @pv@,
-- there is a singleton constructor of type @SProtocolVersion pv@, which is named
-- by prepending "S" to the protocol version constructor (e.g. @SP1 :: SProtocolVersion 'P1@).
--
-- The class 'IsProtocolVersion' identifies the singleton for each 'ProtocolVersion',
-- and should have an instance for each constructor of 'ProtocolVersion'.
module Concordium.Types.ProtocolVersion where

import Data.Serialize
import Data.Aeson
import Data.Aeson.Types
import Data.Word

-- |An enumeration of the supported versions of the consensus protocol.
-- Binary and JSON serializations are as Word64 corresponding to the protocol number.
data ProtocolVersion
    = P1
    | P2
    | P3
    | P4
    deriving (Eq, Show, Ord)

-- |The singleton type associated with 'ProtocolVersion'.
-- There is a unique constructor of 'SProtocolVersion' for
-- each constructor of 'ProtocolVersion'.
data SProtocolVersion (pv :: ProtocolVersion) where
    SP1 :: SProtocolVersion 'P1
    SP2 :: SProtocolVersion 'P2
    SP3 :: SProtocolVersion 'P3
    SP4 :: SProtocolVersion 'P4

protocolVersionToWord64 :: ProtocolVersion -> Word64
protocolVersionToWord64 P1 = 1
protocolVersionToWord64 P2 = 2
protocolVersionToWord64 P3 = 3
protocolVersionToWord64 P4 = 4

protocolVersionFromWord64 :: MonadFail m => Word64 -> m ProtocolVersion
protocolVersionFromWord64 1 = return P1
protocolVersionFromWord64 2 = return P2
protocolVersionFromWord64 3 = return P3
protocolVersionFromWord64 4 = return P4
protocolVersionFromWord64 v = fail $ "Unknown protocol version: " ++ show v

instance Serialize ProtocolVersion where
    put = putWord64be . protocolVersionToWord64
    get = protocolVersionFromWord64 =<< getWord64be

instance ToJSON ProtocolVersion where
  toJSON = toJSON . protocolVersionToWord64

instance FromJSON ProtocolVersion where
  parseJSON v = prependFailure "Protocol version" $ do
      x <- parseJSON v
      protocolVersionFromWord64 x


-- |Type class for relating type-level 'ProtocolVersion's with
-- term level 'SProtocolVersion's.
class IsProtocolVersion (pv :: ProtocolVersion) where
    -- |The singleton associated with the protocol version.
    protocolVersion :: SProtocolVersion pv

instance IsProtocolVersion 'P1 where
    protocolVersion = SP1
    {-# INLINE protocolVersion #-}

instance IsProtocolVersion 'P2 where
    protocolVersion = SP2
    {-# INLINE protocolVersion #-}

instance IsProtocolVersion 'P3 where
    protocolVersion = SP3
    {-# INLINE protocolVersion #-}

instance IsProtocolVersion 'P4 where
    protocolVersion = SP4
    {-# INLINE protocolVersion #-}

-- |Demote an 'SProtocolVersion' to a 'ProtocolVersion'.
demoteProtocolVersion :: SProtocolVersion pv -> ProtocolVersion
demoteProtocolVersion SP1 = P1
demoteProtocolVersion SP2 = P2
demoteProtocolVersion SP3 = P3
demoteProtocolVersion SP4 = P4

-- |An existentially quantified protocol version.
data SomeProtocolVersion where
    SomeProtocolVersion :: (IsProtocolVersion pv) => SProtocolVersion pv -> SomeProtocolVersion

-- |Promote a 'ProtocolVersion' to an 'SProtocolVersion'. This is wrapped in the existential
-- type 'SomeProtocolVersion'.
promoteProtocolVersion :: ProtocolVersion -> SomeProtocolVersion
promoteProtocolVersion P1 = SomeProtocolVersion SP1
promoteProtocolVersion P2 = SomeProtocolVersion SP2
promoteProtocolVersion P3 = SomeProtocolVersion SP3
promoteProtocolVersion P4 = SomeProtocolVersion SP4
