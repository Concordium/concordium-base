{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
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

-- |An enumeration of the supported versions of the consensus protocol.
data ProtocolVersion
    = P1 
    | P2
    deriving (Eq, Show)

-- |The singleton type associated with 'ProtocolVersion'.
-- There is a unique constructor of 'SProtocolVersion' for
-- each constructor of 'ProtocolVersion'.
data SProtocolVersion (pv :: ProtocolVersion) where
    SP1 :: SProtocolVersion 'P1
    SP2 :: SProtocolVersion 'P2

instance Serialize ProtocolVersion where
    put P1 = putWord64be 1
    put P2 = putWord64be 2
    get =
        getWord64be >>= \case
            1 -> return P1
            2 -> return P2
            v -> fail $ "Unknown protocol version: " ++ show v

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

-- |Demote an 'SProtocolVersion' to a 'ProtocolVersion'.
demoteProtocolVersion :: SProtocolVersion pv -> ProtocolVersion
demoteProtocolVersion SP1 = P1
demoteProtocolVersion SP2 = P2

-- |An existentially quantified protocol version.
data SomeProtocolVersion where
    SomeProtocolVersion :: (IsProtocolVersion pv) => SProtocolVersion pv -> SomeProtocolVersion

-- |Promote a 'ProtocolVersion' to an 'SProtocolVersion'. This is wrapped in the existential
-- type 'SomeProtocolVersion'.
promoteProtocolVersion :: ProtocolVersion -> SomeProtocolVersion
promoteProtocolVersion P1 = SomeProtocolVersion SP1
promoteProtocolVersion P2 = SomeProtocolVersion SP2