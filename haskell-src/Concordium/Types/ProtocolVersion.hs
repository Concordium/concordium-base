{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE StandaloneKindSignatures #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

-- |This module contains the 'ProtocolVersion' datatype, which enumerates the
-- (supported) versions of the protocol for the consensus layer and up.
-- For the most part, 'ProtocolVersion' should be used at the kind level, and
-- its constructors promoted to types (as @'P0@).
--
-- We use the Singletons library, which generates some boilerplate. In particular,
-- the type family 'SProtocolVersion', which is indexed by the protocol version.
-- i.e. @SProtocolVersion :: ProtocolVersion -> Type@. For each protocol version @pv@,
-- there is a singleton constructor of type @SProtocolVersion pv@, which is named
-- by prepending "S" to the protocol version constructor (e.g. @SP0 :: SProtocolVersion 'P0@).
--
-- The class 'IsProtocolVersion' is essentially a specialized version of the 'SingI' class,
-- and should have an instance for each constructor of 'ProtocolVersion'.
module Concordium.Types.ProtocolVersion where

import Data.Serialize
import Data.Singletons.TH

$( singletons
    [d|
        data ProtocolVersion
            = P0
            | P1
        |]
 )

type OT4 = 'P0

instance Serialize ProtocolVersion where
    put P0 = putWord64be 0
    put P1 = putWord64be 1
    get =
        getWord64be >>= \case
            0 -> return P0
            1 -> return P1
            v -> fail $ "Unknown protocol version: " ++ show v

class IsProtocolVersion (pv :: ProtocolVersion) where
    protocolVersion :: SProtocolVersion pv
    default protocolVersion :: SingI pv => SProtocolVersion pv
    protocolVersion = sing
    {-# INLINE protocolVersion #-}

instance IsProtocolVersion 'P0
instance IsProtocolVersion 'P1
