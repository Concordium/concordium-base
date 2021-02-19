{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE ImplicitParams #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE RankNTypes #-}
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

import Data.Singletons.TH

$( singletons
    [d|
        data ProtocolVersion = P0
        |]
 )

type OT4 = 'P0

class IsProtocolVersion (pv :: ProtocolVersion) where
    protocolVersion :: SProtocolVersion pv
    default protocolVersion :: SingI pv => SProtocolVersion pv
    protocolVersion = sing

instance IsProtocolVersion 'P0

withIsProtocolVersion :: forall (pv :: ProtocolVersion) a. (IsProtocolVersion pv) => (SProtocolVersion pv -> a pv) -> a pv
withIsProtocolVersion = ($ protocolVersion)

-- |Constraint for an implicit parameter identifying the protocol version
type PVer pv = (?pVer :: SProtocolVersion pv)

withPVer :: PVer pv => (SProtocolVersion pv -> a) -> a
withPVer = ($ ?pVer)

letPVer :: SProtocolVersion pv -> (PVer pv => a) -> a
letPVer pv a = let ?pVer = pv in a
