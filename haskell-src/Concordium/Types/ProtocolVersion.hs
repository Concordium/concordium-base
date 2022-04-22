{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

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

import Data.Aeson
import Data.Aeson.Types
import Data.Serialize
import Data.Word
import GHC.TypeNats

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

type family PVNat (pv :: ProtocolVersion) :: Nat where
    PVNat 'P1 = 1
    PVNat 'P2 = 2
    PVNat 'P3 = 3
    PVNat 'P4 = 4

type SupportsDelegation pv = 4 <= PVNat pv

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
class
    ( IsChainParametersVersion (ChainParametersVersionFor pv),
      IsAccountVersion (AccountVersionFor pv)
    ) =>
    IsProtocolVersion (pv :: ProtocolVersion)
    where
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

data ChainParametersVersion = ChainParametersV0 | ChainParametersV1
    deriving (Eq, Show)

type family ChainParametersVersionFor (pv :: ProtocolVersion) :: ChainParametersVersion where
    ChainParametersVersionFor 'P1 = 'ChainParametersV0
    ChainParametersVersionFor 'P2 = 'ChainParametersV0
    ChainParametersVersionFor 'P3 = 'ChainParametersV0
    ChainParametersVersionFor 'P4 = 'ChainParametersV1

data SChainParametersVersion (cpv :: ChainParametersVersion) where
    SCPV0 :: SChainParametersVersion 'ChainParametersV0
    SCPV1 :: SChainParametersVersion 'ChainParametersV1

-- |Type class for relating type-level 'ChainParametersVersion's with
-- term level 'SChainParameters's.
class IsChainParametersVersion (cpv :: ChainParametersVersion) where
    -- |The singleton associated with the protocol version.
    chainParametersVersion :: SChainParametersVersion cpv

instance IsChainParametersVersion 'ChainParametersV0 where
    chainParametersVersion = SCPV0
    {-# INLINE chainParametersVersion #-}

instance IsChainParametersVersion 'ChainParametersV1 where
    chainParametersVersion = SCPV1
    {-# INLINE chainParametersVersion #-}

chainParametersVersionFor :: SProtocolVersion pv -> SChainParametersVersion (ChainParametersVersionFor pv)
chainParametersVersionFor spv = case spv of
    SP1 -> SCPV0
    SP2 -> SCPV0
    SP3 -> SCPV0
    SP4 -> SCPV1

demoteChainParameterVersion :: SChainParametersVersion pv -> ChainParametersVersion
demoteChainParameterVersion SCPV0 = ChainParametersV0
demoteChainParameterVersion SCPV1 = ChainParametersV1
-- * Account versions

-- |A data kind used for parametrising account-related types.
-- This is used rather than 'ProtocolVersion' to coalesce cases where different protocol versions
-- share the same account format.
data AccountVersion
    = -- |Account version used in P1, P2, and P3.
      AccountV0
    | -- |Account version used in P4. Adds stake delegation.
      AccountV1

-- |A singleton type corresponding to 'SAccountVersion'.
data SAccountVersion (av :: AccountVersion) where
    SAccountV0 :: SAccountVersion 'AccountV0
    SAccountV1 :: SAccountVersion 'AccountV1

-- |Projection of 'ProtocolVersion' to 'AccountVersion'.
type family AccountVersionFor (pv :: ProtocolVersion) :: AccountVersion where
    AccountVersionFor 'P1 = 'AccountV0
    AccountVersionFor 'P2 = 'AccountV0
    AccountVersionFor 'P3 = 'AccountV0
    AccountVersionFor 'P4 = 'AccountV1

-- |Projection of 'SProtocolVersion' to 'SAccountVersion'.
accountVersionFor :: SProtocolVersion pv -> SAccountVersion (AccountVersionFor pv)
accountVersionFor SP1 = SAccountV0
accountVersionFor SP2 = SAccountV0
accountVersionFor SP3 = SAccountV0
accountVersionFor SP4 = SAccountV1

class IsAccountVersion (av :: AccountVersion) where
    -- |The singleton associated with the account version
    accountVersion :: SAccountVersion av

instance IsAccountVersion 'AccountV0 where
    accountVersion = SAccountV0

instance IsAccountVersion 'AccountV1 where
    accountVersion = SAccountV1

-- |Whether the protocol version supports memo functionality.
-- (Memos are supported in 'P2' onwards.)
supportsMemo :: SProtocolVersion pv -> Bool
supportsMemo SP1 = False
supportsMemo _ = True

-- |Whether the protocol version supports stake delegation functionality.
-- (Delegation is supported in 'P4' onwards.)
supportsDelegation :: SProtocolVersion pv -> Bool
supportsDelegation SP1 = False
supportsDelegation SP2 = False
supportsDelegation SP3 = False
supportsDelegation SP4 = True

-- |Whether the protocol version supports V1 smart contracts.
-- (V1 contracts are supported in 'P4' onwards.)
supportsV1Contracts :: SProtocolVersion pv -> Bool
supportsV1Contracts SP1 = False
supportsV1Contracts SP2 = False
supportsV1Contracts SP3 = False
supportsV1Contracts SP4 = True