{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE StandaloneKindSignatures #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
-- We suppress redundant constraint warnings since GHC does not detect when a constraint is used
-- for pattern matching. (See: https://gitlab.haskell.org/ghc/ghc/-/issues/20896)
{-# OPTIONS_GHC -Wno-redundant-constraints #-}

-- Note. TH generated definitions are documented in the header of this module while the others are
-- documented where they are defined.

-- | __Overview__
--  This module contains definitions for the configurable parameters used on chain, i.e. the
--  'ChainParameters'. Chain parameters are versioned by 'ChainParametersVersion'. The
--  'ChainParametersVersion' are determined from the 'ProtocolVersion' by
--  'ChainParametersVersionFor'.
--
--  This module also defines the type 'ParameterType', that is used at the kind level for determining
--  which parameters are supported at each 'ChainParametersVersion' by 'IsSupported'. A number of
--  parameters a conditionally included on this basis (using 'OParam').
--
--  While the top level 'ChainParameters' structure is parametrised by the 'ChainParametersVersion',
--  substructures are parametrised by their own versions. For such versions (e.g.
--  'PoolParametersVersion') we define mappings from 'ChainParametersVersion'
--  ('poolParametersVersionFor', 'PoolParmetersVersionFor', 'sPoolParametersVersionFor').
--  Parametrising these structures by separate versions is generally useful to preserve the
--  independence of their versioning (i.e. they don't change every 'ChainParametersVersion').
--  Consequently, the case analysis needed for these structures is limited to the cases that make
--  distinctions.
--
--  __Usage patterns__
--
--  For version-dependent functions, it is typical to case on the singleton type when the return
--  type is parametrised by the version. For example:
--
--  > getPoolParameters :: forall ppv. SPoolParametersVersion ppv -> Get (PoolParameters' ppv)
--  > getPoolParameters = \case
--  >     SPoolParametersVersion0 -> PoolParametersV0 <$> get
--  >     SPoolParametersVersion1 -> PoolParametersV1 <$> get <*> get <*> get <*> get <*> get
--
--  If the function takes a GADT parameter (e.g. 'PoolParameters''), then casing on the constructors
--  of the GADT is typically sufficient, without involving the singleton type.
--
--  For type classes (and some functions), we instead use a constraint such as @'SingI' ppv@, which
--  is typically aliased as, e.g. @'IsPoolParametersVersion' ppv@. The @'SingI' a@ class has a member
--  @'sing' :: 'Sing' a@, where the 'Sing' type family gives the singleton type associated with its
--  parameter, e.g. @Sing PoolPoolParametersVersion = SPoolParametersVersion@.  This, therefore,
--  allows us to pass the singleton as (effectively) an implicit parameter.
--
--  When we have @sppv :: SPoolParametersVersion pvv@, but require a constraint
--  @IsPoolParametersVersion ppv@, we can use @'withSingI' sppv@ to satisfy the constraint.
--  This is effectively the opposite of @'sing' \@pvv@.
--
--  When we have @scpv :: SChainParametersVersion cpv@, but require a
--  @sppv :: SPoolParametersVersion (PoolParametersVersionFor cpv)@, we can use the function
--  'sPoolParametersVersionFor'.
--
--  For convenience, we combine these in one function:
--
--  > withIsPoolParametersVersionFor :: SChainParametersVersion cpv -> (IsPoolParametersVersion (PoolParametersVersionFor cpv) => a) -> a
--  > withIsPoolParametersVersionFor scpv = withSingI (sPoolParametersVersionFor scpv)
--
--  Typically, this will be invoked as @withIsPoolParmetersVersionFor (chainParameters \@cpv)@.
--  Where multiple constraints are required, 'withCPVConstraints' can be used.
--
--  Note that we typically do not use this pattern to get an
--  @SChainParametersVersion (ChainParametersVersionFor pv)@ when we have an @IsProtocolVersion pv@
--  constraint. This is because @IsChainParametersVersion (ChainParametersVersionFor pv)@ is a
--  superclass constraint on @IsProtocolVersion pv@.
module Concordium.Types.Parameters (
    CryptographicParameters,

    -- * Conditional parameters

    -- | Parameter types that are conditionally supported at different 'ChainParametersVersion's.
    ParameterType (..),
    -- | Singleton type corresponding to 'ParameterType'.
    SParameterType (..),
    -- | Whether a particular parameter is supported at a particular 'ChainParametersVersion'.
    isSupported,
    -- | Whether a particular parameter is supported at a particular 'ChainParametersVersion' (at
    --  the type level).
    IsSupported,
    -- | Whether a particular parameter is supported at a particular 'ChainParametersVersion' (on
    --  singletons).
    sIsSupported,
    -- | Type level constraint that is parameterized by a 'ParameterType'.
    IsParameterType,

    -- * Conditional type
    Conditionally (..),
    conditionally,
    conditionallyA,
    unconditionally,

    -- * Conditional parameter
    OParam (..),
    unOParam,
    supportedOParam,
    whenSupported,
    whenSupportedA,
    maybeWhenSupported,

    -- * Mint distribution

    -- | Versioning for the 'MintDistribution' parameters.
    --
    --    * 'MintDistributionVersion0' ('ChainParametersV0'): supports mint per slot.
    --    * 'MintDistributionVersion1' ('ChainParametersV1', 'ChainParametersV2'): does not support
    --      mint per slot.
    MintDistributionVersion (..),
    -- | A data parameterized by the 'MintDistributionVersion' that yields the actual minting distribution parameters.
    MintDistribution (..),
    -- | Singleton type associated with 'MintDistributionVersion'
    SMintDistributionVersion (..),
    -- | The mint distribution version for a chain parameters version.
    mintDistributionVersionFor,
    -- | The mint distribution version for a chain parameters version (types).
    MintDistributionVersionFor,
    -- | The mint distribution version for a chain parameters version (singletons).
    sMintDistributionVersionFor,
    -- | Constraint for mint distribution versions.
    IsMintDistributionVersion,
    -- | Helper function for providing the supplied action @a@ with the context 'IsMintDistributionVersion'.
    withIsMintDistributionVersionFor,
    -- | A constraint for indicating that the 'MintDistributionVersion' @mdv@ supports minting per slot.
    MintPerSlotSupported,
    -- | Whether a 'MintDistributionVersion' supports the mint-per-slot parameter.
    supportsMintPerSlot,
    -- | Whether a 'MintDistributionVersion' supports the mint-per-slot parameter (type level).
    SupportsMintPerSlot,
    -- | Whether a 'MintDistributionVersion' supports the mint-per-slot parameter (singletons).
    sSupportsMintPerSlot,
    -- | Typeclass for structures that contain a 'MintDistribution'.
    HasMintDistribution (..),

    -- * Transaction fee distribution
    TransactionFeeDistribution (..),
    -- | Typeclass for structures that contain a 'TransactionFeeDistribution'.
    HasTransactionFeeDistribution (..),

    -- * GAS rewards

    -- | Versioning for the 'GASRewards' parameters.
    --
    --  * 'GASRewardsVersion0' ('ChainParametersV0', 'ChainParametersV1'): supports GAS reward for
    --    including finalization proofs.
    --  * 'GASRewardsVersion1' ('ChainParametersV1'): does not support GAS reward for including
    --    finalization proofs.
    GASRewardsVersion (..),
    -- | Singleton type associated with 'GASRewardsVersion'.
    SGASRewardsVersion (..),
    -- | The GAS rewards version for a chain parameters version.
    gasRewardsVersionFor,
    -- | The GAS rewards version for a chain parameters version (types).
    GasRewardsVersionFor,
    -- | The GAS rewards version for a chain parameters version (singletons).
    sGasRewardsVersionFor,
    IsGASRewardsVersion,
    withIsGASRewardsVersionFor,
    -- | Whether a 'GASRewardsVersion' supports GAS rewards for finalization proofs.
    supportsGASFinalizationProof,
    -- | Whether a 'GASRewardsVersion' supports GAS rewards for finalization proofs (type level).
    SupportsGASFinalizationProof,
    -- | Whether a 'GASRewardsVersion' supports GAS rewards for finalization proofs (singletons).
    sSupportsGASFinalizationProof,
    withSupportsGASFinalizationProof,
    GASRewards (..),
    -- | Typeclass for structures that contain a 'GASRewards'.
    HasGASRewards (..),

    -- * Reward parameters
    RewardParameters (..),
    -- | Typeclass for structures that contain a 'RewardParameters'.
    HasRewardParameters (..),

    -- * Exchange rates
    ExchangeRates (..),
    makeExchangeRates,
    HasExchangeRates (..),

    -- * Cooldown parameters

    -- | Versioning for the 'CooldownParameters'' structure.
    --
    --  * 'CooldownParametersVersion0' ('ChainParametersV0'): baker cooldown specified in 'Epoch's.
    --  * 'CooldownParametersVersion1' ('ChainParametersV1', 'ChainParametersV2'): baker and
    --    delegator cooldowns specified in seconds.
    CooldownParametersVersion (..),
    -- | Singleton type associated with 'CooldownParametersVersion'.
    SCooldownParametersVersion (..),
    -- | The cooldown parameters version for a chain parameters version.
    cooldownParametersVersionFor,
    -- | The cooldown parameters version for a chain parameters version (types).
    CooldownParametersVersionFor,
    -- | The cooldown parameters version for a chain parameters version (singletons).
    sCooldownParametersVersionFor,
    IsCooldownParametersVersion,
    withIsCooldownParametersVersionFor,
    CooldownParameters' (..),
    CooldownParameters,
    cpBakerExtraCooldownEpochs,
    cpPoolOwnerCooldown,
    cpDelegatorCooldown,
    cpUnifiedCooldown,
    putCooldownParameters,
    getCooldownParameters,

    -- * Time parameters
    TimeParameters (..),
    -- | Typeclass for structures that contain a 'TimeParameters'.
    HasTimeParameters (..),
    putTimeParameters,
    getTimeParameters,

    -- * Commission ranges
    InclusiveRange (..),
    isInRange,
    closestInRange,
    CommissionRanges (..),
    -- | The range of allowed finalization commissions.
    finalizationCommissionRange,
    -- | The range of allowed baker commissions.
    bakingCommissionRange,
    -- | The range of allowed transaction commissions.
    transactionCommissionRange,
    maximumCommissionRates,

    -- * Pool parameters
    LeverageFactor (..),
    applyLeverageFactor,
    CapitalBound (..),
    -- | Versioning for the 'PoolParameters'' structure.
    --
    --  * 'PoolParametersVersion0' ('ChainParametersV0'): just the minimum stake for registering a
    --     baker
    --  * 'PoolParametersVersion1' ('ChainParametersV1', 'ChainParametersV2'):
    --
    --      - passive commission rates
    --      - bounds on pool commission rates
    --      - minimum baker equity capital
    --      - maximum fraction of total staked capital that a baker can have
    --      - leverage bound for a baker
    PoolParametersVersion (..),
    -- | Singleton type associated with 'PoolParametersVersion'.
    SPoolParametersVersion (..),
    -- | The pool parameters version associated with a chain parameters version.
    poolParametersVersionFor,
    -- | The pool parameters version associated with a chain parameters version (types).
    PoolParametersVersionFor,
    -- | The pool parameters version associated with a chain parameters version (singletons).
    sPoolParametersVersionFor,
    PoolParameters' (..),
    PoolParameters,
    IsPoolParametersVersion,
    withIsPoolParametersVersionFor,
    ppBakerStakeThreshold,
    ppPassiveCommissions,
    ppCommissionBounds,
    ppMinimumEquityCapital,
    ppCapitalBound,
    ppLeverageBound,
    putPoolParameters,
    getPoolParameters,

    -- * Timeout parameters
    TimeoutParameters (..),
    HasTimeoutParameters (..),

    -- * Consensus parameters

    -- | Versioning for the 'ConsensusParameters'' structure.
    --
    --  * 'ConsensusParametersVersion0' ('ChainParametersV0', 'ChainParametersV1'): election difficulty
    --  * 'ConsensusParametersVersion1' ('ChainParametersV2'):
    --
    --      - Timeout parameters
    --      - Minimum block time
    --      - Block energy limit
    ConsensusParametersVersion (..),
    -- | Singleton type associated with 'ConsensusParametersVersion'.
    SConsensusParametersVersion (..),
    -- | The consensus parameters version associated with a chain parameters version.
    consensusParametersVersionFor,
    -- | The consensus parameters version associated with a chain parameters version (types).
    ConsensusParametersVersionFor,
    -- | The consensus parameters version associated with a chain parameters version (singletons).
    sConsensusParametersVersionFor,
    IsConsensusParametersVersion,
    withIsConsensusParametersVersionFor,
    ConsensusParameters' (..),
    ConsensusParameters,
    cpElectionDifficulty,
    cpTimeoutParameters,
    cpMinBlockTime,
    cpBlockEnergyLimit,
    cpFinalizationCommitteeParameters,

    -- * Chain parameters
    withCPVConstraints,
    ChainParameters' (..),
    -- | Consensus parameters.
    cpConsensusParameters,
    -- | Exchange rates.
    cpExchangeRates,
    -- | Cooldown parameters.
    cpCooldownParameters,
    -- | Time parameters.
    cpTimeParameters,
    -- | LimitAccountCreation: the maximum number of accounts
    --  that may be created in one block.
    cpAccountCreationLimit,
    -- | Reward parameters.
    cpRewardParameters,
    -- | Foundation account index.
    cpFoundationAccount,
    -- | Parameters for baker pools. Prior to P4, this is just the minimum stake threshold
    --  for becoming a baker.
    cpPoolParameters,
    -- | Parameters for validator suspension. Available since P8.
    cpValidatorScoreParameters,
    EChainParameters (..),
    ChainParameters,
    putChainParameters,
    getChainParameters,

    -- * Finalization parameters
    FinalizationParameters (..),
    putFinalizationParametersGD3,
    getFinalizationParametersGD3,

    -- * Delegation helpers
    DelegationChainParameters (..),
    delegationChainParameters,

    -- * Finalization committee parameters
    FinalizationCommitteeParameters (..),
    -- | The number of bakers that are eligible for finalization committee before
    --  the 'fcpFinalizerRelativeStakeThreshold' takes effect.
    fcpMinFinalizers,
    -- | The maximum number of bakers allowed to be in the finalization committee.
    fcpMaxFinalizers,
    -- | Determining the staking threshold required for being eligible the finalization committee.
    --  The minimum amount required to join the finalization committee
    --  is given by @total staked ccd / fcpFinalizerRelativeStakeThreshold@
    fcpFinalizerRelativeStakeThreshold,
    -- | 'FinalizationCommitteeParameters' wrapped in an 'OParam'
    --  supporting ''PTFinalizationCommitteeParameters'.
    OFinalizationCommitteeParameters,

    -- * Validator score parameters
    ValidatorScoreParameters (..),
    vspMaxMissedRounds,

    -- * Authorizations version

    -- | Version of the authorizations structure.
    --
    --  * 'AuthorizationsVersion0' ('ChainParametersV0').
    --  * 'AuthorizationsVersion1' ('ChainParametersV1', 'ChainParametersV2'): add access structures
    --    for cooldown parameters and time parameters
    AuthorizationsVersion (..),
    -- | Singleton type associated with 'AuthorizationsVersion'.
    SAuthorizationsVersion (..),
    -- | The authorizations version associated with a chain parameters version.
    authorizationsVersionFor,
    -- | The authorizations version associated with a chain parameters version (types).
    AuthorizationsVersionFor,
    -- | The authorizations version associated with a chain parameters version (singletons).
    sAuthorizationsVersionFor,
    -- | The authorizations version associated with a protocol version.
    authorizationsVersionForPV,
    -- | The authorizations version associated with a protocol version (types).
    AuthorizationsVersionForPV,
    -- | The authorizations version associated with a protocol version (singletons).
    sAuthorizationsVersionForPV,
    IsAuthorizationsVersion,
    withIsAuthorizationsVersionFor,
    withIsAuthorizationsVersionForPV,
    -- | Whether cooldown parameters are updatable for an 'AuthorizationsVersion'.
    supportsCooldownParametersAccessStructure,
    -- | Whether cooldown parameters are updatable for an 'AuthorizationsVersion' (types).
    SupportsCooldownParametersAccessStructure,
    -- | Whether cooldown parameters are updatable for an 'AuthorizationsVersion' (singletons).
    sSupportsCooldownParametersAccessStructure,
    -- | Whether time parameters are supported for an 'AuthorizationsVersion'.
    supportsTimeParameters,
    -- | Whether time parameters are supported for an 'AuthorizationsVersion' (types).
    SupportsTimeParameters,
    -- | Whether time parameters are supported for an 'AuthorizationsVersion' (singletons).
    sSupportsTimeParameters,

    -- * Consensus version
    IsConsensusV0,
    IsConsensusV1,
    ConsensusVersion (..),
    consensusVersionFor,

    -- * Defunctionalisation symbols
    PTElectionDifficultySym0,
    PTTimeParametersSym0,
    PTMintPerSlotSym0,
    PTTimeoutParametersSym0,
    PTMinBlockTimeSym0,
    PTBlockEnergyLimitSym0,
    PTCooldownParametersAccessStructureSym0,
    PTFinalizationProofSym0,
    PTFinalizationCommitteeParametersSym0,
    PTValidatorScoreParametersSym0,
) where

import Control.Monad
import qualified Data.Aeson as AE
import Data.Aeson.Types
import Data.Bool.Singletons
import Data.Maybe
import Data.Ratio
import Data.Serialize
import Data.Singletons.TH
import Data.Word
import Lens.Micro.Platform
import Test.QuickCheck.Arbitrary
import Test.QuickCheck.Gen

import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.ID.Parameters
import Concordium.Types
import Concordium.Types.Conditionally
import Concordium.Types.HashableTo
import Concordium.Types.SeedState

-- | Chain cryptographic parameters.
type CryptographicParameters = GlobalContext

-- The Template Haskell below generates the quoted definitions (terms represented at the type level see e.g. ''MintDistributionVersion0) together with the singletons
-- and liftings to singletons. The module header is used to give the haddock documentation.
--
-- Example:
-- '$( singletons [d |
-- data Foo = Bar | Baz
-- supportsBar :: Foo -> Bool
-- supportsBar Bar = True
-- supportsBar Baz = False
-- @|])'
-- The splice then generates the following:
-- Basic type definition
-- data Foo = Bar | Baz
-- Singleton definition
-- data SFoo (f :: Foo) where
--     SBar :: SFoo 'Bar
--     SBaz :: SFoo 'Baz
-- Term level function
-- supportsBar :: Foo -> Bool
-- supportsBar Bar = True
-- supportsBar Baz = False
-- Type level function
-- SupportsBar :: SFoo -> 'Bool (note 'Bool is the lifted term Bool value)
-- SupportsBar SBar = 'True
-- SupportsBaz SBar = 'False
-- Term level function that takes a singleton instance of Foo.
-- sSupportsBar :: SFoo -> Bool
-- sSupportsBar SBar = True
-- sSupportsBar SBaz = False
-- Note that type level functions start with a capital letter while
-- the term level functions starts with a lowercase letter.
--
-- Note. We normally also define a constraint like:
-- type IsBarSupported (foo :: Foo) = SingI (SupportsBar foo)
-- as all features can be determined from the protocol version.
-- This is because the splice also generates SingI instances for the type level functions.
-- However instead of using the 'SingI Supports...' constraints in code we instead
-- define our own specialized definitions (as IsBarSupported) above.
-- Note. to use this at the term level one can use the 'sing' function in order to
-- obtain the singleton.
-- Example:
-- myFunction :: IsBarSupported foo => Bool
-- myFunction :: sSupportsBar (sing @foo)
-- This pattern (demoting from type level to term level) is called "reification" and the opposite can also
-- be done and is called "reflection" (promoting from term level to type level).
-- myFunction' :: Foo -> Bool
-- myFunction' f = case toSing f of
--     SomeSing SBar -> True
--     SomeSing SBaz -> False
--
-- The above documentation covers one of the two parts that the singletons
-- library provides, i.e. creating lifted data kinds and the functions
-- required for reflection (demoting type- to term level) and reification (promoting term- to type level).
-- This is supported via the 'SingKind' type class which the singletons library creates instances of via the splice.
-- The 'SingKind' type class exposes @fromSing :: Sing (a :: k) -> Demote k@ i.e. reflection and
-- @toSing :: Demote k -> SomeSing k@ (reification).
--
-- The second part that the singletons library provides is a way of
-- applying functions partially at the type level. It is here that the
-- defunctionalization symbols generated comes into the picture e.g. 'PTElectionDifficultySym0'.
-- This is required when one wants to create a higher order function at the type level,
-- i.e. a type level 'map' function (we would call such one Map, note the capital letter in the start).
-- One can then pass in the generated defunctionalization symbols instead of the
-- function that one are using for the mapping.
-- This is because at the type level functions must be fully applied, but as that is not
-- possible, then one can use the defunctionalization symbols which are the associated symbols for the function.
$( singletons
    [d|
        -- \|Mint distribution version.
        data MintDistributionVersion
            = MintDistributionVersion0 -- \^Supports mint-per-slot
            | MintDistributionVersion1 -- \^Mint rate is removed from mint distribution

        -- \|The mint distribution version for a chain parameters version.
        mintDistributionVersionFor :: ChainParametersVersion -> MintDistributionVersion
        mintDistributionVersionFor ChainParametersV0 = MintDistributionVersion0
        mintDistributionVersionFor ChainParametersV1 = MintDistributionVersion1
        mintDistributionVersionFor ChainParametersV2 = MintDistributionVersion1
        mintDistributionVersionFor ChainParametersV3 = MintDistributionVersion1

        -- \|Whether a 'MintDistributionVersion' supports the mint-per-slot parameter.
        supportsMintPerSlot :: MintDistributionVersion -> Bool
        supportsMintPerSlot MintDistributionVersion0 = True
        supportsMintPerSlot MintDistributionVersion1 = False

        -- \|GAS rewards version.
        data GASRewardsVersion
            = GASRewardsVersion0 -- \^Supports finalization GAS reward
            | GASRewardsVersion1 -- \^Removes finalization GAS reward

        -- \|The GAS rewards version for a chain parameters version.
        gasRewardsVersionFor :: ChainParametersVersion -> GASRewardsVersion
        gasRewardsVersionFor ChainParametersV0 = GASRewardsVersion0
        gasRewardsVersionFor ChainParametersV1 = GASRewardsVersion0
        gasRewardsVersionFor ChainParametersV2 = GASRewardsVersion1
        gasRewardsVersionFor ChainParametersV3 = GASRewardsVersion1

        -- \|Whether a 'GASRewardsVersion' supports GAS rewards for finalization proofs.
        supportsGASFinalizationProof :: GASRewardsVersion -> Bool
        supportsGASFinalizationProof GASRewardsVersion0 = True
        supportsGASFinalizationProof GASRewardsVersion1 = False

        -- \|Cooldown parameters version.
        data CooldownParametersVersion
            = CooldownParametersVersion0 -- \^Baker cooldown in epochs
            | CooldownParametersVersion1 -- \^Baker and delegator cooldowns in seconds

        -- \|The cooldown parameters version for a chain parameters version.
        cooldownParametersVersionFor :: ChainParametersVersion -> CooldownParametersVersion
        cooldownParametersVersionFor ChainParametersV0 = CooldownParametersVersion0
        cooldownParametersVersionFor ChainParametersV1 = CooldownParametersVersion1
        cooldownParametersVersionFor ChainParametersV2 = CooldownParametersVersion1
        cooldownParametersVersionFor ChainParametersV3 = CooldownParametersVersion1

        -- \|Pool parameters version.
        data PoolParametersVersion
            = PoolParametersVersion0 -- \^Minimum baker stake
            | PoolParametersVersion1 -- \^Pool commission rates, limits and bounds.

        -- \|The pool parameters version associated with a chain parameters version.
        poolParametersVersionFor :: ChainParametersVersion -> PoolParametersVersion
        poolParametersVersionFor ChainParametersV0 = PoolParametersVersion0
        poolParametersVersionFor ChainParametersV1 = PoolParametersVersion1
        poolParametersVersionFor ChainParametersV2 = PoolParametersVersion1
        poolParametersVersionFor ChainParametersV3 = PoolParametersVersion1

        -- \|Consensus parameters version.
        data ConsensusParametersVersion
            = ConsensusParametersVersion0 -- \^Election difficulty
            | ConsensusParametersVersion1 -- \^Timeout parameters, block energy limit, min block time

        -- \|The consensus parameters version associated with a chain parameters version.
        consensusParametersVersionFor :: ChainParametersVersion -> ConsensusParametersVersion
        consensusParametersVersionFor ChainParametersV0 = ConsensusParametersVersion0
        consensusParametersVersionFor ChainParametersV1 = ConsensusParametersVersion0
        consensusParametersVersionFor ChainParametersV2 = ConsensusParametersVersion1
        consensusParametersVersionFor ChainParametersV3 = ConsensusParametersVersion1

        -- \|Authorizations version.
        data AuthorizationsVersion
            = AuthorizationsVersion0 -- \^Initial set of authorizations
            | AuthorizationsVersion1 -- \^Adds cooldown parameters and time parameters

        -- \|The authorizations version associated with a chain parameters version.
        authorizationsVersionFor :: ChainParametersVersion -> AuthorizationsVersion
        authorizationsVersionFor ChainParametersV0 = AuthorizationsVersion0
        authorizationsVersionFor ChainParametersV1 = AuthorizationsVersion1
        authorizationsVersionFor ChainParametersV2 = AuthorizationsVersion1
        authorizationsVersionFor ChainParametersV3 = AuthorizationsVersion1

        -- \|The authorizations version associated with a protocol version.
        authorizationsVersionForPV :: ProtocolVersion -> AuthorizationsVersion
        authorizationsVersionForPV pv = authorizationsVersionFor (chainParametersVersionFor pv)

        -- \|Whether cooldown parameters are updatable for an 'AuthorizationsVersion'.
        supportsCooldownParametersAccessStructure :: AuthorizationsVersion -> Bool
        supportsCooldownParametersAccessStructure AuthorizationsVersion0 = False
        supportsCooldownParametersAccessStructure AuthorizationsVersion1 = True

        -- \|Whether time parameters are supported for an 'AuthorizationsVersion'.
        supportsTimeParameters :: AuthorizationsVersion -> Bool
        supportsTimeParameters AuthorizationsVersion0 = False
        supportsTimeParameters AuthorizationsVersion1 = True

        -- \|Parameter types that are conditionally supported at different 'ChainParametersVersion's.
        data ParameterType
            = -- \|Election difficulty (consensus parameter)
              PTElectionDifficulty
            | -- \|Time parameters
              PTTimeParameters
            | -- \|Mint rate per slot as part of mint distribution parameters
              PTMintPerSlot
            | -- \|Timeout parameters for V2 consensus (consensus parameter)
              PTTimeoutParameters
            | -- \|Minimum block time for V2 consensus (consensus parameter)
              PTMinBlockTime
            | -- \|Block energy limit for V2 consensus (consensus parameter)
              PTBlockEnergyLimit
            | -- \|Updatable cooldown parameters
              PTCooldownParametersAccessStructure
            | -- \|Finalization proof GAS rewards (GAS rewards parameter)
              PTFinalizationProof
            | -- Finalization committee selection for V2 consensus
              PTFinalizationCommitteeParameters
            | -- Maximal score a validator can reach before it gets suspended
              PTValidatorScoreParameters

        -- \|Whether a particular parameter is supported at a particular 'ChainParametersVersion'.
        isSupported :: ParameterType -> ChainParametersVersion -> Bool
        isSupported PTElectionDifficulty cpv = case consensusParametersVersionFor cpv of
            ConsensusParametersVersion0 -> True
            ConsensusParametersVersion1 -> False
        isSupported PTTimeParameters cpv = supportsTimeParameters (authorizationsVersionFor cpv)
        isSupported PTMintPerSlot cpv = supportsMintPerSlot (mintDistributionVersionFor cpv)
        isSupported PTTimeoutParameters cpv = case consensusParametersVersionFor cpv of
            ConsensusParametersVersion0 -> False
            ConsensusParametersVersion1 -> True
        isSupported PTMinBlockTime cpv = case consensusParametersVersionFor cpv of
            ConsensusParametersVersion0 -> False
            ConsensusParametersVersion1 -> True
        isSupported PTBlockEnergyLimit cpv = case consensusParametersVersionFor cpv of
            ConsensusParametersVersion0 -> False
            ConsensusParametersVersion1 -> True
        isSupported PTCooldownParametersAccessStructure cpv = supportsCooldownParametersAccessStructure (authorizationsVersionFor cpv)
        isSupported PTFinalizationProof ChainParametersV0 = True
        isSupported PTFinalizationProof ChainParametersV1 = True
        isSupported PTFinalizationProof ChainParametersV2 = False
        isSupported PTFinalizationProof ChainParametersV3 = False
        isSupported PTFinalizationCommitteeParameters ChainParametersV0 = False
        isSupported PTFinalizationCommitteeParameters ChainParametersV1 = False
        isSupported PTFinalizationCommitteeParameters ChainParametersV2 = True
        isSupported PTFinalizationCommitteeParameters ChainParametersV3 = True
        isSupported PTValidatorScoreParameters ChainParametersV0 = False
        isSupported PTValidatorScoreParameters ChainParametersV1 = False
        isSupported PTValidatorScoreParameters ChainParametersV2 = False
        isSupported PTValidatorScoreParameters ChainParametersV3 = True
        |]
 )

-- | Constraint on a type level 'ParameterType' that can be used to get a corresponding
--  'SParameterType'.
type IsParameterType (pt :: ParameterType) = SingI pt

-- | Constraint on a type level 'AuthorizationsVersion' that can be used to get a corresponding
--  'SAuthorizationsVersion'.
type IsAuthorizationsVersion (auv :: AuthorizationsVersion) = SingI auv

-- | Witness an 'IsAuthorizationsVersion' constraint using a 'SChainParametersVersion'.
--  Concretely this provices the action @a@ with the context 'IsAuthorizationsVersion (AuthorizationsVersionFor cpv)' via the
--  supplied 'ChainParametersVersion'.
withIsAuthorizationsVersionFor :: SChainParametersVersion cpv -> ((IsAuthorizationsVersion (AuthorizationsVersionFor cpv)) => a) -> a
withIsAuthorizationsVersionFor scpv = withSingI (sAuthorizationsVersionFor scpv)

-- | Witness an 'IsAuthorizationsVersion' constraint using a 'SProtocolVersion'.
--  Concretely this provices the action @a@ with the context 'IsAuthorizationsVersion (AuthorizationsVersionForPV pv)' via the
--  supplied 'ProtocolVersion'.
withIsAuthorizationsVersionForPV :: SProtocolVersion pv -> ((IsAuthorizationsVersion (AuthorizationsVersionForPV pv)) => a) -> a
withIsAuthorizationsVersionForPV spv = withSingI (sAuthorizationsVersionForPV spv)

-- | An @OParam pt cpv a@ is an @a@ if the parameter type @pt@ is supported at @cpv@, and @()@
--  otherwise.
--  This needs to be defined as its own type instead of being the alias @type OParam pt cpv = Conditionally (IsSupported pt cpv)@,
--  since 'IsSupported' is not injective then @pt@ and @cpv@ would become ambigious in the definition for 'unOParam'.
data OParam (pt :: ParameterType) (cpv :: ChainParametersVersion) a where
    NoParam :: (IsSupported pt cpv ~ 'False) => OParam pt cpv a
    SomeParam :: (IsSupported pt cpv ~ 'True) => !a -> OParam pt cpv a

-- | Unwrap the 'OParam' when the parameter is supported.
unOParam :: (IsSupported pt cpv ~ 'True) => OParam pt cpv a -> a
unOParam (SomeParam a) = a

-- | Lens for accessing the contents of an 'OParam' when the parameter is supported.
supportedOParam :: (IsSupported pt cpv ~ 'True) => Lens' (OParam pt cpv a) a
supportedOParam f (SomeParam a) = SomeParam <$> f a

instance Functor (OParam pt cpv) where
    fmap _ NoParam = NoParam
    fmap f (SomeParam v) = SomeParam (f v)

instance Foldable (OParam pt cpv) where
    foldr _ b NoParam = b
    foldr f b (SomeParam a) = f a b

    foldl _ b NoParam = b
    foldl f b (SomeParam a) = f b a

    foldMap _ NoParam = mempty
    foldMap f (SomeParam a) = f a

instance Traversable (OParam pt cpv) where
    traverse _ NoParam = pure NoParam
    traverse f (SomeParam a) = SomeParam <$> f a

instance (Eq a) => Eq (OParam pt cpv a) where
    NoParam == NoParam = True
    SomeParam a == SomeParam b = a == b

instance (Ord a) => Ord (OParam pt cpv a) where
    compare NoParam NoParam = EQ
    compare (SomeParam a) (SomeParam b) = compare a b

instance (Show a) => Show (OParam pt cpv a) where
    show NoParam = "<parameter type unsupported>"
    show (SomeParam a) = show a

instance (Serialize a, SingI pt, IsChainParametersVersion cpv) => Serialize (OParam pt cpv a) where
    put NoParam = return ()
    put (SomeParam a) = put a

    get = whenSupportedA get

-- | Perform an action conditionally on whether the parameter is supported in the relevant chain
--  parameters version (per 'sIsSupported'). The action is not performed if the parameter is not
--  supported.
whenSupportedA :: forall pt cpv f a. (Applicative f, SingI pt, IsChainParametersVersion cpv) => f a -> f (OParam pt cpv a)
whenSupportedA m = case sIsSupported (sing @pt) (chainParametersVersion @cpv) of
    SFalse -> pure NoParam
    STrue -> SomeParam <$> m

-- | Wrap a value in an 'OParam' depending on whether the parameter is supported.
whenSupported :: forall pt cpv a. (SingI pt, IsChainParametersVersion cpv) => a -> OParam pt cpv a
whenSupported v = case sIsSupported (sing @pt) (chainParametersVersion @cpv) of
    SFalse -> NoParam
    STrue -> SomeParam v

-- | Analogue of 'maybe' for 'OParam'.
maybeWhenSupported :: b -> (a -> b) -> OParam pt cpv a -> b
maybeWhenSupported b _ NoParam = b
maybeWhenSupported _ f (SomeParam a) = f a

-- * Mint distribution

-- | Constraint on a type level 'MintDistributionVersion' that can be used to get a corresponding
--  'SMintDistributionVersion'.
type IsMintDistributionVersion (mdv :: MintDistributionVersion) = SingI mdv

-- | Constraint on a type level 'MintDistributionVersion' that can be used to get a corresponding
--  'SupportsMintPerSlot mdv'.
type MintPerSlotSupported (mdv :: MintDistributionVersion) = SingI (SupportsMintPerSlot mdv)

-- | Witness a @SingI (SupportsMintPerSlot mdv)@ constraint using a 'SMintDistributionVersion mdv'.
--  Concretely this provides the passed in action @a@ with the context 'SupportsMintPerSlot mdv'.
--  This is useful with one has a 'MintDistributionVersion' at hand and @a@ is constrained by
--  'SupportsMintPerSlot mdv'.
withSupportsMintPerSlot :: SMintDistributionVersion mdv -> ((MintPerSlotSupported mdv) => a) -> a
withSupportsMintPerSlot smdv = withSingI (sSupportsMintPerSlot smdv)

-- | Witness an 'IsMintDistributionVersion' constraint for an 'SChainParametersVersion'.
--  Concretely this provides the passed in action @a@ with the context 'IsMintDistributionVersion (MintDistributionVersionFor cpv)'.
withIsMintDistributionVersionFor :: SChainParametersVersion cpv -> ((IsMintDistributionVersion (MintDistributionVersionFor cpv)) => a) -> a
withIsMintDistributionVersionFor scpv = withSingI (sMintDistributionVersionFor scpv)

-- | The minting rate and the distribution of newly-minted GTU
--  among bakers, finalizers, and the foundation account.
--  It must be the case that
--  @_mdBakingReward + _mdFinalizationReward <= 1@.
--  The remaining amount is the platform development charge.
data MintDistribution (mdv :: MintDistributionVersion) = MintDistribution
    { -- | Mint rate per slot
      _mdMintPerSlot :: !(Conditionally (SupportsMintPerSlot mdv) MintRate),
      -- | BakingRewMintFrac: the fraction allocated to baker rewards
      _mdBakingReward :: !AmountFraction,
      -- | FinRewMintFrac: the fraction allocated to finalization rewards
      _mdFinalizationReward :: !AmountFraction
    }
    deriving (Eq, Show)

-- Define 'HasMintDistribution' class with accessor lenses, and instance for 'MintDistribution'.
makeClassy ''MintDistribution

instance ToJSON (MintDistribution cpv) where
    toJSON MintDistribution{..} =
        object
            ( mintPerSlot
                ++ [ "bakingReward" AE..= _mdBakingReward,
                     "finalizationReward" AE..= _mdFinalizationReward
                   ]
            )
      where
        mintPerSlot = foldMap (\mintRate -> ["mintPerSlot" AE..= mintRate]) _mdMintPerSlot

instance (IsMintDistributionVersion mdv) => FromJSON (MintDistribution mdv) where
    parseJSON = withObject "MintDistribution" $ \v -> do
        _mdMintPerSlot <- conditionallyA (sSupportsMintPerSlot (sing @mdv)) (v .: "mintPerSlot")
        _mdBakingReward <- v .: "bakingReward"
        _mdFinalizationReward <- v .: "finalizationReward"
        unless (isJust (_mdBakingReward `addAmountFraction` _mdFinalizationReward)) $ fail "Amount fractions exceed 100%"
        return MintDistribution{..}

instance (IsMintDistributionVersion mdv) => Serialize (MintDistribution mdv) where
    put MintDistribution{..} = do
        withSupportsMintPerSlot (sing @mdv) (put _mdMintPerSlot)
        put _mdBakingReward
        put _mdFinalizationReward
    get = do
        _mdMintPerSlot <- withSupportsMintPerSlot (sing @mdv) get
        _mdBakingReward <- get
        _mdFinalizationReward <- get
        unless (isJust (_mdBakingReward `addAmountFraction` _mdFinalizationReward)) $ fail "Amount fractions exceed 100%"
        return MintDistribution{..}

instance (IsMintDistributionVersion mdv) => HashableTo Hash.Hash (MintDistribution mdv) where
    getHash = Hash.hash . encode

instance Arbitrary (MintDistribution 'MintDistributionVersion1) where
    arbitrary = do
        (x, y) <- arbitrary `suchThat` (\(x, y) -> isJust $ addAmountFraction x y)
        return $ MintDistribution CFalse x y

instance (Monad m, IsMintDistributionVersion mdv) => MHashableTo m Hash.Hash (MintDistribution mdv)

-- * Transaction fee distribution

-- | The distribution of block transaction fees among the block
--  baker, the GAS account, and the foundation account.  It
--  must be the case that @_tfdBaker + _tfdGASAccount <= 1@.
--  The remaining amount is the TransChargeFrac (paid to the
--  foundation account).
data TransactionFeeDistribution = TransactionFeeDistribution
    { -- | BakerTransFrac: the fraction allocated to the baker
      _tfdBaker :: !AmountFraction,
      -- | The fraction allocated to the GAS account
      _tfdGASAccount :: !AmountFraction
    }
    deriving (Eq, Show)

-- Define 'HasTransactionFeeDistribution' class with accessor lenses, and instance for 'TransactionFeeDistribution'.
makeClassy ''TransactionFeeDistribution

instance ToJSON TransactionFeeDistribution where
    toJSON TransactionFeeDistribution{..} =
        object
            [ "baker" AE..= _tfdBaker,
              "gasAccount" AE..= _tfdGASAccount
            ]
instance FromJSON TransactionFeeDistribution where
    parseJSON = withObject "TransactionFeeDistribution" $ \v -> do
        _tfdBaker <- v .: "baker"
        _tfdGASAccount <- v .: "gasAccount"
        unless (isJust (_tfdBaker `addAmountFraction` _tfdGASAccount)) $ fail "Transaction fee fractions exceed 100%"
        return TransactionFeeDistribution{..}

instance Serialize TransactionFeeDistribution where
    put TransactionFeeDistribution{..} = put _tfdBaker >> put _tfdGASAccount
    get = do
        _tfdBaker <- get
        _tfdGASAccount <- get
        unless (isJust (_tfdBaker `addAmountFraction` _tfdGASAccount)) $ fail "Transaction fee fractions exceed 100%"
        return TransactionFeeDistribution{..}

instance HashableTo Hash.Hash TransactionFeeDistribution where
    getHash = Hash.hash . encode

instance (Monad m) => MHashableTo m Hash.Hash TransactionFeeDistribution

-- * GAS rewards

-- | Constraint on a type level 'GASRewardsVersion' that can be used to get a corresponding
--  'SGASRewardsVersion'.
type IsGASRewardsVersion (grv :: GASRewardsVersion) = SingI grv

-- | Witness a @SingI (SupportsGASFinalizationProof grv)@ constraint using a 'SGASRewardsVersion grv'.
--  Concretely this provides the passed in action @a@ with the context 'SupportsGASFinalizationProof grv'.
withSupportsGASFinalizationProof :: SGASRewardsVersion grv -> ((SingI (SupportsGASFinalizationProof grv)) => a) -> a
withSupportsGASFinalizationProof sgrv = withSingI (sSupportsGASFinalizationProof sgrv)

-- | Witness an 'IsGASRewardsVersion' constraint for an 'SChainParametersVersion'.
--  Concretely this provides the passed in action @a@ with the context 'GasRewardsVersionFor (GasRewardsVersionFor cpv)'.
withIsGASRewardsVersionFor :: SChainParametersVersion cpv -> ((IsGASRewardsVersion (GasRewardsVersionFor cpv)) => a) -> a
withIsGASRewardsVersionFor scpv = withSingI (sGasRewardsVersionFor scpv)

-- | Parameters that determine the proportion of the GAS account that is paid to the baker (pool)
--  under various circumstances.
data GASRewards (grv :: GASRewardsVersion) = GASRewards
    { -- | BakerPrevTransFrac: fraction paid to baker
      _gasBaker :: !AmountFraction,
      -- | FeeAddFinalisationProof: fraction paid for including a
      --  finalization proof in a block.
      _gasFinalizationProof :: !(Conditionally (SupportsGASFinalizationProof grv) AmountFraction),
      -- | FeeAccountCreation: fraction paid for including each
      --  account creation transaction in a block.
      _gasAccountCreation :: !AmountFraction,
      -- | FeeUpdate: fraction paid for including an update
      --  transaction in a block.
      _gasChainUpdate :: !AmountFraction
    }
    deriving (Eq, Show)

-- Define 'HasGasRewards' class with accessor lenses, and instance for 'GasRewards'.
makeClassy ''GASRewards

instance AE.ToJSON (GASRewards cpv) where
    toJSON GASRewards{..} =
        object
            ( "baker"
                AE..= _gasBaker
                    : finalizationProof
                    ++ [ "accountCreation" AE..= _gasAccountCreation,
                         "chainUpdate" AE..= _gasChainUpdate
                       ]
            )
      where
        finalizationProof = foldMap (\finProof -> ["finalizationProof" AE..= finProof]) _gasFinalizationProof

instance (IsGASRewardsVersion grv) => AE.FromJSON (GASRewards grv) where
    parseJSON = withObject "RewardParameters" $ \v -> do
        _gasBaker <- v .: "baker"
        _gasFinalizationProof <-
            conditionallyA (sSupportsGASFinalizationProof (sing @grv)) $
                v .: "finalizationProof"
        _gasAccountCreation <- v .: "accountCreation"
        _gasChainUpdate <- v .: "chainUpdate"
        return GASRewards{..}

instance (IsGASRewardsVersion grv) => Serialize (GASRewards grv) where
    put GASRewards{..} = do
        put _gasBaker
        withSupportsGASFinalizationProof (sing @grv) $ put _gasFinalizationProof
        put _gasAccountCreation
        put _gasChainUpdate
    get = do
        _gasBaker <- get
        _gasFinalizationProof <- withSupportsGASFinalizationProof (sing @grv) get
        _gasAccountCreation <- get
        _gasChainUpdate <- get
        return GASRewards{..}

instance (IsGASRewardsVersion grv) => HashableTo Hash.Hash (GASRewards grv) where
    getHash = Hash.hash . encode

instance (Monad m, IsGASRewardsVersion grv) => MHashableTo m Hash.Hash (GASRewards grv)

-- * Reward parameters

-- | Parameters affecting rewards.
--  It must be that @rpBakingRewMintFrac + rpFinRewMintFrac < 1@
data RewardParameters (cpv :: ChainParametersVersion) = RewardParameters
    { -- | Distribution of newly-minted GTUs.
      _rpMintDistribution :: !(MintDistribution (MintDistributionVersionFor cpv)),
      -- | Distribution of transaction fees.
      _rpTransactionFeeDistribution :: !TransactionFeeDistribution,
      -- | Rewards paid from the GAS account.
      _rpGASRewards :: !(GASRewards (GasRewardsVersionFor cpv))
    }
    deriving (Eq, Show)

-- Define 'HasRewardParameters' class with accessor lenses, and instance for 'RewardParameters'.
makeClassy ''RewardParameters

instance (mdv ~ MintDistributionVersionFor cpv) => HasMintDistribution (RewardParameters cpv) mdv where
    mintDistribution = rpMintDistribution

instance HasTransactionFeeDistribution (RewardParameters cpv) where
    transactionFeeDistribution = rpTransactionFeeDistribution

instance (grv ~ GasRewardsVersionFor cpv) => HasGASRewards (RewardParameters cpv) grv where
    gASRewards = rpGASRewards

instance AE.ToJSON (RewardParameters cpv) where
    toJSON RewardParameters{..} =
        object
            [ "mintDistribution" AE..= _rpMintDistribution,
              "transactionFeeDistribution" AE..= _rpTransactionFeeDistribution,
              "gASRewards" AE..= _rpGASRewards
            ]

instance (IsChainParametersVersion cpv) => AE.FromJSON (RewardParameters cpv) where
    parseJSON = withObject "RewardParameters" $ \v -> do
        _rpMintDistribution <- withIsMintDistributionVersionFor (chainParametersVersion @cpv) $ v .: "mintDistribution"
        _rpTransactionFeeDistribution <- v .: "transactionFeeDistribution"
        _rpGASRewards <- withIsGASRewardsVersionFor (sing @cpv) $ v .: "gASRewards"
        return RewardParameters{..}

instance (IsChainParametersVersion cpv) => Serialize (RewardParameters cpv) where
    put RewardParameters{..} = do
        withIsMintDistributionVersionFor (chainParametersVersion @cpv) $ put _rpMintDistribution
        put _rpTransactionFeeDistribution
        withIsGASRewardsVersionFor (sing @cpv) $ put _rpGASRewards
    get = do
        _rpMintDistribution <- withIsMintDistributionVersionFor (chainParametersVersion @cpv) get
        _rpTransactionFeeDistribution <- get
        _rpGASRewards <- withIsGASRewardsVersionFor (sing @cpv) get
        return RewardParameters{..}

-- * Exchange rates

-- | Exchange rates that apply on the chain.
data ExchangeRates = ExchangeRates
    { -- | Euro:Energy rate.
      _erEuroPerEnergy :: !ExchangeRate,
      -- | uGTU:Euro rate.
      _erMicroGTUPerEuro :: !ExchangeRate,
      -- | uGTU:Energy rate.
      --  This is derived, but will be computed when the other
      --  rates are updated since it is more useful.
      _erEnergyRate :: !EnergyRate
    }
    deriving (Eq, Show)

instance Serialize ExchangeRates where
    put ExchangeRates{..} = do
        put _erEuroPerEnergy
        put _erMicroGTUPerEuro
    get = makeExchangeRates <$> get <*> get

-- | Construct an 'ExchangeRates' from the Euro:Energy and uGTU:Euro rates.
makeExchangeRates ::
    -- | Euro:Energy rate
    ExchangeRate ->
    -- | uGTU:Euro rate
    ExchangeRate ->
    ExchangeRates
makeExchangeRates _erEuroPerEnergy _erMicroGTUPerEuro = ExchangeRates{..}
  where
    _erEnergyRate = computeEnergyRate _erMicroGTUPerEuro _erEuroPerEnergy

-- | Lenses (and a getter) for accessing the 'ExchangeRates' fields.
--  Note that 'energyRate' is a getter, since it should not be updated directly, but only as a
--  result of changes to the 'euroPerEnergy' or 'microGTUPerEuro' updates.
class HasExchangeRates t where
    -- | Access the 'ExchangeRates' structure.
    exchangeRates :: Lens' t ExchangeRates

    -- | Access the Euro per energy rate.
    --  Updating this also affects the energy rate.
    euroPerEnergy :: Lens' t ExchangeRate
    euroPerEnergy = exchangeRates . lens _erEuroPerEnergy (\er epe -> er{_erEuroPerEnergy = epe, _erEnergyRate = computeEnergyRate (_erMicroGTUPerEuro er) epe})

    -- | Access the microGTU [microCCD] per Euro rate.
    --  Updating this also affects the energy rate.
    microGTUPerEuro :: Lens' t ExchangeRate
    microGTUPerEuro = exchangeRates . lens _erMicroGTUPerEuro (\er mgtupe -> er{_erMicroGTUPerEuro = mgtupe, _erEnergyRate = computeEnergyRate mgtupe (_erEuroPerEnergy er)})

    -- | Getter for the energy to GTU [CCD] rate.
    energyRate :: SimpleGetter t EnergyRate
    energyRate = exchangeRates . to _erEnergyRate

instance HasExchangeRates ExchangeRates where
    {-# INLINE exchangeRates #-}
    exchangeRates = id
    {-# INLINE euroPerEnergy #-}
    euroPerEnergy = lens _erEuroPerEnergy (\er epe -> er{_erEuroPerEnergy = epe, _erEnergyRate = computeEnergyRate (_erMicroGTUPerEuro er) epe})
    {-# INLINE microGTUPerEuro #-}
    microGTUPerEuro = lens _erMicroGTUPerEuro (\er mgtupe -> er{_erMicroGTUPerEuro = mgtupe, _erEnergyRate = computeEnergyRate mgtupe (_erEuroPerEnergy er)})
    {-# INLINE energyRate #-}
    energyRate = to _erEnergyRate

-- * Cooldown parameters

-- | Constraint on a type level 'CooldownParametersVersion' that can be used to get a corresponding
--  'SCooldownParametersVersion'.
type IsCooldownParametersVersion (cpv :: CooldownParametersVersion) = SingI cpv

-- | Witness an 'IsCooldownParametersVersion' constraint for an 'SChainParametersVersion'.
--  Concretely this provides the passed in action @a@ with the context 'IsCooldownParametersVersion (CooldownParametersVersionFor cpv)'.
withIsCooldownParametersVersionFor ::
    SChainParametersVersion cpv ->
    ((IsCooldownParametersVersion (CooldownParametersVersionFor cpv)) => a) ->
    a
withIsCooldownParametersVersionFor scpv = withSingI (sCooldownParametersVersionFor scpv)

-- | Version-indexed type of cooldown parameters.
--  This is a GADT to provide instances of 'Eq' and 'Show'.
data CooldownParameters' (cpv :: CooldownParametersVersion) where
    CooldownParametersV0 ::
        { -- | Number of additional epochs that bakers must cool down when
          --  removing stake. The cool-down will effectively be 2 epochs
          --  longer than this value, since at any given time, the bakers
          --  (and stakes) for the current and next epochs have already
          --  been determined.
          _cpBakerExtraCooldownEpochs :: Epoch
        } ->
        CooldownParameters' 'CooldownParametersVersion0
    CooldownParametersV1 ::
        { -- | Number of seconds that pool owners must cooldown
          --  when reducing their equity capital or closing the pool.
          _cpPoolOwnerCooldown :: !DurationSeconds,
          -- | Number of seconds that a delegator must cooldown
          --  when reducing their delegated stake.
          _cpDelegatorCooldown :: !DurationSeconds
        } ->
        CooldownParameters' 'CooldownParametersVersion1

-- | A convenience alias for 'CooldownParameters'' but parametrised by the 'ChainParametersVersion'.
type CooldownParameters (cpv :: ChainParametersVersion) = CooldownParameters' (CooldownParametersVersionFor cpv)

instance ToJSON (CooldownParameters' cpv) where
    toJSON CooldownParametersV0{..} =
        object
            [ "bakerCooldownEpochs" AE..= _cpBakerExtraCooldownEpochs
            ]
    toJSON CooldownParametersV1{..} =
        object
            [ "poolOwnerCooldown" AE..= _cpPoolOwnerCooldown,
              "delegatorCooldown" AE..= _cpDelegatorCooldown
            ]

parseCooldownParametersJSON ::
    forall cpv.
    (IsCooldownParametersVersion cpv) =>
    Value ->
    Parser (CooldownParameters' cpv)
parseCooldownParametersJSON = case sing @cpv of
    SCooldownParametersVersion0 -> withObject "CooldownParametersV0" $ \v -> CooldownParametersV0 <$> v .: "bakerCooldownEpochs"
    SCooldownParametersVersion1 -> withObject "CooldownParametersV1" $ \v ->
        CooldownParametersV1
            <$> v .: "poolOwnerCooldown"
            <*> v .: "delegatorCooldown"

instance (IsCooldownParametersVersion cpv) => FromJSON (CooldownParameters' cpv) where
    parseJSON = parseCooldownParametersJSON

-- | Lens for '_cpBakerExtraCooldownEpochs'
{-# INLINE cpBakerExtraCooldownEpochs #-}
cpBakerExtraCooldownEpochs ::
    Lens' (CooldownParameters' 'CooldownParametersVersion0) Epoch
cpBakerExtraCooldownEpochs =
    lens _cpBakerExtraCooldownEpochs (\cp x -> cp{_cpBakerExtraCooldownEpochs = x})

-- | Lens for '_cpPoolOwnerCooldown'
{-# INLINE cpPoolOwnerCooldown #-}
cpPoolOwnerCooldown ::
    Lens' (CooldownParameters' 'CooldownParametersVersion1) DurationSeconds
cpPoolOwnerCooldown =
    lens _cpPoolOwnerCooldown (\cp x -> cp{_cpPoolOwnerCooldown = x})

-- | Lens for '_cpDelegatorCooldown'
{-# INLINE cpDelegatorCooldown #-}
cpDelegatorCooldown ::
    Lens' (CooldownParameters' 'CooldownParametersVersion1) DurationSeconds
cpDelegatorCooldown =
    lens _cpDelegatorCooldown (\cp x -> cp{_cpDelegatorCooldown = x})

-- | Getter for the cooldown period that applies when the protocol version supports flexible
--  cooldowns. This is defined as the minimum of the pool owner and delegator cooldowns.
{-# INLINE cpUnifiedCooldown #-}
cpUnifiedCooldown :: SimpleGetter (CooldownParameters' 'CooldownParametersVersion1) DurationSeconds
cpUnifiedCooldown = to $ \cp -> min (_cpPoolOwnerCooldown cp) (_cpDelegatorCooldown cp)

deriving instance Eq (CooldownParameters' cpv)
deriving instance Show (CooldownParameters' cpv)

-- | Serialize 'CooldownParameters''.
putCooldownParameters :: Putter (CooldownParameters' cpv)
putCooldownParameters CooldownParametersV0{..} = do
    put _cpBakerExtraCooldownEpochs
putCooldownParameters CooldownParametersV1{..} = do
    put _cpPoolOwnerCooldown
    put _cpDelegatorCooldown

instance HashableTo Hash.Hash (CooldownParameters' cpv) where
    getHash = Hash.hash . runPut . putCooldownParameters

instance (Monad m) => MHashableTo m Hash.Hash (CooldownParameters' cpv)

-- | Deserialize 'CooldownParameters'' for a given version.
getCooldownParameters :: forall cpv. SCooldownParametersVersion cpv -> Get (CooldownParameters' cpv)
getCooldownParameters = \case
    SCooldownParametersVersion0 -> CooldownParametersV0 <$> get
    SCooldownParametersVersion1 -> CooldownParametersV1 <$> get <*> get

instance (IsCooldownParametersVersion cpv) => Serialize (CooldownParameters' cpv) where
    put = putCooldownParameters
    get = getCooldownParameters (sing @cpv)

-- * Time parameters

-- | The time parameters are introduced as of 'ChainParametersV1', and consist of the reward period
--  length and the mint rate per payday.  These are coupled as a change to either affects the
--  overall rate of minting.
data TimeParameters where
    -- | For 'ChainParametersV1', the time parameters are the reward period length and mint rate per
    --  payday.
    TimeParametersV1 ::
        { -- | Length of a reward period (a number of epochs).
          _tpRewardPeriodLength :: RewardPeriodLength,
          -- | Mint rate per payday (as a proportion of the extant supply).
          _tpMintPerPayday :: !MintRate
        } ->
        TimeParameters
    deriving (Eq, Show)

-- Define 'HasTimeParameters' class with accessor lenses, and instance for 'TimeParameters'.
makeClassy ''TimeParameters

instance (IsSupported 'PTTimeParameters cpv ~ 'True) => HasTimeParameters (OParam 'PTTimeParameters cpv TimeParameters) where
    timeParameters = supportedOParam

-- | Serialize 'TimeParameters'.
--  (This dispatches on the GADT, and so does not require @IsChainParameters cpv@.)
putTimeParameters :: Putter TimeParameters
putTimeParameters TimeParametersV1{..} = do
    put _tpRewardPeriodLength
    put _tpMintPerPayday

-- | Deserialize 'TimeParameters'.
getTimeParameters :: Get TimeParameters
getTimeParameters = TimeParametersV1 <$> get <*> get

instance Serialize TimeParameters where
    put = putTimeParameters
    get = getTimeParameters

instance ToJSON TimeParameters where
    toJSON TimeParametersV1{..} =
        object
            [ "rewardPeriodLength" AE..= _tpRewardPeriodLength,
              "mintPerPayday" AE..= _tpMintPerPayday
            ]

instance FromJSON TimeParameters where
    parseJSON = withObject "TimeParametersV1" $ \v ->
        TimeParametersV1 <$> v .: "rewardPeriodLength" <*> v .: "mintPerPayday"

-- | The 'HashableTo' instance for 'TimeParameters' is used in hashing the state for queued updates.
--  It is not necessary to include the version in the hash computation, as it is implicit from the
--  context.
instance HashableTo Hash.Hash TimeParameters where
    getHash = Hash.hash . runPut . putTimeParameters

instance (Monad m) => MHashableTo m Hash.Hash TimeParameters

-- | A range that includes both endpoints.
data InclusiveRange a = InclusiveRange {irMin :: !a, irMax :: !a}
    deriving (Eq, Show)

instance (ToJSON a) => ToJSON (InclusiveRange a) where
    toJSON InclusiveRange{..} =
        object
            [ "min" AE..= irMin,
              "max" AE..= irMax
            ]

instance (FromJSON a, Ord a) => FromJSON (InclusiveRange a) where
    parseJSON = withObject "InclusiveRange" $ \v -> do
        irMin <- v .: "min"
        irMax <- v .: "max"
        when (irMin > irMax) $ fail "Invalid interval. Left endpoint cannot be bigger than right endpoint."
        return InclusiveRange{..}

instance (Serialize a, Ord a) => Serialize (InclusiveRange a) where
    put InclusiveRange{..} = do
        put irMin
        put irMax
    get = do
        irMin <- get
        irMax <- get
        when (irMin > irMax) $ fail "Invalid interval. Left endpoint cannot be bigger than right endpoint."
        return InclusiveRange{..}

-- | Determine if a value is in a given 'InclusiveRange'.
isInRange :: (Ord a) => a -> InclusiveRange a -> Bool
isInRange v InclusiveRange{..} = irMin <= v && v <= irMax

-- | Determine the closest value to a target within the given 'InclusiveRange'.
closestInRange :: (Ord a) => a -> InclusiveRange a -> a
closestInRange v r
    | isInRange v r = v
    | v < irMin r = irMin r
    | otherwise = irMax r

-- | Ranges of allowed commission values that pools may choose from.
data CommissionRanges = CommissionRanges
    { -- | The range of allowed finalization commissions.
      _finalizationCommissionRange :: !(InclusiveRange AmountFraction),
      -- | The range of allowed baker commissions.
      _bakingCommissionRange :: !(InclusiveRange AmountFraction),
      -- | The range of allowed transaction commissions.
      _transactionCommissionRange :: !(InclusiveRange AmountFraction)
    }
    deriving (Eq, Show)

makeLenses ''CommissionRanges

instance Serialize CommissionRanges where
    put CommissionRanges{..} = do
        put _finalizationCommissionRange
        put _bakingCommissionRange
        put _transactionCommissionRange
    get = CommissionRanges <$> get <*> get <*> get

-- | Compute the maximum commission rates from commission ranges.
maximumCommissionRates :: CommissionRanges -> CommissionRates
maximumCommissionRates CommissionRanges{..} =
    CommissionRates
        { _finalizationCommission = irMax _finalizationCommissionRange,
          _bakingCommission = irMax _bakingCommissionRange,
          _transactionCommission = irMax _transactionCommissionRange
        }

-- | A leverage factor, which determines the maximum ratio of a baker's effective stake to its
--  equity capital. This is cannot be less than 1.
--  This is mostly a thin wrapper around @Ratio Word64@, except deserialization checks
--  that the denominator is non-zero and the value is at least 1.
newtype LeverageFactor = LeverageFactor {theLeverageFactor :: Ratio Word64}
    deriving newtype (Eq, Ord, Show, Num, Real, Fractional, RealFrac, ToJSON)

instance Serialize LeverageFactor where
    put (LeverageFactor l) = put (numerator l) >> put (denominator l)
    get = do
        num <- get
        den <- get
        when (den == 0) $ fail "0 denominator"
        when (gcd num den /= 1) $ fail "non-normalized ratio"
        when (den > num) $ fail "leverage factor < 1"
        return $ LeverageFactor $ num % den

instance FromJSON LeverageFactor where
    parseJSON v = do
        r <- parseJSON v
        when (r < 1) $ fail "leverage factor < 1"
        return $ LeverageFactor r

-- | Apply a leverage factor to a capital amount.
--  If the computed amount would be larger than the maximum amount, this returns 'maxBound'.
applyLeverageFactor :: LeverageFactor -> Amount -> Amount
applyLeverageFactor (LeverageFactor leverage) (Amount amt)
    | preAmount > toInteger (maxBound :: Amount) = maxBound
    | otherwise = fromInteger preAmount
  where
    preAmount = (toInteger (numerator leverage) * toInteger amt) `div` toInteger (denominator leverage)

-- | A bound on the relative share of the total staked capital that a baker can have as its stake.
--  This is required to be greater than 0.
newtype CapitalBound = CapitalBound {theCapitalBound :: AmountFraction}
    deriving newtype (Eq, Ord, Show, ToJSON)

instance Serialize CapitalBound where
    put = put . theCapitalBound
    get = do
        cb <- get
        when (cb == AmountFraction 0) $ fail "zero-valued capital bound"
        return $ CapitalBound cb

instance FromJSON CapitalBound where
    parseJSON v = do
        cb <- parseJSON v
        when (cb == AmountFraction 0) $ fail "zero-valued capital bound"
        return $ CapitalBound cb

deriving instance Eq PoolParametersVersion
deriving instance Show PoolParametersVersion

-- | Constraint on a type level 'PoolParametersVersion' that can be used to get a corresponding
--  'SPoolParametersVersion'.
type IsPoolParametersVersion (ppv :: PoolParametersVersion) = SingI ppv

-- | Witness an 'IsPoolParametersVersion' constraint for an 'SChainParametersVersion'.
--  Concretely this provides the passed in action @a@ with the context 'SupportsMintPerSlot (IsPoolParametersVersion (PoolParametersVersionFor cpv)'.
withIsPoolParametersVersionFor :: SChainParametersVersion cpv -> ((IsPoolParametersVersion (PoolParametersVersionFor cpv)) => a) -> a
withIsPoolParametersVersionFor scpv = withSingI (sPoolParametersVersionFor scpv)

-- | The 'PoolParameters' abstracts the parameters that affect baking pools. Prior to P4, there
--  is no concept of a baking pool as such, so the pool parameters are considered just to be the
--  baker stake threshold. From P4 onwards, a broader range of parameters is included.
data PoolParameters' (ppv :: PoolParametersVersion) where
    PoolParametersV0 ::
        { -- | Minimum threshold required for registering as a baker.
          _ppBakerStakeThreshold :: Amount
        } ->
        PoolParameters' 'PoolParametersVersion0
    PoolParametersV1 ::
        { -- | Commission rates charged for passive delegation.
          _ppPassiveCommissions :: !CommissionRates,
          -- | Bounds on the commission rates that may be charged by bakers.
          _ppCommissionBounds :: !CommissionRanges,
          -- | Minimum equity capital required for a new baker.
          _ppMinimumEquityCapital :: !Amount,
          -- | Maximum fraction of the total staked capital of that a new baker can have.
          _ppCapitalBound :: !CapitalBound,
          -- | The maximum leverage that a baker can have as a ratio of total stake
          --  to equity capital.
          _ppLeverageBound :: !LeverageFactor
        } ->
        PoolParameters' 'PoolParametersVersion1

-- | Convenience type for a 'PoolParameters'' parametrised by the 'ChainParametersVersion'.
type PoolParameters (cpv :: ChainParametersVersion) = PoolParameters' (PoolParametersVersionFor cpv)

instance ToJSON (PoolParameters' ppv) where
    toJSON PoolParametersV0{..} =
        object
            [ "minimumThresholdForBaking" AE..= _ppBakerStakeThreshold
            ]
    toJSON PoolParametersV1{..} =
        object
            [ "passiveFinalizationCommission" AE..= _finalizationCommission _ppPassiveCommissions,
              "passiveBakingCommission" AE..= _bakingCommission _ppPassiveCommissions,
              "passiveTransactionCommission" AE..= _transactionCommission _ppPassiveCommissions,
              "finalizationCommissionRange" AE..= _finalizationCommissionRange _ppCommissionBounds,
              "bakingCommissionRange" AE..= _bakingCommissionRange _ppCommissionBounds,
              "transactionCommissionRange" AE..= _transactionCommissionRange _ppCommissionBounds,
              "minimumEquityCapital" AE..= _ppMinimumEquityCapital,
              "capitalBound" AE..= _ppCapitalBound,
              "leverageBound" AE..= _ppLeverageBound
            ]

parsePoolParametersJSON :: SPoolParametersVersion ppv -> Value -> Parser (PoolParameters' ppv)
parsePoolParametersJSON = \case
    SPoolParametersVersion0 -> withObject "PoolParametersV0" $ \v -> PoolParametersV0 <$> v .: "minimumThresholdForBaking"
    SPoolParametersVersion1 -> withObject "PoolParametersV1" $ \v -> do
        _finalizationCommission <- v .: "passiveFinalizationCommission"
        _bakingCommission <- v .: "passiveBakingCommission"
        _transactionCommission <- v .: "passiveTransactionCommission"
        _finalizationCommissionRange <- v .: "finalizationCommissionRange"
        _bakingCommissionRange <- v .: "bakingCommissionRange"
        _transactionCommissionRange <- v .: "transactionCommissionRange"
        _ppMinimumEquityCapital <- v .: "minimumEquityCapital"
        _ppCapitalBound <- v .: "capitalBound"
        _ppLeverageBound <- v .: "leverageBound"
        let _ppPassiveCommissions = CommissionRates{..}
        let _ppCommissionBounds = CommissionRanges{..}
        return PoolParametersV1{..}

instance (IsPoolParametersVersion ppv) => FromJSON (PoolParameters' ppv) where
    parseJSON = parsePoolParametersJSON (sing @ppv)

-- | Lens for '_ppBakerStakeThreshold'
{-# INLINE ppBakerStakeThreshold #-}
ppBakerStakeThreshold ::
    Lens' (PoolParameters' 'PoolParametersVersion0) Amount
ppBakerStakeThreshold =
    lens _ppBakerStakeThreshold (\pp x -> pp{_ppBakerStakeThreshold = x})

-- | Lens for '_ppPassiveCommissions'
{-# INLINE ppPassiveCommissions #-}
ppPassiveCommissions ::
    Lens' (PoolParameters' 'PoolParametersVersion1) CommissionRates
ppPassiveCommissions =
    lens _ppPassiveCommissions (\pp x -> pp{_ppPassiveCommissions = x})

-- | Lens for '_ppCommissionBounds'
{-# INLINE ppCommissionBounds #-}
ppCommissionBounds ::
    Lens' (PoolParameters' 'PoolParametersVersion1) CommissionRanges
ppCommissionBounds =
    lens _ppCommissionBounds (\pp x -> pp{_ppCommissionBounds = x})

-- | Lens for '_ppMinimumEquityCapital'
{-# INLINE ppMinimumEquityCapital #-}
ppMinimumEquityCapital ::
    Lens' (PoolParameters' 'PoolParametersVersion1) Amount
ppMinimumEquityCapital =
    lens _ppMinimumEquityCapital (\pp x -> pp{_ppMinimumEquityCapital = x})

-- | Lens for '_ppCapitalBound'
{-# INLINE ppCapitalBound #-}
ppCapitalBound ::
    Lens' (PoolParameters' 'PoolParametersVersion1) CapitalBound
ppCapitalBound =
    lens _ppCapitalBound (\pp x -> pp{_ppCapitalBound = x})

-- | Lens for '_ppLeverageBound'
{-# INLINE ppLeverageBound #-}
ppLeverageBound ::
    Lens' (PoolParameters' 'PoolParametersVersion1) LeverageFactor
ppLeverageBound =
    lens _ppLeverageBound (\pp x -> pp{_ppLeverageBound = x})

-- | Serialize a 'PoolParameters''.
putPoolParameters :: Putter (PoolParameters' ppv)
putPoolParameters PoolParametersV0{..} = do
    put _ppBakerStakeThreshold
putPoolParameters PoolParametersV1{..} = do
    put _ppPassiveCommissions
    put _ppCommissionBounds
    put _ppMinimumEquityCapital
    put _ppCapitalBound
    put _ppLeverageBound

instance HashableTo Hash.Hash (PoolParameters' ppv) where
    getHash = Hash.hash . runPut . putPoolParameters

instance (Monad m) => MHashableTo m Hash.Hash (PoolParameters' ppv)

-- | Deserialize a 'PoolParameters'' at a given version.
getPoolParameters :: forall ppv. SPoolParametersVersion ppv -> Get (PoolParameters' ppv)
getPoolParameters = \case
    SPoolParametersVersion0 -> PoolParametersV0 <$> get
    SPoolParametersVersion1 -> PoolParametersV1 <$> get <*> get <*> get <*> get <*> get

instance (IsPoolParametersVersion ppv) => Serialize (PoolParameters' ppv) where
    put = putPoolParameters
    get = getPoolParameters sing

deriving instance Eq (PoolParameters' ppv)
deriving instance Show (PoolParameters' ppv)

-- * Timeout parameters

-- | Parameters controlling consensus timeouts for the consensus protocol version 2.
data TimeoutParameters = TimeoutParameters
    { -- | The base value for triggering a timeout.
      _tpTimeoutBase :: Duration,
      -- | Factor for increasing the timeout. Must be greater than 1.
      _tpTimeoutIncrease :: Ratio Word64,
      -- | Factor for decreasing the timeout. Must be between 0 and 1.
      _tpTimeoutDecrease :: Ratio Word64
    }
    deriving (Eq, Show)

-- Define 'HasTimeoutParameters' class with accessor lenses, and instance for 'TimeoutParameters'.
makeClassy ''TimeoutParameters

instance Serialize TimeoutParameters where
    put TimeoutParameters{..} = do
        put _tpTimeoutBase
        put (numerator _tpTimeoutIncrease)
        put (denominator _tpTimeoutIncrease)
        put (numerator _tpTimeoutDecrease)
        put (denominator _tpTimeoutDecrease)
    get = do
        _tpTimeoutBase <- get
        -- Get the timeout increase ratio.
        tiNum <- get
        tiDen <- get
        when (tiDen == 0) $ fail "timeoutIncrease denominator must be non zero."
        let _tpTimeoutIncrease = tiNum % tiDen
        unless (_tpTimeoutIncrease > 1) $ fail "timeoutIncrease must be greater than 1."
        unless (gcd tiNum tiDen == 1) $ fail "timeoutIncrease numerator and denominator are not coprime."
        -- Get the timeout decrease ratio.
        tdNum <- get
        tdDen <- get
        when (tdDen == 0) $ fail "timeoutDecrease denominator must be non zero."
        let _tpTimeoutDecrease = tdNum % tdDen
        unless (_tpTimeoutDecrease > 0) $ fail "timeoutDecrease must be greater than 0."
        unless (_tpTimeoutDecrease < 1) $ fail "timeoutDecrease must be less than 1."
        unless (gcd tiNum tiDen == 1) $ fail "timeoutDecrease numerator and denominator are not coprime."
        return TimeoutParameters{..}

instance ToJSON TimeoutParameters where
    toJSON TimeoutParameters{..} =
        object
            [ "timeoutBase" AE..= _tpTimeoutBase,
              "timeoutIncrease" AE..= _tpTimeoutIncrease,
              "timeoutDecrease" AE..= _tpTimeoutDecrease
            ]

instance FromJSON TimeoutParameters where
    parseJSON = withObject "TimeoutParameters" $ \o -> do
        _tpTimeoutBase <- o .: "timeoutBase"
        _tpTimeoutIncrease <- o .: "timeoutIncrease"
        unless (_tpTimeoutIncrease > 1) $ fail "timeoutIncrease must be greater than 1."
        let tiNum = numerator _tpTimeoutIncrease
            tiDen = denominator _tpTimeoutIncrease
        unless (gcd tiNum tiDen == 1) $ fail "timeoutIncrease numerator and denominator are not coprime."
        _tpTimeoutDecrease <- o .: "timeoutDecrease"
        unless (_tpTimeoutDecrease > 0) $ fail "timeoutDecrease must be greater than 0."
        unless (_tpTimeoutDecrease < 1) $ fail "timeoutDecrease must be less than 1."
        let tdNum = numerator _tpTimeoutDecrease
            tdDen = denominator _tpTimeoutDecrease
        unless (gcd tdNum tdDen == 1) $ fail "timeoutDecrease numerator and denominator are not coprime."
        return TimeoutParameters{..}

instance HashableTo Hash.Hash TimeoutParameters where
    getHash = Hash.hash . encode

instance (Monad m) => MHashableTo m Hash.Hash TimeoutParameters

-- * Finalization committee parameters for consensus v1.

-- | Finalization committee parameters
--  These parameters control which bakers are in the finalization committee.
--  '_fcpMinFinalizers' MUST be at least 1.
--  '_fcpMaxFinalizers' MUST be at least '_fcpMinFinalizers'.
data FinalizationCommitteeParameters = FinalizationCommitteeParameters
    { -- | Minimum number of bakers to include in the finalization committee before
      --  the '_fcpFinalizerRelativeStakeThreshold' takes effect.
      _fcpMinFinalizers :: !Word32,
      -- | Maximum number of bakers to include in the finalization committee.
      _fcpMaxFinalizers :: !Word32,
      -- | Determining the staking threshold required for being eligible the finalization committee.
      --  The required amount is given by @total stake in pools * _fcpFinalizerRelativeStakeThreshold@
      --  Accepted values are in the range [0,1].
      _fcpFinalizerRelativeStakeThreshold :: !PartsPerHundredThousands
    }
    deriving (Eq, Show)

-- Define 'HasFinalizationCommitteeParameters' class with accessor lenses, and instance for 'FinalizationCommitteeParameters'.
makeClassy ''FinalizationCommitteeParameters

-- | An instance for 'HasFinalizationCommitteeParameters' that automatically unwraps the @OParam 'PTFinalizationCommitteeParameters cpv 'FinalizationCommitteeParameters@
--  when @IsSupported 'PTFinalizationCommitteeParameters cpv ~ 'True@
instance (IsSupported 'PTFinalizationCommitteeParameters cpv ~ 'True) => HasFinalizationCommitteeParameters (OParam 'PTFinalizationCommitteeParameters cpv FinalizationCommitteeParameters) where
    finalizationCommitteeParameters = supportedOParam

instance Serialize FinalizationCommitteeParameters where
    put FinalizationCommitteeParameters{..} = do
        put _fcpMinFinalizers
        put _fcpMaxFinalizers
        put _fcpFinalizerRelativeStakeThreshold
    get = do
        _fcpMinFinalizers <- get
        unless (_fcpMinFinalizers > 0) $ fail "the minimum number of finalizers must be positive."
        _fcpMaxFinalizers <- get
        unless (_fcpMaxFinalizers >= _fcpMinFinalizers) $ fail "The maximum number of finalizers must be greater or equal than minimumFinalizers."
        _fcpFinalizerRelativeStakeThreshold <- get
        return FinalizationCommitteeParameters{..}

instance HashableTo Hash.Hash FinalizationCommitteeParameters where
    getHash = Hash.hash . encode

instance (Monad m) => MHashableTo m Hash.Hash FinalizationCommitteeParameters

instance ToJSON FinalizationCommitteeParameters where
    toJSON FinalizationCommitteeParameters{..} =
        object
            [ "maximumFinalizers" AE..= _fcpMinFinalizers,
              "minimumFinalizers" AE..= _fcpMaxFinalizers,
              "finalizerRelativeStakeThreshold" AE..= _fcpFinalizerRelativeStakeThreshold
            ]

instance FromJSON FinalizationCommitteeParameters where
    parseJSON = withObject "FinalizationCommitteeParameters" $ \o -> do
        _fcpMinFinalizers <- o .: "minimumFinalizers"
        unless (_fcpMinFinalizers > 0) $ fail "the minimum number of finalizers must be positive."
        _fcpMaxFinalizers <- o .: "maximumFinalizers"
        unless (_fcpMaxFinalizers >= _fcpMinFinalizers) $ fail "The maximum number of finalizers must be greater or equal than minimumFinalizers."
        _fcpFinalizerRelativeStakeThreshold <- o .: "finalizerRelativeStakeThreshold"
        return FinalizationCommitteeParameters{..}

-- | 'FinalizationCommitteeParameters', where supported by the protocol version.
type OFinalizationCommitteeParameters (pv :: ProtocolVersion) =
    OParam
        'PTFinalizationCommitteeParameters
        (ChainParametersVersionFor pv)
        FinalizationCommitteeParameters

-- * Validator score parameters

-- | Score specific parameters.
newtype ValidatorScoreParameters = ValidatorScoreParameters
    { -- | Maximal number of rounds a validator can miss before it gets suspended.
      _vspMaxMissedRounds :: Word64
    }
    deriving (Eq, Show)

makeLenses ''ValidatorScoreParameters

instance HashableTo Hash.Hash ValidatorScoreParameters where
    getHash = Hash.hash . encode

instance (Monad m) => MHashableTo m Hash.Hash ValidatorScoreParameters

instance Serialize ValidatorScoreParameters where
    put ValidatorScoreParameters{..} = do
        put _vspMaxMissedRounds
    get = do
        _vspMaxMissedRounds <- get
        return ValidatorScoreParameters{..}

instance ToJSON ValidatorScoreParameters where
    toJSON ValidatorScoreParameters{..} =
        object
            [ "maximumMissedRounds" AE..= _vspMaxMissedRounds
            ]

instance FromJSON ValidatorScoreParameters where
    parseJSON = withObject "ValidatorScoreParameters" $ \o -> do
        _vspMaxMissedRounds <- o .: "maximumMissedRounds"
        return ValidatorScoreParameters{..}

-- * Consensus parameters

-- | Constraint on a type level 'ConsensusParametersVersion' that can be used to get a corresponding
--  'SConsensusParametersVersion'.
type IsConsensusParametersVersion (cpv :: ConsensusParametersVersion) = SingI cpv

-- | Witness an 'IsConsensusParametersVersion' constraint for an 'SChainParametersVersion'.
--  Concretely this provides the passed in action @a@ with the context '(IsConsensusParametersVersion (ConsensusParametersVersionFor cpv)'.
withIsConsensusParametersVersionFor :: SChainParametersVersion cpv -> ((IsConsensusParametersVersion (ConsensusParametersVersionFor cpv)) => a) -> a
withIsConsensusParametersVersionFor scpv = withSingI (sConsensusParametersVersionFor scpv)

-- | Consensus-specific parameters.
data ConsensusParameters' (cpv :: ConsensusParametersVersion) where
    ConsensusParametersV0 ::
        { -- | Election difficulty parameter.
          _cpElectionDifficulty :: !ElectionDifficulty
        } ->
        ConsensusParameters' 'ConsensusParametersVersion0
    ConsensusParametersV1 ::
        { -- | Parameters controlling round timeouts.
          _cpTimeoutParameters :: !TimeoutParameters,
          -- | Minimum time interval between blocks.
          _cpMinBlockTime :: !Duration,
          -- | Maximum energy allowed per block.
          _cpBlockEnergyLimit :: !Energy
        } ->
        ConsensusParameters' 'ConsensusParametersVersion1

-- | Convenience type for a 'ConsensusParameters'' parametrised by the 'ChainParametersVersion'.
type ConsensusParameters (cpv :: ChainParametersVersion) =
    ConsensusParameters' (ConsensusParametersVersionFor cpv)

-- | Lens for '_cpElectionDifficulty'
--  This provides access to the election difficulty parameter of 'ConsensusParametersV0'
{-# INLINE cpElectionDifficulty #-}
cpElectionDifficulty ::
    Lens' (ConsensusParameters' 'ConsensusParametersVersion0) ElectionDifficulty
cpElectionDifficulty =
    lens _cpElectionDifficulty (\cp x -> cp{_cpElectionDifficulty = x})

-- | Lens for '_cpTimeoutParameters'
--  This provides access to the timeout parameters of 'ConsensusParametersV1'
{-# INLINE cpTimeoutParameters #-}
cpTimeoutParameters ::
    Lens' (ConsensusParameters' 'ConsensusParametersVersion1) TimeoutParameters
cpTimeoutParameters =
    lens _cpTimeoutParameters (\cp x -> cp{_cpTimeoutParameters = x})

-- | Lens for '_cpMinBlockTime'
--  This provides access to the minimum time between blocks of 'ConsensusParametersV1'
{-# INLINE cpMinBlockTime #-}
cpMinBlockTime ::
    Lens' (ConsensusParameters' 'ConsensusParametersVersion1) Duration
cpMinBlockTime =
    lens _cpMinBlockTime (\cp x -> cp{_cpMinBlockTime = x})

-- | Lens for '_cpBlockEnergyLimit'
--  This provides access to the block energy limit of 'ConsensusParametersV1'
{-# INLINE cpBlockEnergyLimit #-}
cpBlockEnergyLimit ::
    Lens' (ConsensusParameters' 'ConsensusParametersVersion1) Energy
cpBlockEnergyLimit =
    lens _cpBlockEnergyLimit (\cp x -> cp{_cpBlockEnergyLimit = x})

deriving instance Eq (ConsensusParameters' cpv)
deriving instance Show (ConsensusParameters' cpv)

instance (IsConsensusParametersVersion cpv) => Serialize (ConsensusParameters' cpv) where
    put ConsensusParametersV0{..} = put _cpElectionDifficulty
    put ConsensusParametersV1{..} = do
        put _cpTimeoutParameters
        put _cpMinBlockTime
        put _cpBlockEnergyLimit
    get = case sing @cpv of
        SConsensusParametersVersion0 -> ConsensusParametersV0 <$> get
        SConsensusParametersVersion1 -> do
            _cpTimeoutParameters <- get
            _cpMinBlockTime <- get
            _cpBlockEnergyLimit <- get
            return ConsensusParametersV1{..}

-- * Chain parameters

-- | Witness the constraints implied by an 'SChainParametersVersion'.
--  A function for obtaining an aggregated context of constraints implied by the chain parameters version.
--  This is useful when having the chain parameters at hand and an action @a@ requires the below constraints:
--  @IsAuthorizationsVersion@, @IsConsensusParametersVersion@, @IsCooldownParametersVersion@, @IsGASRewardsVersion@,
--  @IsMintDistributionVersion@ and @IsPoolParametersVersion@.
withCPVConstraints ::
    SChainParametersVersion cpv ->
    ( ( IsAuthorizationsVersion (AuthorizationsVersionFor cpv),
        IsConsensusParametersVersion (ConsensusParametersVersionFor cpv),
        IsCooldownParametersVersion (CooldownParametersVersionFor cpv),
        IsGASRewardsVersion (GasRewardsVersionFor cpv),
        IsMintDistributionVersion (MintDistributionVersionFor cpv),
        IsPoolParametersVersion (PoolParametersVersionFor cpv)
      ) =>
      a
    ) ->
    a
withCPVConstraints scpv a =
    withIsAuthorizationsVersionFor scpv $
        withIsConsensusParametersVersionFor scpv $
            withIsCooldownParametersVersionFor scpv $
                withIsGASRewardsVersionFor scpv $
                    withIsMintDistributionVersionFor scpv $
                        withIsPoolParametersVersionFor scpv a

-- | Updatable chain parameters.  This type is parametrised by a 'ChainParametersVersion' that
--  reflects changes to the chain parameters across different protocol versions.
data ChainParameters' (cpv :: ChainParametersVersion) = ChainParameters
    { -- | Consensus parameters.
      _cpConsensusParameters :: !(ConsensusParameters cpv),
      -- | Exchange rates.
      _cpExchangeRates :: !ExchangeRates,
      -- | Cooldown parameters.
      _cpCooldownParameters :: !(CooldownParameters cpv),
      -- | Time parameters.
      _cpTimeParameters :: !(OParam 'PTTimeParameters cpv TimeParameters),
      -- | LimitAccountCreation: the maximum number of accounts
      --  that may be created in one block.
      _cpAccountCreationLimit :: !CredentialsPerBlockLimit,
      -- | Reward parameters.
      _cpRewardParameters :: !(RewardParameters cpv),
      -- | Foundation account index.
      _cpFoundationAccount :: !AccountIndex,
      -- | Parameters for baker pools. Prior to P4, this is just the minimum stake threshold
      --  for becoming a baker.
      _cpPoolParameters :: !(PoolParameters cpv),
      -- | The finalization committee parameters.
      --  These parameters are introduced as part of protocol 6 (cpv2).
      --  The set of parameters shares the 'Authorization' with the '_cpPoolParameters'.
      _cpFinalizationCommitteeParameters :: !(OParam 'PTFinalizationCommitteeParameters cpv FinalizationCommitteeParameters),
      -- | The score parameters.
      --  These parameters are introduced as part of protocol 8 (cpv3).
      _cpValidatorScoreParameters :: !(OParam 'PTValidatorScoreParameters cpv ValidatorScoreParameters)
    }
    deriving (Eq, Show)

makeLenses ''ChainParameters'

-- | An existentially qualified chain parameters variant that is useful where we
--  need to return chain parameters in queries.
data EChainParameters = forall (cpv :: ChainParametersVersion). (IsChainParametersVersion cpv) => EChainParameters (ChainParameters' cpv)

-- | Chain parameters for a specific 'ProtocolVersion'.
type ChainParameters (pv :: ProtocolVersion) = ChainParameters' (ChainParametersVersionFor pv)

instance HasExchangeRates (ChainParameters' cpv) where
    {-# INLINE exchangeRates #-}
    exchangeRates = cpExchangeRates

instance HasRewardParameters (ChainParameters' cpv) cpv where
    rewardParameters = cpRewardParameters

-- | Serialize a 'ChainParameters''.
putChainParameters :: forall cpv. (IsChainParametersVersion cpv) => Putter (ChainParameters' cpv)
putChainParameters ChainParameters{..} = do
    withIsConsensusParametersVersionFor (chainParametersVersion @cpv) $ put _cpConsensusParameters
    put _cpExchangeRates
    putCooldownParameters _cpCooldownParameters
    put _cpTimeParameters
    put _cpAccountCreationLimit
    put _cpRewardParameters
    put _cpFoundationAccount
    putPoolParameters _cpPoolParameters
    put _cpFinalizationCommitteeParameters
    put _cpValidatorScoreParameters

-- | Deserialize a 'ChainParameters''.
getChainParameters :: forall cpv. (IsChainParametersVersion cpv) => Get (ChainParameters' cpv)
getChainParameters = do
    _cpConsensusParameters <- withIsConsensusParametersVersionFor (chainParametersVersion @cpv) get
    _cpExchangeRates <- get
    _cpCooldownParameters <- withIsCooldownParametersVersionFor (chainParametersVersion @cpv) get
    _cpTimeParameters <- get
    _cpAccountCreationLimit <- get
    _cpRewardParameters <- get
    _cpFoundationAccount <- get
    _cpPoolParameters <- withIsPoolParametersVersionFor (chainParametersVersion @cpv) get
    _cpFinalizationCommitteeParameters <- get
    _cpValidatorScoreParameters <- get
    return ChainParameters{..}

instance (IsChainParametersVersion cpv) => Serialize (ChainParameters' cpv) where
    put = putChainParameters
    get = getChainParameters

instance (IsChainParametersVersion cpv) => HashableTo Hash.Hash (ChainParameters' cpv) where
    getHash = Hash.hash . runPut . putChainParameters

instance (Monad m, IsChainParametersVersion cpv) => MHashableTo m Hash.Hash (ChainParameters' cpv)

parseJSONForCPV0 :: Value -> Parser (ChainParameters' 'ChainParametersV0)
parseJSONForCPV0 =
    withObject "ChainParameters" $ \v -> do
        _cpElectionDifficulty <- v .: "electionDifficulty"
        let _cpConsensusParameters = ConsensusParametersV0{..}
        _cpExchangeRates <-
            makeExchangeRates
                <$> v
                    .: "euroPerEnergy"
                <*> v
                    .: "microGTUPerEuro"
        _cpCooldownParameters <-
            CooldownParametersV0
                <$> v
                    .: "bakerCooldownEpochs"
        _cpAccountCreationLimit <- v .: "accountCreationLimit"
        _cpRewardParameters <- v .: "rewardParameters"
        _cpFoundationAccount <- v .: "foundationAccountIndex"
        _cpPoolParameters <-
            PoolParametersV0
                <$> v
                    .: "minimumThresholdForBaking"
        let _cpTimeParameters = NoParam
            _cpFinalizationCommitteeParameters = NoParam
            _cpValidatorScoreParameters = NoParam
        return ChainParameters{..}

parseJSONForCPV1 :: Value -> Parser (ChainParameters' 'ChainParametersV1)
parseJSONForCPV1 =
    withObject "ChainParametersV1" $ \v -> do
        _cpElectionDifficulty <- v .: "electionDifficulty"
        let _cpConsensusParameters = ConsensusParametersV0{..}
        _cpEuroPerEnergy <- v .: "euroPerEnergy"
        _cpMicroGTUPerEuro <- v .: "microGTUPerEuro"
        _cpPoolOwnerCooldown <- v .: "poolOwnerCooldown"
        _cpDelegatorCooldown <- v .: "delegatorCooldown"
        _cpAccountCreationLimit <- v .: "accountCreationLimit"
        _cpRewardParameters <- v .: "rewardParameters"
        _cpFoundationAccount <- v .: "foundationAccountIndex"
        _finalizationCommission <- v .: "passiveFinalizationCommission"
        _bakingCommission <- v .: "passiveBakingCommission"
        _transactionCommission <- v .: "passiveTransactionCommission"
        _finalizationCommissionRange <- v .: "finalizationCommissionRange"
        _bakingCommissionRange <- v .: "bakingCommissionRange"
        _transactionCommissionRange <- v .: "transactionCommissionRange"
        _ppMinimumEquityCapital <- v .: "minimumEquityCapital"
        _ppCapitalBound <- v .: "capitalBound"
        _ppLeverageBound <- v .: "leverageBound"
        _tpRewardPeriodLength <- v .: "rewardPeriodLength"
        _tpMintPerPayday <- v .: "mintPerPayday"
        let _cpCooldownParameters = CooldownParametersV1{..}
            _cpTimeParameters = SomeParam TimeParametersV1{..}
            _cpPoolParameters = PoolParametersV1{..}
            _cpExchangeRates = makeExchangeRates _cpEuroPerEnergy _cpMicroGTUPerEuro
            _ppPassiveCommissions = CommissionRates{..}
            _ppCommissionBounds = CommissionRanges{..}
            _cpFinalizationCommitteeParameters = NoParam
            _cpValidatorScoreParameters = NoParam
        return ChainParameters{..}

parseJSONForCPV2 :: Value -> Parser (ChainParameters' 'ChainParametersV2)
parseJSONForCPV2 =
    withObject "ChainParametersV2" $ \v -> do
        _cpEuroPerEnergy <- v .: "euroPerEnergy"
        _cpMicroGTUPerEuro <- v .: "microGTUPerEuro"
        _cpPoolOwnerCooldown <- v .: "poolOwnerCooldown"
        _cpDelegatorCooldown <- v .: "delegatorCooldown"
        _cpAccountCreationLimit <- v .: "accountCreationLimit"
        _cpRewardParameters <- v .: "rewardParameters"
        _cpFoundationAccount <- v .: "foundationAccountIndex"
        _finalizationCommission <- v .: "passiveFinalizationCommission"
        _bakingCommission <- v .: "passiveBakingCommission"
        _transactionCommission <- v .: "passiveTransactionCommission"
        _finalizationCommissionRange <- v .: "finalizationCommissionRange"
        _bakingCommissionRange <- v .: "bakingCommissionRange"
        _transactionCommissionRange <- v .: "transactionCommissionRange"
        _ppMinimumEquityCapital <- v .: "minimumEquityCapital"
        _ppCapitalBound <- v .: "capitalBound"
        _ppLeverageBound <- v .: "leverageBound"
        _tpRewardPeriodLength <- v .: "rewardPeriodLength"
        _tpMintPerPayday <- v .: "mintPerPayday"
        _tpTimeoutBase <- v .: "timeoutBase"
        _tpTimeoutIncrease <- v .: "timeoutIncrease"
        _tpTimeoutDecrease <- v .: "timeoutDecrease"
        let _cpTimeoutParameters = TimeoutParameters{..}
        _cpMinBlockTime <- v .: "minBlockTime"
        _cpBlockEnergyLimit <- v .: "blockEnergyLimit"
        _fcpMinFinalizers <- v .: "minimumFinalizers"
        _fcpMaxFinalizers <- v .: "maximumFinalizers"

        _fcpFinalizerRelativeStakeThreshold <- v .: "finalizerRelativeStakeThreshold"
        let _cpCooldownParameters = CooldownParametersV1{..}
            _cpTimeParameters = SomeParam TimeParametersV1{..}
            _cpPoolParameters = PoolParametersV1{..}
            _cpExchangeRates = makeExchangeRates _cpEuroPerEnergy _cpMicroGTUPerEuro
            _ppPassiveCommissions = CommissionRates{..}
            _ppCommissionBounds = CommissionRanges{..}
            _cpFinalizationCommitteeParameters = SomeParam FinalizationCommitteeParameters{..}
            _cpConsensusParameters = ConsensusParametersV1{..}
            _cpValidatorScoreParameters = NoParam
        return ChainParameters{..}

parseJSONForCPV3 :: Value -> Parser (ChainParameters' 'ChainParametersV3)
parseJSONForCPV3 =
    withObject "ChainParametersV3" $ \v -> do
        _cpEuroPerEnergy <- v .: "euroPerEnergy"
        _cpMicroGTUPerEuro <- v .: "microGTUPerEuro"
        _cpPoolOwnerCooldown <- v .: "poolOwnerCooldown"
        _cpDelegatorCooldown <- v .: "delegatorCooldown"
        _cpAccountCreationLimit <- v .: "accountCreationLimit"
        _cpRewardParameters <- v .: "rewardParameters"
        _cpFoundationAccount <- v .: "foundationAccountIndex"
        _finalizationCommission <- v .: "passiveFinalizationCommission"
        _bakingCommission <- v .: "passiveBakingCommission"
        _transactionCommission <- v .: "passiveTransactionCommission"
        _finalizationCommissionRange <- v .: "finalizationCommissionRange"
        _bakingCommissionRange <- v .: "bakingCommissionRange"
        _transactionCommissionRange <- v .: "transactionCommissionRange"
        _ppMinimumEquityCapital <- v .: "minimumEquityCapital"
        _ppCapitalBound <- v .: "capitalBound"
        _ppLeverageBound <- v .: "leverageBound"
        _tpRewardPeriodLength <- v .: "rewardPeriodLength"
        _tpMintPerPayday <- v .: "mintPerPayday"
        _tpTimeoutBase <- v .: "timeoutBase"
        _tpTimeoutIncrease <- v .: "timeoutIncrease"
        _tpTimeoutDecrease <- v .: "timeoutDecrease"
        let _cpTimeoutParameters = TimeoutParameters{..}
        _cpMinBlockTime <- v .: "minBlockTime"
        _cpBlockEnergyLimit <- v .: "blockEnergyLimit"
        _fcpMinFinalizers <- v .: "minimumFinalizers"
        _fcpMaxFinalizers <- v .: "maximumFinalizers"

        _fcpFinalizerRelativeStakeThreshold <- v .: "finalizerRelativeStakeThreshold"
        let _cpCooldownParameters = CooldownParametersV1{..}
            _cpTimeParameters = SomeParam TimeParametersV1{..}
            _cpPoolParameters = PoolParametersV1{..}
            _cpExchangeRates = makeExchangeRates _cpEuroPerEnergy _cpMicroGTUPerEuro
            _ppPassiveCommissions = CommissionRates{..}
            _ppCommissionBounds = CommissionRanges{..}
            _cpFinalizationCommitteeParameters = SomeParam FinalizationCommitteeParameters{..}
            _cpConsensusParameters = ConsensusParametersV1{..}

        _vspMaxMissedRounds <- v .: "maximumMissedRounds"
        let _cpValidatorScoreParameters = SomeParam ValidatorScoreParameters{..}

        return ChainParameters{..}

instance forall cpv. (IsChainParametersVersion cpv) => FromJSON (ChainParameters' cpv) where
    parseJSON = case chainParametersVersion @cpv of
        SChainParametersV0 -> parseJSONForCPV0
        SChainParametersV1 -> parseJSONForCPV1
        SChainParametersV2 -> parseJSONForCPV2
        SChainParametersV3 -> parseJSONForCPV3

instance forall cpv. (IsChainParametersVersion cpv) => ToJSON (ChainParameters' cpv) where
    toJSON ChainParameters{..} = case chainParametersVersion @cpv of
        SChainParametersV0 ->
            object
                [ "electionDifficulty" AE..= _cpElectionDifficulty _cpConsensusParameters,
                  "euroPerEnergy" AE..= _erEuroPerEnergy _cpExchangeRates,
                  "microGTUPerEuro" AE..= _erMicroGTUPerEuro _cpExchangeRates,
                  "bakerCooldownEpochs" AE..= _cpBakerExtraCooldownEpochs _cpCooldownParameters,
                  "accountCreationLimit" AE..= _cpAccountCreationLimit,
                  "rewardParameters" AE..= _cpRewardParameters,
                  "foundationAccountIndex" AE..= _cpFoundationAccount,
                  "minimumThresholdForBaking" AE..= _ppBakerStakeThreshold _cpPoolParameters
                ]
        SChainParametersV1 ->
            object
                [ "electionDifficulty" AE..= _cpElectionDifficulty _cpConsensusParameters,
                  "euroPerEnergy" AE..= _erEuroPerEnergy _cpExchangeRates,
                  "microGTUPerEuro" AE..= _erMicroGTUPerEuro _cpExchangeRates,
                  "poolOwnerCooldown" AE..= _cpPoolOwnerCooldown _cpCooldownParameters,
                  "delegatorCooldown" AE..= _cpDelegatorCooldown _cpCooldownParameters,
                  "accountCreationLimit" AE..= _cpAccountCreationLimit,
                  "rewardParameters" AE..= _cpRewardParameters,
                  "foundationAccountIndex" AE..= _cpFoundationAccount,
                  "passiveFinalizationCommission" AE..= _finalizationCommission (_ppPassiveCommissions _cpPoolParameters),
                  "passiveBakingCommission" AE..= _bakingCommission (_ppPassiveCommissions _cpPoolParameters),
                  "passiveTransactionCommission" AE..= _transactionCommission (_ppPassiveCommissions _cpPoolParameters),
                  "finalizationCommissionRange" AE..= _finalizationCommissionRange (_ppCommissionBounds _cpPoolParameters),
                  "bakingCommissionRange" AE..= _bakingCommissionRange (_ppCommissionBounds _cpPoolParameters),
                  "transactionCommissionRange" AE..= _transactionCommissionRange (_ppCommissionBounds _cpPoolParameters),
                  "minimumEquityCapital" AE..= _ppMinimumEquityCapital _cpPoolParameters,
                  "capitalBound" AE..= _ppCapitalBound _cpPoolParameters,
                  "leverageBound" AE..= _ppLeverageBound _cpPoolParameters,
                  "rewardPeriodLength" AE..= _tpRewardPeriodLength (unOParam _cpTimeParameters),
                  "mintPerPayday" AE..= _tpMintPerPayday (unOParam _cpTimeParameters)
                ]
        SChainParametersV2 ->
            object
                [ "euroPerEnergy" AE..= _erEuroPerEnergy _cpExchangeRates,
                  "microGTUPerEuro" AE..= _erMicroGTUPerEuro _cpExchangeRates,
                  "poolOwnerCooldown" AE..= _cpPoolOwnerCooldown _cpCooldownParameters,
                  "delegatorCooldown" AE..= _cpDelegatorCooldown _cpCooldownParameters,
                  "accountCreationLimit" AE..= _cpAccountCreationLimit,
                  "rewardParameters" AE..= _cpRewardParameters,
                  "foundationAccountIndex" AE..= _cpFoundationAccount,
                  "passiveFinalizationCommission" AE..= _finalizationCommission (_ppPassiveCommissions _cpPoolParameters),
                  "passiveBakingCommission" AE..= _bakingCommission (_ppPassiveCommissions _cpPoolParameters),
                  "passiveTransactionCommission" AE..= _transactionCommission (_ppPassiveCommissions _cpPoolParameters),
                  "finalizationCommissionRange" AE..= _finalizationCommissionRange (_ppCommissionBounds _cpPoolParameters),
                  "bakingCommissionRange" AE..= _bakingCommissionRange (_ppCommissionBounds _cpPoolParameters),
                  "transactionCommissionRange" AE..= _transactionCommissionRange (_ppCommissionBounds _cpPoolParameters),
                  "minimumEquityCapital" AE..= _ppMinimumEquityCapital _cpPoolParameters,
                  "capitalBound" AE..= _ppCapitalBound _cpPoolParameters,
                  "leverageBound" AE..= _ppLeverageBound _cpPoolParameters,
                  "rewardPeriodLength" AE..= _tpRewardPeriodLength (unOParam _cpTimeParameters),
                  "mintPerPayday" AE..= _tpMintPerPayday (unOParam _cpTimeParameters),
                  "timeoutBase" AE..= _tpTimeoutBase (_cpTimeoutParameters _cpConsensusParameters),
                  "timeoutIncrease" AE..= _tpTimeoutIncrease (_cpTimeoutParameters _cpConsensusParameters),
                  "timeoutDecrease" AE..= _tpTimeoutDecrease (_cpTimeoutParameters _cpConsensusParameters),
                  "minBlockTime" AE..= _cpMinBlockTime _cpConsensusParameters,
                  "blockEnergyLimit" AE..= _cpBlockEnergyLimit _cpConsensusParameters,
                  "minimumFinalizers" AE..= _fcpMinFinalizers (unOParam _cpFinalizationCommitteeParameters),
                  "maximumFinalizers" AE..= _fcpMaxFinalizers (unOParam _cpFinalizationCommitteeParameters),
                  "finalizerRelativeStakeThreshold" AE..= _fcpFinalizerRelativeStakeThreshold (unOParam _cpFinalizationCommitteeParameters)
                ]
        SChainParametersV3 ->
            object
                [ "euroPerEnergy" AE..= _erEuroPerEnergy _cpExchangeRates,
                  "microGTUPerEuro" AE..= _erMicroGTUPerEuro _cpExchangeRates,
                  "poolOwnerCooldown" AE..= _cpPoolOwnerCooldown _cpCooldownParameters,
                  "delegatorCooldown" AE..= _cpDelegatorCooldown _cpCooldownParameters,
                  "accountCreationLimit" AE..= _cpAccountCreationLimit,
                  "rewardParameters" AE..= _cpRewardParameters,
                  "foundationAccountIndex" AE..= _cpFoundationAccount,
                  "passiveFinalizationCommission" AE..= _finalizationCommission (_ppPassiveCommissions _cpPoolParameters),
                  "passiveBakingCommission" AE..= _bakingCommission (_ppPassiveCommissions _cpPoolParameters),
                  "passiveTransactionCommission" AE..= _transactionCommission (_ppPassiveCommissions _cpPoolParameters),
                  "finalizationCommissionRange" AE..= _finalizationCommissionRange (_ppCommissionBounds _cpPoolParameters),
                  "bakingCommissionRange" AE..= _bakingCommissionRange (_ppCommissionBounds _cpPoolParameters),
                  "transactionCommissionRange" AE..= _transactionCommissionRange (_ppCommissionBounds _cpPoolParameters),
                  "minimumEquityCapital" AE..= _ppMinimumEquityCapital _cpPoolParameters,
                  "capitalBound" AE..= _ppCapitalBound _cpPoolParameters,
                  "leverageBound" AE..= _ppLeverageBound _cpPoolParameters,
                  "rewardPeriodLength" AE..= _tpRewardPeriodLength (unOParam _cpTimeParameters),
                  "mintPerPayday" AE..= _tpMintPerPayday (unOParam _cpTimeParameters),
                  "timeoutBase" AE..= _tpTimeoutBase (_cpTimeoutParameters _cpConsensusParameters),
                  "timeoutIncrease" AE..= _tpTimeoutIncrease (_cpTimeoutParameters _cpConsensusParameters),
                  "timeoutDecrease" AE..= _tpTimeoutDecrease (_cpTimeoutParameters _cpConsensusParameters),
                  "minBlockTime" AE..= _cpMinBlockTime _cpConsensusParameters,
                  "blockEnergyLimit" AE..= _cpBlockEnergyLimit _cpConsensusParameters,
                  "minimumFinalizers" AE..= _fcpMinFinalizers (unOParam _cpFinalizationCommitteeParameters),
                  "maximumFinalizers" AE..= _fcpMaxFinalizers (unOParam _cpFinalizationCommitteeParameters),
                  "finalizerRelativeStakeThreshold" AE..= _fcpFinalizerRelativeStakeThreshold (unOParam _cpFinalizationCommitteeParameters)
                ]

-- | Parameters that affect finalization.
data FinalizationParameters = FinalizationParameters
    { -- | Number of levels to skip between finalizations.
      finalizationMinimumSkip :: BlockHeight,
      -- | Maximum size of the finalization committee; determines the minimum stake
      --  required to join the committee as @totalGTU / finalizationCommitteeMaxSize@.
      finalizationCommitteeMaxSize :: FinalizationCommitteeSize,
      -- | Base delay time used in finalization.
      finalizationWaitingTime :: Duration,
      -- | Factor used to shrink the finalization gap. Must be strictly between 0 and 1.
      finalizationSkipShrinkFactor :: Ratio Word64,
      -- | Factor used to grow the finalization gap. Must be strictly greater than 1.
      finalizationSkipGrowFactor :: Ratio Word64,
      -- | Factor for shrinking the finalization delay (i.e. number of descendent blocks
      --  required to be eligible as a finalization target).
      finalizationDelayShrinkFactor :: Ratio Word64,
      -- | Factor for growing the finalization delay when it takes more than one round
      --  to finalize a block.
      finalizationDelayGrowFactor :: Ratio Word64,
      -- | Whether to allow the delay to be 0. (This allows a block to be finalized as soon
      --  as it is baked.)
      finalizationAllowZeroDelay :: Bool
    }
    deriving (Eq, Show)

-- | Serialize 'FinalizationParameters' in the V3 GenesisData
--  format.
putFinalizationParametersGD3 :: Putter FinalizationParameters
putFinalizationParametersGD3 FinalizationParameters{..} = do
    put finalizationMinimumSkip
    put finalizationCommitteeMaxSize
    put finalizationWaitingTime
    put finalizationSkipShrinkFactor
    put finalizationSkipGrowFactor
    put finalizationDelayShrinkFactor
    put finalizationDelayGrowFactor
    put finalizationAllowZeroDelay

-- | Deserialize 'FinalizationParameters' in the V3 GenesisData
--  format
getFinalizationParametersGD3 :: Get FinalizationParameters
getFinalizationParametersGD3 = label "FinalizationParameters" $ do
    finalizationMinimumSkip <- get
    finalizationCommitteeMaxSize <- get
    finalizationWaitingTime <- get
    finalizationSkipShrinkFactor <- get
    unless (finalizationSkipShrinkFactor > 0 && finalizationSkipShrinkFactor < 1) $
        fail "skipShrinkFactor must be strictly between 0 and 1"
    finalizationSkipGrowFactor <- get
    unless (finalizationSkipGrowFactor > 1) $
        fail "skipGrowFactor must be strictly greater than 1"
    finalizationDelayShrinkFactor <- get
    unless (finalizationDelayShrinkFactor > 0 && finalizationDelayShrinkFactor < 1) $
        fail "delayShrinkFactor must be strictly between 0 and 1"
    finalizationDelayGrowFactor <- get
    unless (finalizationDelayGrowFactor > 1) $
        fail "delayGrowFactor must be strictly greater than 1"
    finalizationAllowZeroDelay <- get
    return FinalizationParameters{..}

instance FromJSON FinalizationParameters where
    parseJSON = withObject "FinalizationParameters" $ \v -> do
        finalizationMinimumSkip <- BlockHeight <$> v .: "minimumSkip"
        finalizationCommitteeMaxSize <- v .: "committeeMaxSize"
        finalizationWaitingTime <- v .: "waitingTime"
        finalizationIgnoreFirstWait <- v .:? "ignoreFirstWait" .!= True
        unless finalizationIgnoreFirstWait $
            fail "ignoreFirstWait must be true (or not specified)"
        finalizationOldStyleSkip <- v .:? "oldStyleSkip" .!= False
        when finalizationOldStyleSkip $
            fail "oldStyleSkip must be false (or not specified)"
        finalizationSkipShrinkFactor <- v .: "skipShrinkFactor"
        unless (finalizationSkipShrinkFactor > 0 && finalizationSkipShrinkFactor < 1) $
            fail "skipShrinkFactor must be strictly between 0 and 1"
        finalizationSkipGrowFactor <- v .: "skipGrowFactor"
        unless (finalizationSkipGrowFactor > 1) $
            fail "skipGrowFactor must be strictly greater than 1"
        finalizationDelayShrinkFactor <- v .: "delayShrinkFactor"
        unless (finalizationDelayShrinkFactor > 0 && finalizationDelayShrinkFactor < 1) $
            fail "delayShrinkFactor must be strictly between 0 and 1"
        finalizationDelayGrowFactor <- v .: "delayGrowFactor"
        unless (finalizationDelayGrowFactor > 1) $
            fail "delayGrowFactor must be strictly greater than 1"
        finalizationAllowZeroDelay <- v .:? "allowZeroDelay" .!= False
        return FinalizationParameters{..}

-- | A GADT that encapsulates relevant facts about the 'ChainParametersVersion' for a protocol
--  version that supports delegation.
data DelegationChainParameters (pv :: ProtocolVersion) where
    DelegationChainParameters ::
        ( IsSupported 'PTTimeParameters (ChainParametersVersionFor pv) ~ 'True,
          PoolParametersVersionFor (ChainParametersVersionFor pv) ~ 'PoolParametersVersion1,
          CooldownParametersVersionFor (ChainParametersVersionFor pv) ~ 'CooldownParametersVersion1
        ) =>
        DelegationChainParameters pv

-- | Constrain the chain parameters given that the protocol version supports delegation.
--  This should be used in a context where @SupportsDelegation pv@ is known and one or more of the
--  following constraints are required:
--
--  * @IsSupported 'PTTimeParameters (ChainParametersVersionFor pv) ~ 'True@
--  * @PoolParametersVersionFor (ChainParametersVersionFor pv) ~ 'PoolParametersVersion1@
--
--  > case delegationChainParameters @pv of
--  >    DelegationChainParameters -> {\- here the constraints apply -\}
delegationChainParameters :: forall pv. (IsProtocolVersion pv, PVSupportsDelegation pv) => DelegationChainParameters pv
delegationChainParameters = case protocolVersion @pv of
    SP4 -> DelegationChainParameters
    SP5 -> DelegationChainParameters
    SP6 -> DelegationChainParameters
    SP7 -> DelegationChainParameters
    SP8 -> DelegationChainParameters

-- * Consensus versions

-- | Constraint that the protocol version @pv@ is associated with the version 0 consensus.
type IsConsensusV0 (pv :: ProtocolVersion) =
    ( ConsensusParametersVersionFor (ChainParametersVersionFor pv) ~ 'ConsensusParametersVersion0,
      SeedStateVersionFor pv ~ 'SeedStateVersion0
    )

-- | Constraint that the protocol version @pv@ is associated with the version 1 consensus.
type IsConsensusV1 (pv :: ProtocolVersion) =
    ( ConsensusParametersVersionFor (ChainParametersVersionFor pv) ~ 'ConsensusParametersVersion1,
      SeedStateVersionFor pv ~ 'SeedStateVersion1,
      IsSupported 'PTFinalizationCommitteeParameters (ChainParametersVersionFor pv) ~ 'True,
      IsSupported 'PTTimeParameters (ChainParametersVersionFor pv) ~ 'True,
      PoolParametersVersionFor (ChainParametersVersionFor pv) ~ 'PoolParametersVersion1,
      MintDistributionVersionFor (ChainParametersVersionFor pv) ~ 'MintDistributionVersion1,
      CooldownParametersVersionFor (ChainParametersVersionFor pv) ~ 'CooldownParametersVersion1,
      PVSupportsDelegation pv
    )

-- | The consensus version constraints for a particular protocol version.
data ConsensusVersion (pv :: ProtocolVersion) where
    ConsensusV0 :: (IsConsensusV0 pv) => ConsensusVersion pv
    ConsensusV1 :: (IsConsensusV1 pv) => ConsensusVersion pv

-- | Get the consensus version constraints for a protocol version.
consensusVersionFor :: SProtocolVersion pv -> ConsensusVersion pv
consensusVersionFor SP1 = ConsensusV0
consensusVersionFor SP2 = ConsensusV0
consensusVersionFor SP3 = ConsensusV0
consensusVersionFor SP4 = ConsensusV0
consensusVersionFor SP5 = ConsensusV0
consensusVersionFor SP6 = ConsensusV1
consensusVersionFor SP7 = ConsensusV1
consensusVersionFor SP8 = ConsensusV1
