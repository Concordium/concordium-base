-- |This module defines the genesis data fromat for the 'P1' protocol version.
module Concordium.Genesis.Data.P1 where

import Control.Monad
import Data.ByteString (ByteString)
import Data.Serialize
import qualified Data.Vector as Vec
import Lens.Micro.Platform

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.Genesis.Account
import Concordium.Genesis.Data.Base
import Concordium.Genesis.Parameters
import Concordium.Types
import Concordium.Types.AnonymityRevokers
import Concordium.Types.IdentityProviders
import Concordium.Types.Parameters
import Concordium.Types.Updates
import Concordium.Utils.Serialization

-- |Core parameters that are set at genesis.
-- These parameters are not updatable (except via protocol update) and
-- so are specified anew in any regenesis block.
data CoreGenesisParameters = CoreGenesisParameters
    { -- |The nominal time of the genesis block.
      genesisTime :: !Timestamp,
      -- |The duration of each slot.
      genesisSlotDuration :: !Duration,
      -- |Length of a baking epoch.
      genesisEpochLength :: !EpochLength,
      -- |The maximum total energy that may be expended by transactions in a block.
      genesisMaxBlockEnergy :: !Energy,
      -- |The parameters of the finalization protocol.
      genesisFinalizationParameters :: !FinalizationParameters
    }
    deriving (Eq, Show)

instance Serialize CoreGenesisParameters where
    put CoreGenesisParameters{..} = do
        put genesisTime
        put genesisSlotDuration
        put genesisEpochLength
        put genesisMaxBlockEnergy
        putFinalizationParametersGD3 genesisFinalizationParameters
    get = do
        genesisTime <- get
        genesisSlotDuration <- get
        genesisEpochLength <- get
        genesisMaxBlockEnergy <- get
        genesisFinalizationParameters <- getFinalizationParametersGD3
        return CoreGenesisParameters{..}

-- |Initial state configuration for genesis.
--
-- The initial accounts are assigned account indexes sequentially based
-- on their index in 'genesisAccounts'. This means that, when accounts
-- are bakers, their baker ID must correspond to this index.
--
-- It is also required that the foundation account specified in the
-- chain parameters is one of the genesis accounts.
data GenesisState = GenesisState
    { -- |Cryptographic parameters for on-chain proofs.
      genesisCryptographicParameters :: !CryptographicParameters,
      -- |The initial collection of identity providers.
      genesisIdentityProviders :: !IdentityProviders,
      -- |The initial collection of anonymity revokers.
      genesisAnonymityRevokers :: !AnonymityRevokers,
      -- |The initial authorization structure for chain updates.
      genesisAuthorizations :: !Authorizations,
      -- |The initial (updatable) chain parameters.
      genesisChainParameters :: !ChainParameters,
      -- |The initial leadership election nonce.
      genesisLeadershipElectionNonce :: !LeadershipElectionNonce,
      -- |The initial accounts on the chain.
      genesisAccounts :: !(Vec.Vector GenesisAccount)
    }
    deriving (Eq, Show)

instance Serialize GenesisState where
    put GenesisState{..} = do
        put genesisCryptographicParameters
        put genesisIdentityProviders
        put genesisAnonymityRevokers
        put genesisAuthorizations
        put genesisChainParameters
        put genesisLeadershipElectionNonce
        putLength (length genesisAccounts)
        mapM_ putGenesisAccountGD3 genesisAccounts
    get = do
        genesisCryptographicParameters <- get
        genesisIdentityProviders <- get
        genesisAnonymityRevokers <- get
        genesisAuthorizations <- get
        genesisChainParameters <- get
        genesisLeadershipElectionNonce <- get
        nGenesisAccounts <- getLength
        genesisAccounts <- Vec.replicateM nGenesisAccounts getGenesisAccountGD3
        Vec.forM_ (Vec.indexed genesisAccounts) $ \case
            (i, GenesisAccount{gaBaker = Just GenesisBaker{..}})
                | (gbBakerId /= fromIntegral i) -> fail "Baker Id is incorrect."
            _ -> return ()
        unless (genesisChainParameters ^. cpFoundationAccount < fromIntegral (Vec.length genesisAccounts)) $
            fail "Invalid foundation account."
        return GenesisState{..}

-- |Genesis data for the P1 protocol version.
-- Two types of genesis data are supported.
--
-- * 'GDP1Initial' represents an initial genesis block.
--   It specifies how the initial state should be configured.
--
-- * 'GDP1Regenesis' represents a reset of the protocol with
--   a new genesis block.  This includes the full serialized
--   block state to use from this point forward.
--
-- The serialization of the block state may not be unique, so
-- only the hash of it is used in defining the hash of the
-- genesis block.
--
-- The relationship between the new state and the state of the
-- terminal block of the old chain should be defined by the
-- chain update mechanism used.
--
-- To the extent that the 'CoreGenesisParameters' are represented
-- in the block state, they should agree. (This is probably only
-- the epoch length.)
--
-- Note that the invariants regarding the 'genesisNewState' are
-- soft: deserialization does not check them, or even that the
-- serialization is valid.
data GenesisDataP1
    = -- |An initial genesis block.
      GDP1Initial
        { -- |The immutable genesis parameters.
          genesisCore :: !CoreGenesisParameters,
          -- |The blueprint for the initial state at genesis.
          genesisInitialState :: !GenesisState
        }
    | -- |A re-genesis block.
      GDP1Regenesis
        { -- |The immutable genesis parameters.
          -- (These need not be invariant across re-genesis.)
          genesisCore :: !CoreGenesisParameters,
          -- |The hash of the first genesis block in the chain.
          genesisFirstGenesis :: !BlockHash,
          -- |The hash of the preceding (re)genesis block.
          genesisPreviousGenesis :: !BlockHash,
          -- |The hash of the last finalized block that terminated the chain before the
          -- new genesis.
          genesisTerminalBlock :: !BlockHash,
          -- |The hash of the block state for the regenesis.
          genesisStateHash :: !StateHash,
          -- |The serialized block state. This should match the specified hash.
          genesisNewState :: !ByteString
        }
    deriving (Eq, Show)

instance BasicGenesisData GenesisDataP1 where
    gdGenesisTime = genesisTime . genesisCore
    {-# INLINE gdGenesisTime #-}
    gdSlotDuration = genesisSlotDuration . genesisCore
    {-# INLINE gdSlotDuration #-}
    gdMaxBlockEnergy = genesisMaxBlockEnergy . genesisCore
    {-# INLINE gdMaxBlockEnergy #-}
    gdFinalizationParameters = genesisFinalizationParameters . genesisCore
    {-# INLINE gdFinalizationParameters #-}
    gdEpochLength = genesisEpochLength . genesisCore
    {-# INLINE gdEpochLength #-}

-- |Deserialize genesis data in the V3 format.
getGenesisDataV3 :: Get GenesisDataP1
getGenesisDataV3 =
    getWord8 >>= \case
        0 -> do
            genesisCore <- get
            genesisInitialState <- get
            return GDP1Initial{..}
        1 -> do
            genesisCore <- get
            genesisFirstGenesis <- get
            genesisPreviousGenesis <- get
            genesisTerminalBlock <- get
            genesisStateHash <- get
            genesisNewState <- getByteStringLen
            return GDP1Regenesis{..}
        _ -> fail "Unrecognised genesis data type"

-- |Serialize genesis data in the V3 format.
putGenesisDataV3 :: Putter GenesisDataP1
putGenesisDataV3 GDP1Initial{..} = do
    putWord8 0
    put genesisCore
    put genesisInitialState
putGenesisDataV3 GDP1Regenesis{..} = do
    putWord8 1
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash
    putByteStringLen genesisNewState

-- |Deserialize genesis data with a version tag.
getVersionedGenesisData :: Get GenesisDataP1
getVersionedGenesisData =
    getVersion >>= \case
        3 -> getGenesisDataV3
        n -> fail $ "Unsupported genesis data version: " ++ show n

-- |Serialize genesis data with a version tag.
-- This will use the V3 format.
putVersionedGenesisData :: Putter GenesisDataP1
putVersionedGenesisData gd = do
    putVersion 3
    putGenesisDataV3 gd

-- |Convert 'GenesisParameters' to 'GenesisDataP1'.
parametersToGenesisData :: GenesisParameters -> GenesisDataP1
parametersToGenesisData GenesisParametersV2{gpChainParameters = GenesisChainParameters{..}, ..} =
    GDP1Initial
        { genesisCore = CoreGenesisParameters{..},
          genesisInitialState = GenesisState{..}
        }
  where
    genesisTime = gpGenesisTime
    genesisSlotDuration = gpSlotDuration
    genesisEpochLength = gpEpochLength
    genesisLeadershipElectionNonce = gpLeadershipElectionNonce
    genesisAccounts = Vec.fromList gpInitialAccounts
    genesisFinalizationParameters = gpFinalizationParameters
    genesisCryptographicParameters = gpCryptographicParameters
    genesisIdentityProviders = gpIdentityProviders
    genesisAnonymityRevokers = gpAnonymityRevokers
    genesisMaxBlockEnergy = gpMaxBlockEnergy
    genesisAuthorizations = gpAuthorizations
    genesisChainParameters =
        makeChainParameters
            gcpElectionDifficulty
            gcpEuroPerEnergy
            gcpMicroGTUPerEuro
            gcpBakerExtraCooldownEpochs
            gcpAccountCreationLimit
            gcpRewardParameters
            foundationAccountIndex
            gcpBakerStakeThreshold
    foundationAccountIndex = case Vec.findIndex ((gcpFoundationAccount ==) . gaAddress) genesisAccounts of
        Nothing -> error "Foundation account is missing"
        Just i -> fromIntegral i

-- |Compute the block hash of the genesis block with the given genesis data.
-- Every block hash is derived from a message that begins with the block slot,
-- which is 0 for genesis blocks.  For the genesis block, as of 'P1', we include
-- a signifier of the protocol version next.
--
-- Note, for regenesis blocks, the state is only represented by its hash.
genesisBlockHash :: GenesisDataP1 -> BlockHash
genesisBlockHash GDP1Initial{..} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P1
    putWord8 0 -- Initial
    put genesisCore
    put genesisInitialState
genesisBlockHash GDP1Regenesis{..} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P1
    putWord8 1 -- Regenesis
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash
