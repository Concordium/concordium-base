module Concordium.Genesis.Data.Base where

import Control.Monad
import qualified Data.ByteString as BS
import Data.Serialize
import qualified Data.Vector as Vec
import qualified Data.Map.Strict as Map
import Lens.Micro.Platform

import Concordium.Types
import Concordium.Types.Parameters
import Concordium.Types.AnonymityRevokers
import Concordium.Types.IdentityProviders
import Concordium.Types.Updates
import Concordium.Utils.Serialization
import Concordium.Genesis.Account
import Concordium.Genesis.Parameters

-- |A class that provides access to fields of genesis data that
-- are expected to be stable across versions.
class BasicGenesisData gd where
    -- |The genesis time.
    gdGenesisTime :: gd -> Timestamp

    -- |The duration of a slot.
    gdSlotDuration :: gd -> Duration

    -- |The maximum energy per block.
    gdMaxBlockEnergy :: gd -> Energy

    -- |The finalization parameters.
    gdFinalizationParameters :: gd -> FinalizationParameters

    -- |The epoch length in slots
    gdEpochLength :: gd -> EpochLength


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

-- | Data in the "regenesis" block, which is the first block of the chain after
-- the protocol update takes effect.
-- It is likely that the data in here will change for future protocol versions, but
-- P1 and P2 updates share it.
data RegenesisData = RegenesisData {
    -- |The immutable genesis parameters.
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
    genesisNewState :: !BS.ByteString
  } deriving(Eq, Show)


getRegenesisData :: Get RegenesisData
getRegenesisData = do
    genesisCore <- get
    genesisFirstGenesis <- get
    genesisPreviousGenesis <- get
    genesisTerminalBlock <- get
    genesisStateHash <- get
    genesisNewState <- getByteStringLen
    return RegenesisData{..}

putRegenesisData :: Putter RegenesisData
putRegenesisData RegenesisData{..} = do
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash
    putByteStringLen genesisNewState

-- |Initial state configuration for genesis.
--
-- The initial accounts are assigned account indexes sequentially based
-- on their index in 'genesisAccounts'. This means that, when accounts
-- are bakers, their baker ID must correspond to this index.
--
-- It is also required that the foundation account specified in the
-- chain parameters is one of the genesis accounts.
--
-- It is likely that the data in here will change for future protocol versions, but
-- P1 and P2 updates share it.
data GenesisState = GenesisState
    { -- |Cryptographic parameters for on-chain proofs.
      genesisCryptographicParameters :: !CryptographicParameters,
      -- |The initial collection of identity providers.
      genesisIdentityProviders :: !IdentityProviders,
      -- |The initial collection of anonymity revokers.
      genesisAnonymityRevokers :: !AnonymityRevokers,
      -- |The initial update keys structure for chain updates.
      genesisUpdateKeys :: !UpdateKeysCollection,
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
        put genesisUpdateKeys
        put genesisChainParameters
        put genesisLeadershipElectionNonce
        putLength (length genesisAccounts)
        mapM_ putGenesisAccountGD3 genesisAccounts
    get = do
        genesisCryptographicParameters <- get
        genesisIdentityProviders <- get
        genesisAnonymityRevokers <- get
        genesisUpdateKeys <- get
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

-- |Convert 'GenesisParameters' to genesis data.
-- This is an auxiliary function since the same parameters are used for P1 and P2 genesis.
parametersToState :: GenesisParameters -> (CoreGenesisParameters, GenesisState)
parametersToState GenesisParametersV2{gpChainParameters = GenesisChainParameters{..}, ..} =
    (CoreGenesisParameters{..}, GenesisState{..})
  where
    genesisTime = gpGenesisTime
    genesisSlotDuration = gpSlotDuration
    genesisEpochLength = gpEpochLength
    genesisLeadershipElectionNonce = gpLeadershipElectionNonce
    genesisAccounts = Vec.fromList gpInitialAccounts
    genesisFinalizationParameters = gpFinalizationParameters
    genesisCryptographicParameters = gpCryptographicParameters
    genesisIdentityProviders =
      case filter (\(k, v) -> k /= ipIdentity v) (Map.toList (idProviders gpIdentityProviders)) of
        [] -> gpIdentityProviders
        ips -> error $ "Inconsistent identity provider ids: " ++ show ips
    genesisAnonymityRevokers =
      case filter (\(k, v) -> k /= arIdentity v) (Map.toList (arRevokers gpAnonymityRevokers)) of
        [] -> gpAnonymityRevokers
        ars -> error $ "Inconsistent anonymity revoker ids: " ++ show ars
    genesisMaxBlockEnergy = gpMaxBlockEnergy
    genesisUpdateKeys = gpUpdateKeys
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

