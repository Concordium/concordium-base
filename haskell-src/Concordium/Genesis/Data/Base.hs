{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Concordium.Genesis.Data.Base where

import Control.Monad
import qualified Data.Map.Strict as Map
import Data.Serialize
import qualified Data.Vector as Vec
import Data.Word
import Lens.Micro.Platform

import Concordium.Genesis.Account
import Concordium.Genesis.Parameters
import Concordium.Types
import Concordium.Types.AnonymityRevokers
import Concordium.Types.IdentityProviders
import Concordium.Types.Parameters
import Concordium.Types.Updates
import Concordium.Utils.Serialization

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

-- |Extract the core genesis parameters.
coreGenesisParameters :: BasicGenesisData gd => gd -> CoreGenesisParameters
coreGenesisParameters gd =
    CoreGenesisParameters
        { genesisTime = gdGenesisTime gd,
          genesisSlotDuration = gdSlotDuration gd,
          genesisEpochLength = gdEpochLength gd,
          genesisFinalizationParameters = gdFinalizationParameters gd,
          genesisMaxBlockEnergy = gdMaxBlockEnergy gd
        }

instance BasicGenesisData CoreGenesisParameters where
    gdGenesisTime = genesisTime
    gdSlotDuration = genesisSlotDuration
    gdMaxBlockEnergy = genesisMaxBlockEnergy
    gdFinalizationParameters = genesisFinalizationParameters
    gdEpochLength = genesisEpochLength

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

-- |Information about the genesis block of the chain. This is not the full
-- genesis block. It does not include the genesis state. Instead, it is the
-- minimal information needed by a running consensus.
--
-- The intention is that this structured can always be deserialized from a
-- serialized @GenesisData@ provided the hash of the genesis data is known.
data GenesisConfiguration = GenesisConfiguration
    { -- |The tag used when deserializing genesis data. This determines the variant
      -- of the genesis data that is to be deserialized. The allowed values depend
      -- on the protocol version. For each protocol there is a function
      -- 'genesisVariantTag' that determines the allowed values for this tag.
      _gcTag :: !Word8,
      -- |Genesis parameters.
      _gcCore :: !CoreGenesisParameters,
      -- |Hash of the genesis block of the chain. This is carried over on protocol
      -- updates.
      _gcFirstGenesis :: !BlockHash,
      -- |Hash of the current genesis block. Each protocol update introduces a new
      -- genesis block.
      _gcCurrentHash :: !BlockHash
    }
    deriving (Eq, Show)

instance BasicGenesisData GenesisConfiguration where
    gdGenesisTime = gdGenesisTime . _gcCore
    gdSlotDuration = gdSlotDuration . _gcCore
    gdMaxBlockEnergy = gdMaxBlockEnergy . _gcCore
    gdFinalizationParameters = gdFinalizationParameters . _gcCore
    gdEpochLength = gdEpochLength . _gcCore

-- |Serialize genesis configuration. This is done in such a way that
-- 'getGenesisConfiguration' can parse it.
putGenesisConfiguration :: Putter GenesisConfiguration
putGenesisConfiguration GenesisConfiguration{..} = put _gcTag <> put _gcCore <> put _gcFirstGenesis <> put _gcCurrentHash

-- | Common data in the "regenesis" block, which is the first block of the chain after
-- the protocol update takes effect.
data RegenesisData = RegenesisData
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
      genesisStateHash :: !StateHash
    }
    deriving (Eq, Show)

getRegenesisData :: Get RegenesisData
getRegenesisData = do
    genesisCore <- get
    genesisFirstGenesis <- get
    genesisPreviousGenesis <- get
    genesisTerminalBlock <- get
    genesisStateHash <- get
    return RegenesisData{..}

putRegenesisData :: Putter RegenesisData
putRegenesisData RegenesisData{..} = do
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash

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
data GenesisState (pv :: ProtocolVersion) = GenesisState
    { -- |Cryptographic parameters for on-chain proofs.
      genesisCryptographicParameters :: !CryptographicParameters,
      -- |The initial collection of identity providers.
      genesisIdentityProviders :: !IdentityProviders,
      -- |The initial collection of anonymity revokers.
      genesisAnonymityRevokers :: !AnonymityRevokers,
      -- |The initial update keys structure for chain updates.
      genesisUpdateKeys :: !(UpdateKeysCollection (ChainParametersVersionFor pv)),
      -- |The initial (updatable) chain parameters.
      genesisChainParameters :: !(ChainParameters pv),
      -- |The initial leadership election nonce.
      genesisLeadershipElectionNonce :: !LeadershipElectionNonce,
      -- |The initial accounts on the chain.
      genesisAccounts :: !(Vec.Vector GenesisAccount)
    }
    deriving (Eq, Show)

instance forall pv. IsProtocolVersion pv => Serialize (GenesisState pv) where
    put GenesisState{..} = do
        put genesisCryptographicParameters
        put genesisIdentityProviders
        put genesisAnonymityRevokers
        putUpdateKeysCollection genesisUpdateKeys
        putChainParameters genesisChainParameters
        put genesisLeadershipElectionNonce
        putLength (length genesisAccounts)
        mapM_ putGenesisAccountGD3 genesisAccounts
    get = do
        genesisCryptographicParameters <- get
        genesisIdentityProviders <- get
        genesisAnonymityRevokers <- get
        genesisUpdateKeys <- getUpdateKeysCollection
        genesisChainParameters <- getChainParameters
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

-- |Construct chain parameters from the genesis accounts and 'GenesisChainParameters'.
-- It is required that an account with address matching the one in the genesis chain parameters
-- is present in the vector of genesis accounts, or else this function will error.
toChainParameters :: Vec.Vector GenesisAccount -> GenesisChainParameters' cpv -> ChainParameters' cpv
toChainParameters genesisAccounts GenesisChainParameters{..} = ChainParameters{..}
  where
    _cpElectionDifficulty = gcpElectionDifficulty
    _cpExchangeRates = gcpExchangeRates
    _cpCooldownParameters = gcpCooldownParameters
    _cpTimeParameters = gcpTimeParameters
    _cpAccountCreationLimit = gcpAccountCreationLimit
    _cpRewardParameters = gcpRewardParameters
    _cpFoundationAccount = case Vec.findIndex ((gcpFoundationAccount ==) . gaAddress) genesisAccounts of
        Nothing -> error "Foundation account is missing"
        Just i -> fromIntegral i
    _cpPoolParameters = gcpPoolParameters

-- |Convert 'GenesisParameters' to genesis data.
-- This is an auxiliary function since much of the behaviour is shared between protocol versions.
parametersToState :: GenesisParameters pv -> (CoreGenesisParameters, GenesisState pv)
parametersToState GenesisParameters{..} =
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
    genesisChainParameters = toChainParameters genesisAccounts gpChainParameters
