{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Concordium.Genesis.Account where

import Control.Monad
import Data.Aeson.Types (
    FromJSON (parseJSON),
    withObject,
    (.:),
    (.:?),
 )
import Data.Maybe
import Data.Serialize

import Concordium.Common.Version
import qualified Concordium.ID.Types as ID
import Concordium.Types
import Concordium.Utils.Serialization
import qualified Data.Map.Strict as Map

-- |'GenesisBaker' is an abstraction of a baker at genesis.
-- It includes the minimal information for generating a baker.
data GenesisBaker = GenesisBaker
    { -- |The baker's public VRF key
      gbElectionVerifyKey :: BakerElectionVerifyKey,
      -- |The baker's public signature key
      gbSignatureVerifyKey :: BakerSignVerifyKey,
      -- |The baker's public key for aggregate signatures
      gbAggregationVerifyKey :: BakerAggregationVerifyKey,
      -- |The baker's initial stake
      gbStake :: Amount,
      -- |Whether to restake the baker's earnings from rewards
      gbRestakeEarnings :: Bool,
      -- |The baker ID is defined by the account, however we use it here
      -- so we can report an error if inconsistent data is used.
      gbBakerId :: BakerId
    }
    deriving (Eq, Show)

instance FromJSON GenesisBaker where
    parseJSON = withObject "GenesisBaker" $ \v -> do
        gbElectionVerifyKey <- v .: "electionVerifyKey"
        gbSignatureVerifyKey <- v .: "signatureVerifyKey"
        gbAggregationVerifyKey <- v .: "aggregationVerifyKey"
        gbStake <- v .: "stake"
        gbRestakeEarnings <- v .: "restakeEarnings"
        gbBakerId <- v .: "bakerId"
        return GenesisBaker{..}

-- |Serialize a 'GenesisBaker' in the GenesisDataV3 format.
putGenesisBakerGD3 :: Putter GenesisBaker
putGenesisBakerGD3 GenesisBaker{..} = do
    put gbStake
    put gbRestakeEarnings
    -- Baker info
    put gbBakerId
    put gbElectionVerifyKey
    put gbSignatureVerifyKey
    put gbAggregationVerifyKey

-- |Deserialize a 'GenesisBaker' in the GenesisDataV3 format.
getGenesisBakerGD3 :: Get GenesisBaker
getGenesisBakerGD3 = label "GenesisBaker" $ do
    gbStake <- get
    gbRestakeEarnings <- get
    -- Baker info
    gbBakerId <- get
    gbElectionVerifyKey <- get
    gbSignatureVerifyKey <- get
    gbAggregationVerifyKey <- get
    return GenesisBaker{..}

-- |A 'GenesisAccount' is special account existing in the genesis block.
data GenesisAccount = GenesisAccount
    { -- |The address of the account
      gaAddress :: !AccountAddress,
      -- |The account threshold
      gaThreshold :: !ID.AccountThreshold,
      -- |The balance of the account at genesis
      gaBalance :: !Amount,
      -- |The account credentials. At least a credential with index 'initialCredentialIndex' (0) must exist.
      gaCredentials :: !(Map.Map ID.CredentialIndex ID.AccountCredential),
      -- |The (optional) baker information
      gaBaker :: !(Maybe GenesisBaker)
    }
    deriving (Eq, Show)

-- |We only need the credential values. However when parsing we parse a full
-- credential, due to some legacy format issues, and then extract the values.
-- The legacy issues are that the commitments are part of the "proofs" object
-- in the credential, which, in JSON, is represented just as a hex-string.
-- This should be reworked at some point, so that it is more principled than
-- the current, slightly hacky, solution.
instance FromJSON GenesisAccount where
    parseJSON = withObject "GenesisAccount" $ \obj -> do
        gaAddress <- obj .: "address"
        gaThreshold <- obj .: "accountThreshold"
        gaBalance <- obj .: "balance"
        gaCredentials <-
            obj .:? "credentials" >>= \case
                Nothing -> do
                    Versioned{..} <- obj .: "credential"
                    unless (vVersion == 0) $ fail "Only V0 credentials supported in genesis."
                    gaCredential <- parseJSON vValue
                    return (Map.singleton ID.initialCredentialIndex gaCredential)
                Just Versioned{..} -> do
                    unless (vVersion == 0) $ fail "Only V0 credentials supported in genesis."
                    parseJSON vValue
        unless (Map.member ID.initialCredentialIndex gaCredentials) $
            fail $
                "Genesis account must have a credential with index" ++ show ID.initialCredentialIndex ++ "."
        gaBaker <- obj .:? "baker"
        -- Check that bakers do not stake more than their balance.
        case gaBaker of
            Just gb | gbStake gb > gaBalance -> fail "Stake exceeds balance"
            _ -> return ()
        return GenesisAccount{..}

-- |Put a 'GenesisAccount' in the account serialization format
-- used for GenesisDataV3.
putGenesisAccountGD3 :: Putter GenesisAccount
putGenesisAccountGD3 GenesisAccount{..} = do
    -- Put the persisting account data
    put gaAddress
    put gaThreshold
    putSafeMapOf put put gaCredentials
    -- Account amount
    put gaBalance
    -- Baker
    putMaybeOf putGenesisBakerGD3 gaBaker

-- |Get a 'GenesisAccount' in the account serialization format
-- used for GenesisDataV3.
getGenesisAccountGD3 :: Get GenesisAccount
getGenesisAccountGD3 = label "GenesisAccount" $ do
    -- Get the persisting account data
    gaAddress <- get
    gaThreshold <- get
    gaCredentials <- getSafeMapOf get get
    unless (isJust $ Map.lookup ID.initialCredentialIndex gaCredentials) $
        fail $
            "A genesis account must have a credential with index " ++ show ID.initialCredentialIndex ++ "."
    -- Account amount
    gaBalance <- get
    -- Baker
    gaBaker <- getMaybeOf getGenesisBakerGD3
    return GenesisAccount{..}
