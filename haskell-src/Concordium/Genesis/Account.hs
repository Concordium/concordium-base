{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Concordium.Genesis.Account where

import Concordium.Common.Version
import Concordium.ID.Parameters (GlobalContext)
import qualified Concordium.ID.Types as ID
import Concordium.Types
import Concordium.Utils.Serialization
import Control.Monad
import Data.Aeson.Types (
    FromJSON (parseJSON),
    withObject,
    (.:),
    (.:?),
 )
import Data.Serialize

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

-- |Serialize a 'GenesisBaker' in the GenesisDataV2 format.
-- Since this is based on the serialization of the full
-- @AccountBaker@ structure, we also include the pending
-- change to the baker, which is @NoChange@ for a genesis
-- baker.
putGenesisBakerGD2 :: Putter GenesisBaker
putGenesisBakerGD2 GenesisBaker{..} = do
    put gbStake
    put gbRestakeEarnings
    -- Baker info
    put gbBakerId
    put gbElectionVerifyKey
    put gbSignatureVerifyKey
    put gbAggregationVerifyKey
    -- Pending change (none)
    putWord8 0

-- |Deserialize a 'GenesisBaker' in the GenesisDataV2 format.
-- Since this is based on the serialization of the full @AccountBaker@
-- structure, we must also deserialize the pending change to the baker,
-- which is required to be @NoChange@.
getGenesisBakerGD2 :: Get GenesisBaker
getGenesisBakerGD2 = label "GenesisBaker" $ do
    gbStake <- get
    gbRestakeEarnings <- get
    -- Baker info
    gbBakerId <- get
    gbElectionVerifyKey <- get
    gbSignatureVerifyKey <- get
    gbAggregationVerifyKey <- get
    pendingChange <- getWord8
    unless (pendingChange == 0) $ fail "Baker has a pending change, which is not allowed"
    return GenesisBaker{..}

-- |A 'GenesisAccount' is special account existing in the genesis block.
data GenesisAccount = GenesisAccount
    { -- |The address of the account
      gaAddress :: !AccountAddress,
      -- |The account keys
      gaVerifyKeys :: !ID.AccountKeys,
      -- |The balance of the account at genesis
      gaBalance :: !Amount,
      -- |The account credential (only one)
      gaCredential :: !ID.AccountCredential,
      -- |The (optional) baker information
      gaBaker :: !(Maybe GenesisBaker)
    }
    deriving (Eq, Show)

-- |We only need the credential values. However when parsing we parse a full
-- credential, due to some legacy format issues, and then extract the values.
-- The legacy issues are that the commitments are part of the "proofs" object
-- in the credential, which, in JSON, is represented just as a hex-string.
-- This should be reworked at some point, so that it is more principled than
-- the current, slighly hacky, solution.
instance FromJSON GenesisAccount where
    parseJSON = withObject "GenesisAccount" $ \obj -> do
        gaAddress <- obj .: "address"
        gaVerifyKeys <- obj .: "accountKeys"
        gaBalance <- obj .: "balance"
        Versioned{..} <- obj .: "credential"
        unless (vVersion == 0) $ fail "Only V0 credentials supported in genesis."
        gaCredentialFull <- parseJSON vValue
        gaCredential <- case ID.values gaCredentialFull of
            Nothing -> fail "Account credential is malformed."
            Just gaCredential -> return gaCredential
        gaBaker <- obj .:? "baker"
        -- Check that bakers do not stake more than their balance.
        case gaBaker of
            Just gb | gbStake gb > gaBalance -> fail "Stake exceeds balance"
            _ -> return ()
        return GenesisAccount{..}

-- |Put a 'GenesisAccount' in the account serialization format
-- used for GenesisDataV2.  Note that the format permits arbitrary
-- accounts, but the 'GenesisAccount' restricts this.
putGenesisAccountGD2 :: GlobalContext -> Putter GenesisAccount
putGenesisAccountGD2 cryptoParams GenesisAccount{..} = do
    -- Put the persisting account data
    put gaAddress
    let encryptionKey = ID.makeEncryptionKey cryptoParams (ID.regId gaCredential)
    put encryptionKey
    put gaVerifyKeys
    put [gaCredential]
    put ([] :: [ContractAddress])
    -- Account nonce
    put minNonce
    -- Account amount
    put gaBalance
    -- Encrypted amount
    put initialAccountEncryptedAmount
    -- Release schedule
    putLength 0
    -- Baker
    putMaybeOf putGenesisBakerGD2 gaBaker

-- |Get a 'GenesisAccount' in the account serialization format
-- used for GenesisDataV2.  Note that the format permits arbitrary
-- accounts, but the 'GenesisAccount' restricts this.  This returns
-- both the account and the encryption key (which should be checked
-- in the context of the cryptographic context).
getGenesisAccountGD2 :: Get (GenesisAccount, ID.AccountEncryptionKey)
getGenesisAccountGD2 = label "GenesisAccount" $ do
    -- Get the persisting account data
    gaAddress <- get
    encryptionKey <- get
    gaVerifyKeys <- get
    credentials <- get
    gaCredential <- case credentials of
        [cred] -> return cred
        _ -> fail "Expected exactly one credential for a genesis account"
    contracts :: [ContractAddress] <- get
    unless (null contracts) $ fail "Genesis account must not have smart contracts"
    -- Account nonce
    nonce <- get
    unless (nonce == minNonce) $ fail $ "Genesis account must have nonce " ++ show minNonce
    -- Account amount
    gaBalance <- get
    -- Encrypted amount
    encAmt <- get
    unless (encAmt == initialAccountEncryptedAmount) $ fail "Genesis account must have empty encrypted amount"
    -- Release schedule
    len <- getLength
    unless (len == 0) $ fail "Genesis account must not have a release schedule"
    -- Baker
    gaBaker <- getMaybeOf getGenesisBakerGD2
    return (GenesisAccount{..}, encryptionKey)
