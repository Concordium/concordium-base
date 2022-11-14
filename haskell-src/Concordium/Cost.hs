{-# LANGUAGE DerivingVia #-}

-- |
-- Definition of cost functions for the different transactions.
--
-- * @SPEC: <$DOCS/Transactions#transaction-cost>
module Concordium.Cost where

import Concordium.ID.Types as ID
import Concordium.Types
import qualified Concordium.Wasm as Wasm
import Data.Word

-- |A class to convert to and from 'Energy' used by the scheduler.
-- The function should satisfy
--
--   * @toEnergy (fromEnergy x) <= x@
class ResourceMeasure a where
    toEnergy :: a -> Energy
    fromEnergy :: Energy -> a

instance ResourceMeasure Energy where
    {-# INLINE toEnergy #-}
    toEnergy = id
    {-# INLINE fromEnergy #-}
    fromEnergy = id

-- |Measures the cost of running the interpreter.
instance ResourceMeasure Wasm.InterpreterEnergy where
    {-# INLINE toEnergy #-}
    toEnergy = fromInterpreterEnergy
    {-# INLINE fromEnergy #-}
    fromEnergy = toInterpreterEnergy

-- |Measures the cost of __storing__ the given amount of bytes of smart contract
-- state.
instance ResourceMeasure Wasm.ByteSize where
    {-# INLINE toEnergy #-}
    toEnergy = fromIntegral
    {-# INLINE fromEnergy #-}
    fromEnergy = fromIntegral

-- * Cost factors

-- | The amount of interpreter energy corresponding to one unit of energy.
interpreterEnergyFactor :: Wasm.InterpreterEnergy
interpreterEnergyFactor = 1000

-- | Convert an energy amount to interpreter energy.
toInterpreterEnergy :: Energy -> Wasm.InterpreterEnergy
toInterpreterEnergy = (* interpreterEnergyFactor) . fromIntegral

-- | Convert interpreter energy to general energy (rounding down).
fromInterpreterEnergy :: Wasm.InterpreterEnergy -> Energy
fromInterpreterEnergy = fromIntegral . (`div` interpreterEnergyFactor)

-- * Costs for top-level account transactions

-- |The NRG cost is assigned according to the formula A * numSignatures + B *
-- size + C_t where C_t is transaction specific cost and A and B are transaction
-- independent factors.

-- |The A constant for NRG assignment.
constA :: Energy
constA = 100

-- |The B constant for NRG assignment.
constB :: Energy
constB = 1

-- |C_t for simple transfer.
simpleTransferCost :: Energy
simpleTransferCost = 300

-- |C_t for encrypted transfer
encryptedTransferCost :: Energy
encryptedTransferCost = 27000

-- |C_t for transfer from public to encrypted
transferToEncryptedCost :: Energy
transferToEncryptedCost = 600

-- |C_t for transfer from encrypted to public
transferToPublicCost :: Energy
transferToPublicCost = 14850

-- |C_t for transfer with schedule. The argument is the number of releases.
scheduledTransferCost :: Int -> Energy
scheduledTransferCost n = fromIntegral n * (300 + 64)

-- |C_t for adding a baker
addBakerCost :: Energy
addBakerCost = 4050

-- |C_t for configure baker when keys are not present
configureBakerCostWithoutKeys :: Energy
configureBakerCostWithoutKeys = 300

-- |C_t for configure baker when keys are present
configureBakerCostWithKeys :: Energy
configureBakerCostWithKeys = 4050

-- |C_t for updating baker keys
updateBakerKeysCost :: Energy
updateBakerKeysCost = 4050

-- |C_t for updating baker stake.
updateBakerStakeCost :: Energy
updateBakerStakeCost = 300

-- |C_t for updating baker automatic restake option
updateBakerRestakeCost :: Energy
updateBakerRestakeCost = 300

-- |C_t for removing a baker
removeBakerCost :: Energy
removeBakerCost = 300

-- |C_t for configure delegation
configureDelegationCost :: Energy
configureDelegationCost = 300

-- |C_t for updating account credentials
updateCredentialsCost ::
    -- | The number of credentials on the account before the update.
    Int ->
    -- | A list of keys attached to each new credential.
    [Int] ->
    Energy
updateCredentialsCost numCredentials =
    (updateCredentialsBaseCost +)
        . updateCredentialsVariableCost numCredentials

-- |C_t for registering data on chain.
registerDataCost :: Energy
registerDataCost = 300

-- |C_t for deploying a Wasm module.
-- The argument is the size of the Wasm module in bytes.
deployModuleCost :: Word64 -> Energy
deployModuleCost size = fromIntegral size `div` 10

-- |C_t for initializing a contract instance.
initializeContractInstanceCost ::
    -- | How much energy it took to execute the initialization code.
    Wasm.InterpreterEnergy ->
    -- | Size in bytes of the smart contract module that the instance is created from.
    Word64 ->
    -- | Size of the initial smart contract state if initialization succeeded.
    Maybe Wasm.ByteSize ->
    Energy
initializeContractInstanceCost ie ms ss =
    lookupModule ms + toEnergy ie + maybe 0 ((initializeContractInstanceCreateCost +) . toEnergy) ss + initializeContractInstanceBaseCost

-- |C_t for updating smart contract state.
-- This will be applied to each smart contract that is affected by the transaction.
updateContractInstanceCost ::
    -- | How much energy it t ook to execute the update code.
    Wasm.InterpreterEnergy ->
    -- | Size in bytes of the module the contract code belongs to.
    Word64 ->
    -- | Size of the original state.
    Wasm.ByteSize ->
    -- | Size of the new state, if update was successful.
    Maybe Wasm.ByteSize ->
    Energy
updateContractInstanceCost ie ms se ss =
    lookupModule ms + lookupContractState se + toEnergy ie + maybe 0 toEnergy ss + updateContractInstanceBaseCost

-- |C_t for updating existing credential keys. Parametrised by amount of
-- existing credentials and new keys. Due to the way the accounts are stored a
-- new copy of all credentials will be created, so we need to account for that
-- storage increase.
updateCredentialKeysCost ::
    -- | The number of existing credentials on the account.
    Int ->
    -- | The number of keys that will belong to the credential.
    Int ->
    Energy
updateCredentialKeysCost numCredentials numKeys = 500 * fromIntegral numCredentials + 100 * fromIntegral numKeys

-- * NRG assignments for non-account transactions.

-- |NRG value of adding a credential to an account. This cost is costant
-- regardless of the details of the data. It is not charged directly, but it is accounted for
-- in block energy.
deployCredential ::
    -- | Type of the credential. Initial credentials are cheaper.
    ID.CredentialType ->
    -- |Number of keys belonging to the credential.
    Int ->
    Energy
deployCredential ID.Initial numKeys = 1000 + 100 * fromIntegral numKeys
deployCredential ID.Normal numKeys = 54000 + 100 * fromIntegral numKeys

-- * Auxiliary definitions

-- |The cost A * numKeys + B * size
baseCost ::
    -- | The size of the transaction body in bytes.
    Word64 ->
    -- | The number of keys that signed the transaction.
    Int ->
    Energy
baseCost size numKeys = constA * fromIntegral numKeys + constB * fromIntegral size

-- |Fixed cost per generated inter-contract message.
interContractMessage :: Energy
interContractMessage = 10

-- |Cost of looking up a contract instance with a given state.
lookupContractState :: Wasm.ByteSize -> Energy
lookupContractState ss = fromIntegral ss `div` 50

lookupModule :: Word64 -> Energy
lookupModule ms = fromIntegral ms `div` 50

-- | The base cost of initializing a contract instance to cover administrative costs.
-- Even if no code is run and no instance created.
initializeContractInstanceBaseCost :: Energy
initializeContractInstanceBaseCost = 300

-- |Cost of creating an empty smart contract instance.
initializeContractInstanceCreateCost :: Energy
initializeContractInstanceCreateCost = 200

-- | The base cost of updating a contract instance to cover administrative
-- costs. Even if no code is run.
updateContractInstanceBaseCost :: Energy
updateContractInstanceBaseCost = 300

-- |Base cost of updating credentials. There is a non-trivial amount of lookup
-- that needs to be done before we can start any checking. This ensures that
-- those lookups are not a problem. If the credential updates are genuine then
-- this cost is going to be negligible compared to verifying the credential.
updateCredentialsBaseCost :: Energy
updateCredentialsBaseCost = 500

-- |Variable cost of updating credentials.
updateCredentialsVariableCost ::
    -- | The number of credentials on the account before the update.
    Int ->
    -- | A list of keys attached to each new credential.
    [Int] ->
    Energy
updateCredentialsVariableCost numCredentials =
    (500 * fromIntegral numCredentials +)
        . sum
        . map (deployCredential ID.Normal)

-- the 500 * numCredentials is to account for transactions which do nothing,
-- e.g., don't add don't remove, and don't update the threshold. These still
-- have a cost since the way the accounts are stored it will update the stored
-- account data, which does take up quite a bit of space per credential.

-- |Cost of querying the account balance from a within smart contract instance.
contractInstanceQueryAccountBalanceCost :: Energy
contractInstanceQueryAccountBalanceCost = 200

-- |Cost of querying the contract balance from a within smart contract instance.
contractInstanceQueryContractBalanceCost :: Energy
contractInstanceQueryContractBalanceCost = 200

-- |Cost of querying the current exchange rates from a within smart contract instance.
contractInstanceQueryExchangeRatesCost :: Energy
contractInstanceQueryExchangeRatesCost = 100
