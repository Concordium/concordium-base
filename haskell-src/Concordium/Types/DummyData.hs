{-# OPTIONS_GHC -Wno-deprecations #-}

module Concordium.Types.DummyData where

import System.Random

import Concordium.Crypto.DummyData
import qualified Concordium.Crypto.SignatureScheme as Sig
import Concordium.Crypto.VRF as VRF

import qualified Concordium.Cost as Cost
import Concordium.ID.Types
import Concordium.Types
import Concordium.Types.Execution
import Concordium.Types.Transactions

{-# WARNING dummyblockPointer "Do not use in production." #-}
dummyblockPointer :: BlockHash
dummyblockPointer = BlockHash minBound

{-# WARNING mateuszAccount "Do not use in production." #-}
mateuszAccount :: AccountAddress
mateuszAccount = accountAddressFrom 0

{-# WARNING alesAccount "Do not use in production." #-}
alesAccount :: AccountAddress
alesAccount = accountAddressFrom 1

{-# WARNING thomasAccount "Do not use in production." #-}
thomasAccount :: AccountAddress
thomasAccount = accountAddressFrom 2

{-# WARNING accountAddressFrom "Do not use in production." #-}
accountAddressFrom :: Int -> AccountAddress
accountAddressFrom n = fst (randomAccountAddress (mkStdGen n))

{-# WARNING accountAddressFromCredential "Do not use in production." #-}
accountAddressFromCredential :: AccountCredentialWithProofs -> AccountAddress
accountAddressFromCredential (InitialACWP icdi) = initialCredentialAccountAddress . icdiValues $ icdi
accountAddressFromCredential (NormalACWP cdi) = credentialAccountAddress . cdiValues $ cdi

-- The expiry time is set to the same time as slot time, which is currently also 0.
-- If slot time increases, in order for tests to pass transaction expiry must also increase.
{-# WARNING dummyLowTransactionExpiryTime "Do not use in production." #-}
dummyLowTransactionExpiryTime :: TransactionExpiryTime
dummyLowTransactionExpiryTime = 0

{-# WARNING dummyMaxTransactionExpiryTime "Do not use in production." #-}
dummyMaxTransactionExpiryTime :: TransactionExpiryTime
dummyMaxTransactionExpiryTime = TransactionTime maxBound

{-# WARNING dummySlotTime "Do not use in production." #-}
dummySlotTime :: Timestamp
dummySlotTime = 0

{-# WARNING bakerElectionKey "Do not use in production." #-}
bakerElectionKey :: Int -> BakerElectionPrivateKey
bakerElectionKey n = fst (VRF.randomKeyPair (mkStdGen n))

{-# WARNING bakerSignKey "Do not use in production." #-}
bakerSignKey :: Int -> BakerSignPrivateKey
bakerSignKey n = fst (randomBlockKeyPair (mkStdGen n))

{-# WARNING bakerAggregationKey "Do not use in production." #-}
bakerAggregationKey :: Int -> BakerAggregationPrivateKey
bakerAggregationKey n = fst (randomBlsSecretKey (mkStdGen n))

{-# WARNING makeTransferTransaction "Dummy transaction, only use for testing." #-}
-- NB: The cost needs to be in-line with that defined in the scheduler.
makeTransferTransaction :: (Sig.KeyPair, AccountAddress) -> AccountAddress -> Amount -> Nonce -> BlockItem
makeTransferTransaction (fromKP, fromAddress) toAddress amount n =
    normalTransaction . fromAccountTransaction (TransactionTime maxBound) . signTransactionSingle fromKP header $ payload
  where
    header =
        TransactionHeader
            { thNonce = n,
              thSender = fromAddress,
              -- The cost needs to be in-line with that in the scheduler
              thEnergyAmount = Cost.baseCost (transactionHeaderSize + fromIntegral (payloadSize payload)) 1 + Cost.simpleTransferCost,
              thExpiry = dummyMaxTransactionExpiryTime,
              thPayloadSize = payloadSize payload
            }
    payload = encodePayload (Transfer toAddress amount)
