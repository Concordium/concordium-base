{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE EmptyCase #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE CPP #-}
module Concordium.Types.Execution where

import Prelude hiding(fail)

import Control.Monad.Reader

import Data.Char
import qualified Data.Aeson as AE
import Data.Aeson.TH
import qualified Data.HashMap.Strict as HMap
import qualified Data.Map as Map
import qualified Data.Serialize.Put as P
import qualified Data.Serialize.Get as G
import qualified Data.Serialize as S
import qualified Data.Set as Set
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as BSS
import Data.Word
import GHC.Generics
import Language.Haskell.TH

import qualified Concordium.Wasm as Wasm
import Concordium.Types
import Concordium.Utils
import Concordium.Types.Execution.TH

import Concordium.ID.Types
import qualified Concordium.ID.Types as IDTypes
import Concordium.Crypto.Proofs
import Concordium.Crypto.EncryptedTransfers

-- |We assume that the list is non-empty and at most 255 elements long.
newtype AccountOwnershipProof = AccountOwnershipProof [(KeyIndex, Dlog25519Proof)]
    deriving(Eq, Show)

-- |Helper for when an account has only one key with index 0.
singletonAOP :: Dlog25519Proof -> AccountOwnershipProof
singletonAOP proof = AccountOwnershipProof [(0, proof)]

instance S.Serialize AccountOwnershipProof where
  put (AccountOwnershipProof proofs) = do
    S.putWord8 (fromIntegral (length proofs))
    forM_ proofs (S.putTwoOf S.put S.put)

  get = do
    l <- S.getWord8
    when (l == 0) $ fail "At least one proof must be provided."
    AccountOwnershipProof <$> replicateM (fromIntegral l) (S.getTwoOf S.get S.get)

instance AE.FromJSON AccountOwnershipProof where
  parseJSON v = (AccountOwnershipProof . HMap.toList) <$> AE.parseJSON v

instance AE.ToJSON AccountOwnershipProof where
  toJSON (AccountOwnershipProof proofs) = AE.toJSON $ HMap.fromList proofs

-- |The transaction payload. Defines the supported kinds of transactions.
--
--  * @SPEC: <$DOCS/Transactions#transaction-body>
--  * @COMMENT: Serialization format is defined separately, this only defines the datatype.
data Payload =
  -- |Put module on the chain.
  DeployModule {
    -- |A wasm module in binary format.
    dmMod :: !Wasm.WasmModule
    }
  -- |Initialize a new contract instance.
  | InitContract {
      -- |Initial amount on the contract's account.
      icAmount :: !Amount,
      -- |Reference of the module (on-chain) in which the contract exist.
      icModRef :: !ModuleRef,
      -- |Name of the init function to call in that module.
      icInitName :: !Wasm.InitName,
      -- |Parameter to the init method,
      icParam :: !Wasm.Parameter
      }
  -- |Update an existing contract instance.
  | Update {
      -- |Amount to call the receive method with.
      uAmount :: !Amount,
      -- |The address of the contract to invoke.
      uAddress :: !ContractAddress,
      uReceiveName :: !Wasm.ReceiveName,
      -- |Message to invoke the receive method with.
      uMessage :: !Wasm.Parameter
      }
  -- |Simple transfer from an account to an account.
  | Transfer {
      -- |Recepient.
      tToAddress :: !AccountAddress,
      -- |Amount to transfer.
      tAmount :: !Amount
      }
  -- |Add a new baker with fresh id.
  | AddBaker {
      -- NOTE: The baker id should probably be generated automatically.
      -- we do not wish to recycle baker ids. If we allowed that then
      -- potentially when bakers are removed dishonest bakers might try to
      -- claim their ids and thus abuse the system.
      -- |Public key to verify the baker has won the election.
      abElectionVerifyKey :: !BakerElectionVerifyKey,
      -- |Public key to verify block signatures signed by the baker.
      abSignatureVerifyKey :: !BakerSignVerifyKey,
      -- |Public key to verify aggregate signatures in which the baker participates
      abAggregationVerifyKey :: !BakerAggregationVerifyKey,
      -- |Address of the account the baker wants to be rewarded to.
      abAccount :: !AccountAddress,
      -- |Proof that the baker owns the private key corresponding to the
      -- signature verification key.
      abProofSig :: !Dlog25519Proof,
      -- |Proof that the baker owns the private key corresponding to the
      -- election verification key.
      abProofElection :: !Dlog25519Proof,
      -- |Proof that the baker owns the privte key corresponding to the reward
      -- account public key. This is needed at least for beta where we want to
      -- control who can become a baker and thus cannot allow users to send
      -- create their own bakers.
      -- TODO: We could also alternatively just require a signature from one of the
      -- beta accounts on the public data.
      abProofAccount :: !AccountOwnershipProof,
      -- |Proof that the baker owns the private key corresponding to the aggregation
      -- key.
      abProofAggregation :: !BakerAggregationProof
      -- FIXME: in the future also logic the baker is allowed to become a baker:
      -- THIS NEEDS SPEC
      }
  -- |Remove an existing baker from the baker pool.
  | RemoveBaker {
      -- |Id of the baker to remove.
      rbId :: !BakerId
      -- TODO:
      -- Proof that we are allowed to remove the baker. One
      -- -- mechanism would be that the baker would remove itself only
      -- -- (the transaction must come from the baker's account) but
      -- -- possibly we want other mechanisms.
      -- rbProof :: !Proof
      }
  -- |Update the account the baker receives their baking reward to.
  | UpdateBakerAccount {
      -- |Id of the baker to update.
      ubaId :: !BakerId,
      -- |Address of the new account. The account must exist.
      ubaAddress :: !AccountAddress,
      -- |Proof that the baker owns the new account.
      ubaProof :: !AccountOwnershipProof
      }
  -- |Update the signature (verification) key of the baker.
  | UpdateBakerSignKey {
      -- |Id of the baker to update.
      ubsId :: !BakerId,
      -- |New signature verification key.
      ubsKey :: !BakerSignVerifyKey,
      -- |Proof that the baker knows the private key of this verification key.
      ubsProof :: !Dlog25519Proof
      }
  -- |Change which baker an account's stake is delegated to.
  -- If the ID is not valid, the delegation is not updated.
  | DelegateStake {
      -- |ID of the baker to delegate stake to.
      dsID :: !BakerId
      }
  -- |Undelegate stake.
  | UndelegateStake
  -- |Update the election difficulty birk parameter.
  -- Will only be accepted if sent from one of the special beta accounts.
  | UpdateElectionDifficulty {
      -- |The new election difficulty. Must be in the range [0,1).
      uedDifficulty :: !ElectionDifficulty
      }
  -- | Update the aggregation verification key of the baker
  | UpdateBakerAggregationVerifyKey {
      -- |Id of the baker to update
      ubavkId :: !BakerId,
      -- |New aggregation verification key
      ubavkKey :: !BakerAggregationVerifyKey,
      -- |Proof of knowledge of the signing key corresponding to the new verification key
      ubavkProof :: !BakerAggregationProof
      }
  -- | Update the election key of the baker
  | UpdateBakerElectionKey {
      -- |Id of the baker to update
      ubekId :: !BakerId,
      -- |New election key
      ubekKey :: !BakerElectionVerifyKey,
      -- |Proof of knowledge of the secret key corresponding to the new election key
      ubekProof :: !Dlog25519Proof
      }
  -- | Updates existing keys used for signing transactions for the sender's account
  | UpdateAccountKeys {
      -- |Update the account keys with to the ones in this map.
      uakKeys :: !(Map.Map KeyIndex AccountVerificationKey)
    }
  -- | Adds additional keys to the sender's account, optionally updating the signature threshold too
  | AddAccountKeys {
      -- |Map of key indices and the associated key to add
      aakKeys :: !(Map.Map KeyIndex AccountVerificationKey),
      -- |Optional value for updating the threshold of the signature scheme
      aakThreshold :: !(Maybe SignatureThreshold)
    }
  -- | Remove keys from the sender's account, optionally updating the signature threshold too
  | RemoveAccountKeys {
      -- |List of indices of keys to remove
      rakIndices :: !(Set.Set KeyIndex),
      -- |Optional value for updating the threshold of the signature scheme
      rakThreshold :: !(Maybe SignatureThreshold)
    }
  -- | Send an encrypted amount to an account.
  | EncryptedAmountTransfer {
      -- | Receiver account address.
      eatTo :: !AccountAddress,
      eatData :: !EncryptedAmountTransferData
  }
  -- | Transfer some amount from public to encrypted balance.
  | TransferToEncrypted {
      -- | The plaintext that will be deducted from the public balance.
      tteAmount :: !Amount
      }
  -- | Decrypt a portion of the encrypted balance.
  | TransferToPublic {
      ttpData :: !SecToPubAmountTransferData
      }
  deriving(Eq, Show)

$(genEnumerationType ''Payload "TransactionType" "TT" "getTransactionType")

instance S.Serialize TransactionType

-- |Payload serialization according to
--
--  * @SPEC: <$DOCS/Transactions#transaction-body>
putPayload :: Payload -> P.Put
putPayload DeployModule{..} =
    P.putWord8 0 <>
    S.put dmMod
putPayload InitContract{..} =
      P.putWord8 1 <>
      S.put icAmount <>
      S.put icModRef <>
      S.put icInitName <>
      S.put icParam
putPayload Update{..} =
    P.putWord8 2 <>
    S.put uAmount <>
    S.put uAddress <>
    S.put uReceiveName <>
    S.put uMessage
putPayload Transfer{..} =
    P.putWord8 3 <>
    S.put tToAddress <>
    S.put tAmount
putPayload AddBaker{..} =
    P.putWord8 4 <>
    S.put abElectionVerifyKey <>
    S.put abSignatureVerifyKey <>
    S.put abAggregationVerifyKey <>
    S.put abAccount <>
    S.put abProofSig <>
    S.put abProofElection <>
    S.put abProofAccount <>
    S.put abProofAggregation
putPayload RemoveBaker{..} =
    P.putWord8 5 <>
    S.put rbId
putPayload UpdateBakerAccount{..} =
    P.putWord8 6 <>
    S.put ubaId <>
    S.put ubaAddress <>
    S.put ubaProof
putPayload UpdateBakerSignKey{..} =
    P.putWord8 7 <>
    S.put ubsId <>
    S.put ubsKey <>
    S.put ubsProof
putPayload DelegateStake{..} =
    P.putWord8 8 <>
    S.put dsID
putPayload UndelegateStake =
    P.putWord8 9
putPayload UpdateElectionDifficulty{..} =
    P.putWord8 10 <>
    S.put uedDifficulty
putPayload UpdateBakerAggregationVerifyKey{..} =
    P.putWord8 11 <>
    S.put ubavkId <>
    S.put ubavkKey <>
    S.put ubavkProof
putPayload UpdateBakerElectionKey{..} =
    P.putWord8 12 <>
    S.put ubekId <>
    S.put ubekKey <>
    S.put ubekProof
putPayload UpdateAccountKeys{..} = do
    P.putWord8 13
    P.putWord8 (fromIntegral (length uakKeys))
    forM_ (Map.toAscList uakKeys) $ \(idx, key) -> S.put idx <> S.put key
putPayload AddAccountKeys{..} = do
    P.putWord8 14
    P.putWord8 (fromIntegral (length aakKeys))
    forM_ (Map.toAscList aakKeys) $ \(idx, key) -> S.put idx <> S.put key
    putMaybe aakThreshold
putPayload RemoveAccountKeys{..} = do
    P.putWord8 15
    P.putWord8 (fromIntegral (length rakIndices))
    forM_ (Set.toAscList rakIndices) S.put
    putMaybe rakThreshold
putPayload EncryptedAmountTransfer{eatData = EncryptedAmountTransferData{..}, ..} =
    S.putWord8 16 <>
    S.put eatTo <>
    S.put eatdRemainingAmount <>
    S.put eatdTransferAmount <>
    S.put eatdIndex <>
    putEncryptedAmountTransferProof eatdProof
putPayload TransferToEncrypted{..} =
    S.putWord8 17 <>
    S.put tteAmount
putPayload TransferToPublic{ttpData = SecToPubAmountTransferData{..}, ..} =
    S.putWord8 18 <>
    S.put stpatdRemainingAmount <>
    S.put stpatdTransferAmount <>
    S.put stpatdIndex <>
    putSecToPubAmountTransferProof stpatdProof

-- |Get the payload of the given size.
getPayload :: PayloadSize -> S.Get Payload
getPayload size = S.isolate (fromIntegral size) (S.bytesRead >>= go)
  -- isolate is required to consume all the bytes it is meant to.
  where go start = G.getWord8 >>= \case
            0 -> do
              dmMod <- S.get
              return DeployModule{..}
            1 -> do
              icAmount <- S.get
              icModRef <- S.get
              icInitName <- S.get
              icParam <- S.get
              return InitContract{..}
            2 -> do
              uAmount <- S.get
              uAddress <- S.get
              uReceiveName <- S.get
              uMessage <- S.get
              return Update{..}
            3 -> do
              tToAddress <- S.get
              tAmount <- S.get
              return Transfer{..}
            4 -> do
              abElectionVerifyKey <- S.get
              abSignatureVerifyKey <- S.get
              abAggregationVerifyKey <- S.get
              abAccount <- S.get
              abProofSig <- S.get
              abProofElection <- S.get
              abProofAccount <- S.get
              abProofAggregation <- S.get
              return AddBaker{..}
            5 -> do
              rbId <- S.get
              return RemoveBaker{..}
            6 -> do
              ubaId <- S.get
              ubaAddress <- S.get
              ubaProof <- S.get
              return UpdateBakerAccount{..}
            7 -> do
              ubsId <- S.get
              ubsKey <- S.get
              ubsProof <- S.get
              return UpdateBakerSignKey{..}
            8 -> DelegateStake <$> S.get
            9 -> return UndelegateStake
            10 -> do
              uedDifficulty <- S.get
              unless (isValidElectionDifficulty uedDifficulty) $
                fail $ "Illegal election difficulty: " ++ show uedDifficulty
              return UpdateElectionDifficulty{..}
            11 -> do
              ubavkId <- S.get
              ubavkKey <- S.get
              ubavkProof <- S.get
              return UpdateBakerAggregationVerifyKey{..}
            12 -> do
              ubekId <- S.get
              ubekKey <- S.get
              ubekProof <- S.get
              return UpdateBakerElectionKey{..}
            13 -> do
              len <- S.getWord8
              uakKeys <- safeFromAscList =<< replicateM (fromIntegral len) (S.getTwoOf S.get S.get)
              return UpdateAccountKeys{..}
            14 -> do
              len <- S.getWord8
              aakKeys <- safeFromAscList =<< replicateM (fromIntegral len) (S.getTwoOf S.get S.get)
              aakThreshold <- getMaybe
              return AddAccountKeys{..}
            15 -> do
              len <- S.getWord8
              rakIndices <- safeSetFromAscList =<< replicateM (fromIntegral len) S.get
              rakThreshold <- getMaybe
              return RemoveAccountKeys{..}
            16 -> do
              eatTo <- S.get
              eatdRemainingAmount <- S.get
              eatdTransferAmount <- S.get
              eatdIndex <- S.get
              cur <- S.bytesRead
              -- in the subtraction below overflow cannot happen because of guarantees and invariants of isolate
              -- and bytesRead
              eatdProof <- getEncryptedAmountTransferProof (thePayloadSize size - (fromIntegral $ cur - start))
              return EncryptedAmountTransfer{eatData = EncryptedAmountTransferData{..}, ..}
            17 -> do
              tteAmount <- S.get
              return TransferToEncrypted{..}
            18 -> do
              stpatdRemainingAmount <- S.get
              stpatdTransferAmount <- S.get
              stpatdIndex <- S.get
              cur <- S.bytesRead
              -- in the subtraction below overflow cannot happen because of guarantees and invariants of isolate
              -- and bytesRead
              stpatdProof <- getSecToPubAmountTransferProof (thePayloadSize size - (fromIntegral $ cur - start))
              return TransferToPublic{ttpData = SecToPubAmountTransferData{..}}
            n -> fail $ "unsupported transaction type '" ++ show n ++ "'"

-- |Serialize a Maybe value
-- Just v is serialized with a word8 tag 1 followed by the serialization of the value
-- Nothing is seralized with a word8 tag 0.
putMaybe :: S.Serialize a => P.Putter (Maybe a)
putMaybe (Just v) = do
  P.putWord8 1
  S.put v
putMaybe Nothing = S.putWord8 0

-- |Deserialize a Maybe value
-- Expects a leading 0 or 1 word8, 1 signaling Just and 0 signaling Nothing.
-- NB: This method is stricter than the Serialize instance method in that it only allows
-- tags 0 and 1, whereas the Serialize.get method allows any non-zero tag for Just.
getMaybe :: S.Serialize a => S.Get (Maybe a)
getMaybe = G.getWord8 >>=
    \case 0 -> return Nothing
          1 -> Just <$> S.get
          n -> fail $ "encountered invalid tag when deserializing a Maybe '" ++ show n ++ "'"

-- |Builds a set from a list of ascending elements.
-- Fails if the elements are not ordered or a duplicate is encountered.
safeSetFromAscList :: (MonadFail m, Ord a) => [a] -> m (Set.Set a)
safeSetFromAscList = go Set.empty Nothing
    where
      go s _ [] = return s
      go s Nothing (a : rest) = go (Set.insert a s) (Just a) rest
      go s (Just a') (a : rest)
        | (a' < a) = go (Set.insert a s) (Just a) rest
        | otherwise = fail "Elements are either not in ascending order, or a duplicate was found."

{-# INLINE encodePayload #-}
encodePayload :: Payload -> EncodedPayload
encodePayload = EncodedPayload . BSS.toShort . S.runPut . putPayload

#ifdef DISABLE_SMART_CONTRACTS
$(reportWarning "Disabling smart contract related transactions." >> return [])
decodePayload size (EncodedPayload s) =
  let bs = BSS.fromShort s
  in case BS.uncons bs of
       Nothing -> Left "Empty string not a valid payload."
       Just (ttype, _) ->
         if ttype == 0 ||  -- the numbers here must match the serialization of the payload above (Serialize instance)
            ttype == 1 ||
            ttype == 2 then
           Left "Unsupported transaction type."
         else S.runGet (getPayload size) bs
#else
$(reportWarning "All transaction types allowed." >> return [])
decodePayload size (EncodedPayload s) = S.runGet (getPayload size) . BSS.fromShort $ s
#endif
decodePayload :: PayloadSize -> EncodedPayload -> Either String Payload
{-# INLINE decodePayload #-}

{-# INLINE payloadBodyBytes #-}
-- |Get the body of the payload as bytes. Essentially just remove the
-- first byte which encodes the type.
payloadBodyBytes :: EncodedPayload -> BS.ByteString
payloadBodyBytes (EncodedPayload ss) =
  if BSS.null ss
  then BS.empty
  else BS.tail (BSS.fromShort ss)

-- |Additional special events that affect the block state.
data BlockEvents =
  -- |Block reward
  BlockReward !Amount !BakerId
  -- |Delegation reward
  | DelegationReward !Amount !BakerId
  -- |Foundation tax transfer
  | FoundationTax !Amount
  -- |Reward to a finalizer.
  | FinalizationReward !Amount !BakerId

-- |Events which are generated during transaction execution.
-- These are only used for commited transactions.
-- Must be kept in sync with 'showEvents' in concordium-client (Output.hs).
data Event =
           -- |Module with the given address was deployed.
           ModuleDeployed !ModuleRef
           -- |The contract was deployed.
           | ContractInitialized {
               -- |Module in which the contract source resides.
               ecRef :: !ModuleRef,
               -- |Reference to the contract as deployed.
               ecAddress :: !ContractAddress,
               -- |Initial amount transferred to the contract.
               ecAmount :: !Amount,
               -- |Events as reported by the contract via the log method, in the
               -- order they were reported.
               ecEvents :: [Wasm.ContractEvent]
               -- TODO: We could include initial state hash here.
               -- Including the whole state is likely not a good idea.
               }
           -- |The given contract was updated.
           | Updated {
               -- |Address of the contract that was updated.
               euAddress :: !ContractAddress,
               -- |Address of the instigator of the update, i.e. source of the message, an account or contract.
               euInstigator :: !Address,
               -- |Amount which was transferred to the contract.
               euAmount :: !Amount,
               -- |The message which was sent to the contract.
               euMessage :: !Wasm.Parameter,
               -- |Events as reported by the contract via the log method, in the
               -- order they were reported.
               euEvents :: [Wasm.ContractEvent]
               -- TODO: We could include input/output state hashes here
               -- Including the whole state pre/post run is likely not a good idea.
               }
           -- |Tokens were transferred.
           | Transferred {
               -- |Source.
               etFrom :: !Address,
               -- |Amount.
               etAmount :: !Amount,
               -- |Target.
               etTo :: !Address
               }
           -- |A new account was created.
           | AccountCreated !AccountAddress
           -- |A new credential was deployed onto a given account.
           | CredentialDeployed {
               -- |ID of the credential
               ecdRegId :: !IDTypes.CredentialRegistrationID,
               -- |Account to which it was deployed.
               ecdAccount :: !AccountAddress
               }
           | BakerAdded !BakerId
           | BakerRemoved !BakerId
           | BakerAccountUpdated {
               -- |The baker.
               ebauBaker :: !BakerId,
               -- |New account address
               ebauNewAccount :: !AccountAddress
               }
           | BakerKeyUpdated {
               -- |The baker.
               ebkuBaker :: !BakerId,
               -- |New key.
               ebkuNewKey :: !BakerSignVerifyKey
               }
           | BakerElectionKeyUpdated {
               -- |The baker.
               ebekuBaker :: !BakerId,
               -- |New key.
               ebekuNewKey :: !BakerElectionVerifyKey
               }
           | BakerAggregationKeyUpdated {
               -- |The baker.
               ebakuBaker :: !BakerId,
               -- |The updated key
               ebakuNewKey :: !BakerAggregationVerifyKey
               }
           | StakeDelegated {
               -- |Account which is delegating.
               esdAccount :: !AccountAddress,
               -- |To which baker.
               esdBaker :: !BakerId
               }
           | StakeUndelegated {
               -- |Account which undelegated the stake.
               esuAccount :: !AccountAddress,
               -- |The baker to which the account delegated before, if any.
               -- It is OK for an account to try to undelegate stake even if they
               -- are not delegating to anyone at the time.
               esuBaker :: !(Maybe BakerId)
               }
           | ElectionDifficultyUpdated {
               -- |The new election difficulty.
               eeduDifficulty :: !Double
               }
           -- |Keys at existing indexes were updated, no new indexes were added, threshold is unchanged
           | AccountKeysUpdated
           | AccountKeysAdded
           | AccountKeysRemoved
           | AccountKeysSignThresholdUpdated
           -- | New encrypted amount added to an account, with a given index.
           --
           -- This is used on the receiver's account when they get an encrypted amount transfer.
           | NewEncryptedAmount{
               neaAccount :: !AccountAddress,
               -- | Index of the new amount.
               neaNewIndex :: !EncryptedAmountIndex,
               -- | The actual amount.
               neaEncryptedAmount :: !EncryptedAmount
           }
           -- | A number of encrypted amounts were removed from an account, up-to, but not including
           -- the aggregation index. And a new encrypted amount has appeared that is the difference
           -- between what was sent, and what was used. This is the new self-amount after the transfer.
           --
           -- This is used on the sender's account when making an encrypted
           -- transfer, or transfer from the encrypted balance to public
           -- balance.
           | EncryptedAmountsRemoved{
               earAccount :: !AccountAddress,
               -- |The newly added amount.
               earNewAmount :: !EncryptedAmount,
               -- |Index up to (but not including) which the amounts were removed.
               earUpToIndex :: !EncryptedAmountAggIndex
            }
           -- | An encrypted amount was decrypted and added to the public balance of an account.
           -- This is used on an account when it makes a transfer to public transaction.
           | AmountAddedByDecryption {
               aabdAccount :: !AccountAddress,
               -- | The amount that was added to the public balance.
               aabdAmount :: !Amount
            }
           -- | A new encrypted amount was added to the self-encrypted-balance of the account.
           -- The amount given is the newly added one.
           | EncryptedSelfAmountAdded{
               eaaAccount :: !AccountAddress,
               eaaNewAmount :: !EncryptedAmount,
                -- | The amount that was subtracted from the public balance.
               eaaAmount :: !Amount
               }
  deriving (Show, Generic, Eq)

instance S.Serialize Event

-- |Index of the transaction in a block, starting from 0.
newtype TransactionIndex = TransactionIndex Word64
    deriving(Eq, Ord, Enum, Num, Show, Read, Real, Integral, S.Serialize, AE.ToJSON, AE.FromJSON) via Word64

-- |Result of a valid transaction is a transaction summary.
data TransactionSummary' a = TransactionSummary {
  tsSender :: !(Maybe AccountAddress),
  tsHash :: !TransactionHash,
  tsCost :: !Amount,
  tsEnergyCost :: !Energy,
  tsType :: !(Maybe TransactionType),
  tsResult :: !a,
  tsIndex :: !TransactionIndex
  } deriving(Eq, Show, Generic)

type TransactionSummary = TransactionSummary' ValidResult

-- |Outcomes of a valid transaction. Either a reject with a reason or a
-- successful transaction with a list of events which occurred during execution.
-- We also record the cost of the transaction.
data ValidResult = TxSuccess { vrEvents :: ![Event] } | TxReject { vrRejectReason :: !RejectReason }
  deriving(Show, Generic, Eq)

instance S.Serialize ValidResult
instance S.Serialize TransactionSummary

-- |Ways a single transaction can fail. Values of this type are only used for reporting of rejected transactions.
-- Must be kept in sync with 'showRejectReason' in concordium-client (Output.hs).
data RejectReason = ModuleNotWF -- ^Error raised when validating the Wasm module.
                  | ModuleHashAlreadyExists !ModuleRef  -- ^As the name says.
                  | InvalidAccountReference !AccountAddress -- ^Account does not exist.
                  | InvalidInitMethod !ModuleRef !Wasm.InitName -- ^Reference to a non-existing contract init method.
                  | InvalidReceiveMethod !ModuleRef !Wasm.ReceiveName -- ^Reference to a non-existing contract receive method.
                  | InvalidModuleReference !ModuleRef   -- ^Reference to a non-existing module.
                  | InvalidContractAddress !ContractAddress -- ^Contract instance does not exist.
                  | RuntimeFailure -- ^Runtime exception occurred when running either the init or receive method.
                  | ReceiverAccountNoCredential !AccountAddress
                  -- ^The receiver account does not have a valid credential.
                  | ReceiverContractNoCredential !ContractAddress
                  -- ^The receiver contract does not have a valid credential.
                  | AmountTooLarge !Address !Amount
                  -- ^When one wishes to transfer an amount from A to B but there
                  -- are not enough funds on account/contract A to make this
                  -- possible. The data are the from address and the amount to transfer.
                  | SerializationFailure -- ^Serialization of the body failed.
                  | OutOfEnergy -- ^We ran of out energy to process this transaction.
                  | Rejected -- ^Rejected due to contract logic.
                  | NonExistentRewardAccount !AccountAddress -- ^Reward account desired by the baker does not exist.
                  | InvalidProof -- ^Proof that the baker owns relevant private keys is not valid.
                  | RemovingNonExistentBaker !BakerId
                  | InvalidBakerRemoveSource !AccountAddress
                  | UpdatingNonExistentBaker !BakerId
                  | InvalidStakeDelegationTarget !BakerId -- ^The target of stake delegation is not a valid baker.
                  | DuplicateSignKey !BakerSignVerifyKey -- ^A baker with the given signing key already exists.
                  | DuplicateAggregationKey !BakerAggregationVerifyKey -- ^A baker with the given aggregation key already exists
                  -- |A transaction should be sent from the baker's current account, but is not.
                  | NotFromBakerAccount { nfbaFromAccount :: !AccountAddress, -- ^Sender account of the transaction
                                          nfbaCurrentBakerAccount :: !AccountAddress -- ^Current baker account.
                                        }
                  -- |A transaction should be sent from a special account, but is not.
                  | NotFromSpecialAccount
                  -- |Encountered index to which no account key belongs when removing or updating keys
                  | NonExistentAccountKey
                  -- |Attempted to add an account key to a key index already in use
                  | KeyIndexAlreadyInUse
                  -- |When the account key threshold is updated, it must not exceed the amount of existing keys
                  | InvalidAccountKeySignThreshold
                  -- |Proof for an encrypted amount transfer did not validate.
                  | InvalidEncryptedAmountTransferProof
                  -- |Proof for a secret to public transfer did not validate.
                  | InvalidTransferToPublicProof
                  -- |Account tried to transfer an encrypted amount to itself, that's not allowed.
                  | EncryptedAmountSelfTransfer !AccountAddress
    deriving (Show, Eq, Generic)

wasmRejectToRejectReason :: Wasm.ContractExecutionFailure -> RejectReason
wasmRejectToRejectReason Wasm.ContractReject = Rejected
wasmRejectToRejectReason Wasm.RuntimeFailure = RuntimeFailure

instance S.Serialize RejectReason
instance AE.ToJSON RejectReason
instance AE.FromJSON RejectReason

-- | Reasons for the execution of a transaction to fail on the current block state.
data FailureKind = InsufficientFunds -- ^The sender account's amount is not sufficient to cover the
                                     -- amount corresponding to the deposited energy.
                 | IncorrectSignature  -- ^Signature check failed.
                 | NonSequentialNonce !Nonce -- ^The transaction nonce is not
                                             -- next in sequence. The argument
                                             -- is the expected nonce.
                 | SuccessorOfInvalidTransaction -- ^In the context of processing multiple transactions
                                                 -- from the same account, the transaction is a successor
                                                 -- of (has the nonce following that of) an invalid transaction.
                 | UnknownAccount !AccountAddress -- ^Transaction is coming from an unknown sender.
                 | DepositInsufficient -- ^The dedicated gas amount was lower than the minimum allowed.
                 | NoValidCredential -- ^No valid credential on the sender account.
                 | ExpiredTransaction -- ^The transaction has expired.
                 | ExceedsMaxBlockEnergy -- ^The transaction's deposited energy exceeds the maximum block energy limit.
                 | ExceedsMaxBlockSize -- ^The baker decided that this transaction is too big to put in a block.
                 | NonExistentIdentityProvider !IDTypes.IdentityProviderIdentity
                 | UnsupportedAnonymityRevokers -- ^One of the anonymity revokers in the credential is not known.
                 | NonExistentAccount !AccountAddress -- ^Cannot deploy credential onto a non-existing account.
                 | AccountCredentialInvalid -- ^Account credential verification failed, the proofs were invalid or malformed.
                 | DuplicateAccountRegistrationID !IDTypes.CredentialRegistrationID
      deriving(Eq, Show)

data TxResult = TxValid !TransactionSummary | TxInvalid !FailureKind

-- FIXME: These intances need to be made clearer.
$(deriveJSON AE.defaultOptions{AE.fieldLabelModifier = firstLower . dropWhile isLower} ''Event)

-- Derive JSON instance for transaction outcomes
-- At the end of the file to avoid issues with staging restriction.
$(deriveJSON AE.defaultOptions{AE.constructorTagModifier = firstLower . drop 2,
                                 AE.sumEncoding = AE.TaggedObject{
                                    AE.tagFieldName = "outcome",
                                    AE.contentsFieldName = "details"
                                    },
                                 AE.fieldLabelModifier = firstLower . drop 2} ''ValidResult)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . drop 2} ''TransactionSummary')

$(deriveJSON defaultOptions{AE.constructorTagModifier = firstLower . drop 2} ''TransactionType)
