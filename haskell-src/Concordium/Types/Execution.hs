{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE EmptyCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE GADTs #-}
module Concordium.Types.Execution where

import Prelude hiding(fail)

import Control.Monad.Reader

import Data.Char
import qualified Data.Aeson as AE
import Data.Aeson((.=), (.:))
import Data.Aeson.TH
import qualified Data.HashMap.Strict as HMap
import qualified Data.Map as Map
import qualified Data.Serialize.Put as P
import qualified Data.Serialize.Get as G
import qualified Data.Serialize as S
import Concordium.Utils.Serialization
import qualified Data.Set as Set
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as BSS

import Data.Int (Int32)
import Data.Word
import GHC.Generics

import qualified Concordium.Wasm as Wasm
import Concordium.Types
import Concordium.Utils
import Concordium.Types.Execution.TH
import Concordium.Types.Updates
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
  -- |Add a new baker for the sender account.
  | AddBaker {
      -- |Public key to verify the baker has won the election.
      abElectionVerifyKey :: !BakerElectionVerifyKey,
      -- |Public key to verify block signatures signed by the baker.
      abSignatureVerifyKey :: !BakerSignVerifyKey,
      -- |Public key to verify aggregate signatures in which the baker participates
      abAggregationVerifyKey :: !BakerAggregationVerifyKey,
      -- |Proof that the baker owns the private key corresponding to the
      -- signature verification key.
      abProofSig :: !Dlog25519Proof,
      -- |Proof that the baker owns the private key corresponding to the
      -- election verification key.
      abProofElection :: !Dlog25519Proof,
      -- |Proof that the baker owns the private key corresponding to the aggregation
      -- key.
      abProofAggregation :: !BakerAggregationProof,
      -- |Initial stake. This amount must be available on the account,
      -- and will be locked.
      abBakingStake :: !Amount,
      -- |Whether earnings from being a baker should be automatically added
      -- to the stake.
      abRestakeEarnings :: !Bool
      }
  -- |Remove the sender account from the baking pool.
  | RemoveBaker
  -- |Update the amount of stake that is locked for the baker.
  | UpdateBakerStake {
      ubsStake :: !Amount
      }
  -- |Update whether the baker's earnings are automatically restaked.
  | UpdateBakerRestakeEarnings {
      ubreRestakeEarnings :: !Bool
      }
  -- |Update the baker's keys
  | UpdateBakerKeys {
      -- |Public key to verify the baker has won the election.
      ubkElectionVerifyKey :: !BakerElectionVerifyKey,
      -- |Public key to verify block signatures signed by the baker.
      ubkSignatureVerifyKey :: !BakerSignVerifyKey,
      -- |Public key to verify aggregate signatures in which the baker participates
      ubkAggregationVerifyKey :: !BakerAggregationVerifyKey,
      -- |Proof that the baker owns the private key corresponding to the
      -- signature verification key.
      ubkProofSig :: !Dlog25519Proof,
      -- |Proof that the baker owns the private key corresponding to the
      -- election verification key.
      ubkProofElection :: !Dlog25519Proof,
      -- |Proof that the baker owns the private key corresponding to the aggregation
      -- key.
      ubkProofAggregation :: !BakerAggregationProof
      }
  -- | Adds additional keys to the sender's account, optionally updating the signature threshold too
  | UpdateCredentialKeys {
      -- | New set of credential keys to be replaced with the existing ones, including updating the threshold.
      uckCredId :: !CredentialRegistrationID,
      uckKeys :: !CredentialPublicKeys
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
  -- | Send a transfer with an attached schedule.
  | TransferWithSchedule {
      twsTo :: !AccountAddress,
      twsSchedule :: ![(Timestamp, Amount)]
      }
  -- | Updating the account threshold and the credentials linked to an account by adding or removing credentials. The credential with index 0 can never be removed.
  | UpdateCredentials {
      ucNewCredInfos :: !(Map.Map CredentialIndex CredentialDeploymentInformation),
      ucRemoveCredIds :: ![CredentialRegistrationID],
      ucNewThreshold :: !AccountThreshold
  }
  -- | Register data on the chain.
  | RegisterData {
      -- | The data to register.
      rdData :: !RegisteredData
  }
  -- |Simple transfer from an account to an account with additional memo.
  | TransferWithMemo {
      -- |Recepient.
      twmToAddress :: !AccountAddress,
      -- |Memo.
      twmMemo :: !Memo,
      -- |Amount to transfer.
      twmAmount :: !Amount
      }
  -- | Send an encrypted amount to an account with additional memo.
  | EncryptedAmountTransferWithMemo {
      -- | Receiver account address.
      eatwmTo :: !AccountAddress,
      -- |Memo.
      eatwmMemo :: !Memo,
      eatwmData :: !EncryptedAmountTransferData
  }
  -- | Send a transfer with an attached schedule and additional memo.
  | TransferWithScheduleAndMemo {
      twswmTo :: !AccountAddress,
      -- |Memo.
      twswmMemo :: !Memo,
      twswmSchedule :: ![(Timestamp, Amount)]
      }
  deriving(Eq, Show)

$(genEnumerationType ''Payload "TransactionType" "TT" "getTransactionType")

-- NB: This serialization instance would ideally match the tags used when
-- serializing the 'Payload'. Unfortunately in the past (at least for protocol
-- versions 1 and 2) it was derived automatically so it did not match. The
-- instance is now explicit, but to retain compatibility it must match what it
-- used to be.
instance S.Serialize TransactionType where
  put = \case
    TTDeployModule -> S.putWord8 0
    TTInitContract -> S.putWord8 1
    TTUpdate -> S.putWord8 2
    TTTransfer -> S.putWord8 3
    TTAddBaker -> S.putWord8 4
    TTRemoveBaker -> S.putWord8 5
    TTUpdateBakerStake -> S.putWord8 6
    TTUpdateBakerRestakeEarnings -> S.putWord8 7
    TTUpdateBakerKeys -> S.putWord8 8
    TTUpdateCredentialKeys -> S.putWord8 9
    TTEncryptedAmountTransfer -> S.putWord8 10
    TTTransferToEncrypted -> S.putWord8 11
    TTTransferToPublic -> S.putWord8 12
    TTTransferWithSchedule -> S.putWord8 13
    TTUpdateCredentials -> S.putWord8 14
    TTRegisterData -> S.putWord8 15
    TTTransferWithMemo -> S.putWord8 16
    TTEncryptedAmountTransferWithMemo -> S.putWord8 17
    TTTransferWithScheduleAndMemo -> S.putWord8 18

  get = S.getWord8 >>= \case
    0 -> return TTDeployModule
    1 -> return TTInitContract
    2 -> return TTUpdate
    3 -> return TTTransfer
    4 -> return TTAddBaker
    5 -> return TTRemoveBaker
    6 -> return TTUpdateBakerStake
    7 -> return TTUpdateBakerRestakeEarnings
    8 -> return TTUpdateBakerKeys
    9 -> return TTUpdateCredentialKeys
    10 -> return TTEncryptedAmountTransfer
    11 -> return TTTransferToEncrypted
    12 -> return TTTransferToPublic
    13 -> return TTTransferWithSchedule
    14 -> return TTUpdateCredentials
    15 -> return TTRegisterData
    16 -> return TTTransferWithMemo
    17 -> return TTEncryptedAmountTransferWithMemo
    18 -> return TTTransferWithScheduleAndMemo
    n -> fail $ "Unrecognized TransactionType tag: " ++ show n

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
    S.put abProofSig <>
    S.put abProofElection <>
    S.put abProofAggregation <>
    S.put abBakingStake <>
    putBool abRestakeEarnings
putPayload RemoveBaker =
    P.putWord8 5
putPayload UpdateBakerStake{..} =
    P.putWord8 6 <>
    S.put ubsStake
putPayload UpdateBakerRestakeEarnings{..} =
    P.putWord8 7 <>
    putBool ubreRestakeEarnings
putPayload UpdateBakerKeys{..} =
    P.putWord8 8 <>
    S.put ubkElectionVerifyKey <>
    S.put ubkSignatureVerifyKey <>
    S.put ubkAggregationVerifyKey <>
    S.put ubkProofSig <>
    S.put ubkProofElection <>
    S.put ubkProofAggregation
putPayload UpdateCredentialKeys{..} = do
    P.putWord8 13
    S.put uckCredId
    S.put uckKeys
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
putPayload TransferToPublic{ttpData = SecToPubAmountTransferData{..}} =
    S.putWord8 18 <>
    S.put stpatdRemainingAmount <>
    S.put stpatdTransferAmount <>
    S.put stpatdIndex <>
    putSecToPubAmountTransferProof stpatdProof
putPayload TransferWithSchedule{..} =
    S.putWord8 19 <>
    S.put twsTo <>
    P.putWord8 (fromIntegral (length twsSchedule)) <>
    forM_ twsSchedule (\(a,b) -> S.put a >> S.put b)
putPayload UpdateCredentials{..} =
    S.putWord8 20 <>
    S.putWord8 (fromIntegral (Map.size ucNewCredInfos)) <>
    putSafeSizedMapOf S.put S.put ucNewCredInfos <>
    S.putWord8 (fromIntegral (length ucRemoveCredIds)) <>
    mapM_ S.put ucRemoveCredIds <>
    S.put ucNewThreshold
putPayload RegisterData{..} =
  S.putWord8 21 <>
  S.put rdData
putPayload TransferWithMemo{..} =
    P.putWord8 22 <>
    S.put twmToAddress <>
    S.put twmMemo <>
    S.put twmAmount
putPayload EncryptedAmountTransferWithMemo{eatwmData = EncryptedAmountTransferData{..}, ..} =
    S.putWord8 23 <>
    S.put eatwmTo <>
    S.put eatwmMemo <>
    S.put eatdRemainingAmount <>
    S.put eatdTransferAmount <>
    S.put eatdIndex <>
    putEncryptedAmountTransferProof eatdProof
putPayload TransferWithScheduleAndMemo{..} =
    S.putWord8 24 <>
    S.put twswmTo <>
    S.put twswmMemo <>
    P.putWord8 (fromIntegral (length twswmSchedule)) <>
    forM_ twswmSchedule (\(a,b) -> S.put a >> S.put b)


-- |Get the payload of the given size.
getPayload :: SProtocolVersion pv -> PayloadSize -> S.Get Payload
getPayload spv size = S.isolate (fromIntegral size) (S.bytesRead >>= go)
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
              abProofSig <- S.get
              abProofElection <- S.get
              abProofAggregation <- S.get
              abBakingStake <- S.get
              abRestakeEarnings <- getBool
              return AddBaker{..}
            5 -> do
              return RemoveBaker
            6 -> S.label "UpdateBakerStake" $ do
              ubsStake <- S.get
              return UpdateBakerStake{..}
            7 -> S.label "RestakeEarnings" $ do
              ubreRestakeEarnings <- getBool
              return UpdateBakerRestakeEarnings{..}
            8 -> do
              ubkElectionVerifyKey <- S.get
              ubkSignatureVerifyKey <- S.get
              ubkAggregationVerifyKey <- S.get
              ubkProofSig <- S.get
              ubkProofElection <- S.get
              ubkProofAggregation <- S.get
              return UpdateBakerKeys{..}
            13 -> do
              uckCredId <- S.get
              uckKeys <- S.get
              return UpdateCredentialKeys{..}
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
            19 -> do
              twsTo <- S.get
              len <- S.getWord8
              twsSchedule <- replicateM (fromIntegral len) (S.get >>= \s -> S.get >>= \t -> return (s,t))
              return TransferWithSchedule{..}
            20 -> do
              newInfosLen <- S.getWord8
              ucNewCredInfos <- getSafeSizedMapOf newInfosLen S.get S.get
              removeCredsLen <- S.getWord8
              ucRemoveCredIds <- replicateM (fromIntegral removeCredsLen) S.get
              ucNewThreshold <- S.get
              return UpdateCredentials{..}
            21 -> do
              rdData <- S.get
              return RegisterData{..}
            22 | supportMemo -> do
              twmToAddress <- S.get
              twmMemo <- S.get
              twmAmount <- S.get
              return TransferWithMemo{..}
            23 | supportMemo -> do
              eatwmTo <- S.get
              eatwmMemo <- S.get
              eatdRemainingAmount <- S.get
              eatdTransferAmount <- S.get
              eatdIndex <- S.get
              cur <- S.bytesRead
              -- in the subtraction below overflow cannot happen because of guarantees and invariants of isolate
              -- and bytesRead
              eatdProof <- getEncryptedAmountTransferProof (thePayloadSize size - (fromIntegral $ cur - start))
              return EncryptedAmountTransferWithMemo{eatwmData = EncryptedAmountTransferData{..}, ..}
            24 | supportMemo -> do
              twswmTo <- S.get
              twswmMemo <- S.get
              len <- S.getWord8
              twswmSchedule <- replicateM (fromIntegral len) (S.get >>= \s -> S.get >>= \t -> return (s,t))
              return TransferWithScheduleAndMemo{..}
            n -> fail $ "unsupported transaction type '" ++ show n ++ "'"
        supportMemo = case spv of
          SP1 -> False
          _ -> True

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

decodePayload :: SProtocolVersion pv -> PayloadSize -> EncodedPayload -> Either String Payload
decodePayload spv size (EncodedPayload s) = S.runGet (getPayload spv size) . BSS.fromShort $ s
{-# INLINE decodePayload #-}

{-# INLINE payloadBodyBytes #-}
-- |Get the body of the payload as bytes. Essentially just remove the
-- first byte which encodes the type.
payloadBodyBytes :: EncodedPayload -> BS.ByteString
payloadBodyBytes (EncodedPayload ss) =
  if BSS.null ss
  then BS.empty
  else BS.tail (BSS.fromShort ss)

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
               -- |Name of the contract init function being called
               ecInitName :: !Wasm.InitName,
               -- |Events as reported by the contract via the log method, in the
               -- order they were reported.
               ecEvents :: ![Wasm.ContractEvent]
               -- TODO: We could include initial state hash here.
               -- Including the whole state is likely not a good idea.
               }
           -- |The given V0 contract was updated.
           | Updated {
               -- |Address of the contract that was updated.
               euAddress :: !ContractAddress,
               -- |Address of the instigator of the update, i.e. source of the message, an account or contract.
               euInstigator :: !Address,
               -- |Amount which was transferred to the contract.
               euAmount :: !Amount,
               -- |The message which was sent to the contract.
               euMessage :: !Wasm.Parameter,
               -- |Name of the contract receive function being called
               euReceiveName :: !Wasm.ReceiveName,
               -- |Events as reported by the contract via the log method, in the
               -- order they were reported.
               euEvents :: ![Wasm.ContractEvent]
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
           -- |A baker was added.
           | BakerAdded {
              -- |Baker's id
              ebaBakerId :: !BakerId,
              -- |Baker account
              ebaAccount :: !AccountAddress,
              -- |Signing public key
              ebaSignKey :: !BakerSignVerifyKey,
              -- |VRF public key
              ebaElectionKey :: !BakerElectionVerifyKey,
              -- |Aggregation public key
              ebaAggregationKey :: !BakerAggregationVerifyKey,
              -- |Baker stake
              ebaStake :: !Amount,
              -- |Whether baker earnings are automatically staked
              ebaRestakeEarnings :: !Bool
           }
           -- |A baker was removed.
           | BakerRemoved {
              -- |Baker's id
              ebrBakerId :: !BakerId,
              -- |Baker account
              ebrAccount :: !AccountAddress
           }
           -- |A baker's stake was increased.
           | BakerStakeIncreased {
              -- |Baker's id
              ebsiBakerId :: !BakerId,
              -- |Baker account
              ebsiAccount :: !AccountAddress,
              -- |New stake
              ebsiNewStake :: !Amount
           }
           -- |A baker's stake was decreased.
           | BakerStakeDecreased {
              -- |Baker's id
              ebsiBakerId :: !BakerId,
              -- |Baker account
              ebsiAccount :: !AccountAddress,
              -- |New stake
              ebsiNewStake :: !Amount
           }
           -- |A baker's restake earnings flag was set.
           | BakerSetRestakeEarnings {
              -- |Baker's id
              ebsreBakerId :: !BakerId,
              -- |Baker account
              ebsreAccount :: !AccountAddress,
              -- |Whether earnings will be restaked
              ebsreRestakeEarnings :: !Bool
           }
           -- |A baker's keys were updated.
           | BakerKeysUpdated {
              -- |Baker's id
              ebkuBakerId :: !BakerId,
              -- |Baker account
              ebkuAccount :: !AccountAddress,
              -- |Signing public key
              ebkuSignKey :: !BakerSignVerifyKey,
              -- |VRF public key
              ebkuElectionKey :: !BakerElectionVerifyKey,
              -- |Aggregation public key
              ebkuAggregationKey :: !BakerAggregationVerifyKey
           }
           -- | A set of credential keys was updated. Also covers the case of updating the signature threshold for the credential in question
           | CredentialKeysUpdated {
             -- |The credential that had its keys and threshold updated.
             ckuCredId :: !CredentialRegistrationID
           }
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
               -- |The new self amount.
               earNewAmount :: !EncryptedAmount,
               -- |Input encrypted amount that was consumed.
               earInputAmount :: !EncryptedAmount,
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
           | UpdateEnqueued {
             ueEffectiveTime :: !TransactionTime,
             uePayload :: !UpdatePayload
           }
           | TransferredWithSchedule {
               etwsFrom :: !AccountAddress,
               etwsTo :: !AccountAddress,
               etwsAmount :: ![(Timestamp, Amount)]
               }
           | CredentialsUpdated {
               cuAccount :: !AccountAddress,
               -- |A list of newly added credentials. No order is guaranteed.
               cuNewCredIds :: ![CredentialRegistrationID],
               -- |A list of credentials that were removed from the account.
               cuRemovedCredIds :: ![CredentialRegistrationID],
               -- |A new account threshold.
               cuNewThreshold :: !AccountThreshold
              }
           -- | Data was registered on the chain.
           | DataRegistered {
               -- | The actual data.
               drData :: !RegisteredData
           }
           -- | Memo from simple transfer, encrypted transfer or scheduled transfer.
           | TransferMemo {
               -- | The memo.
               tmMemo :: !Memo
           }
           -- | Contract invocation was interrupted. This only applies to V1 contracts.
           | Interrupted {
               -- |Address of the contract that was interrupted.
               iAddress :: !ContractAddress,
               -- |Partial event log generated in the execution before the interrupt.
               iEvents :: ![Wasm.ContractEvent]
               }
           -- | Contract execution resumed. This only applies to V1 contracts.
           | Resumed {
               -- |Address of the contract that was interrupted.
               rAddress :: !ContractAddress,
               -- |Whether the operation succeeded.
               rSuccess :: !Bool
               }

  deriving (Show, Generic, Eq)

instance S.Serialize Event where
  put = \case ModuleDeployed mref ->
                S.putWord8 0 <>
                S.put mref
              ContractInitialized{..} ->
                S.putWord8 1 <>
                S.put ecRef <>
                S.put ecAddress <>
                S.put ecAmount <>
                S.put ecInitName <>
                putListOf S.put ecEvents
              Updated{..} ->
                S.putWord8 2 <>
                S.put euAddress <>
                S.put euInstigator <>
                S.put euAmount <>
                S.put euMessage <>
                S.put euReceiveName <>
                putListOf S.put euEvents
              Transferred{..} ->
                S.putWord8 3 <>
                S.put etFrom <>
                S.put etAmount <>
                S.put etTo
              AccountCreated addr ->
                S.putWord8 4 <>
                S.put addr
              CredentialDeployed{..} ->
                S.putWord8 5 <>
                S.put ecdRegId <>
                S.put ecdAccount
              BakerAdded {..} ->
                S.putWord8 6 <>
                S.put ebaBakerId <>
                S.put ebaAccount <>
                S.put ebaSignKey <>
                S.put ebaElectionKey <>
                S.put ebaAggregationKey <>
                S.put ebaStake <>
                putBool ebaRestakeEarnings
              BakerRemoved {..} ->
                S.putWord8 7 <>
                S.put ebrBakerId <>
                S.put ebrAccount
              BakerStakeIncreased {..} ->
                S.putWord8 8 <>
                S.put ebsiBakerId <>
                S.put ebsiAccount <>
                S.put ebsiNewStake
              BakerStakeDecreased {..} ->
                S.putWord8 9 <>
                S.put ebsiBakerId <>
                S.put ebsiAccount <>
                S.put ebsiNewStake
              BakerSetRestakeEarnings {..} ->
                S.putWord8 10 <>
                S.put ebsreBakerId <>
                S.put ebsreAccount <>
                putBool ebsreRestakeEarnings
              BakerKeysUpdated {..} ->
                S.putWord8 11 <>
                S.put ebkuBakerId <>
                S.put ebkuAccount <>
                S.put ebkuSignKey <>
                S.put ebkuElectionKey <>
                S.put ebkuAggregationKey
              CredentialKeysUpdated {..} ->
                S.putWord8 12 <>
                S.put ckuCredId
              NewEncryptedAmount{..} ->
                S.putWord8 13 <>
                S.put neaAccount <>
                S.put neaNewIndex <>
                S.put neaEncryptedAmount
              EncryptedAmountsRemoved{..} ->
                S.putWord8 14 <>
                S.put earAccount <>
                S.put earNewAmount <>
                S.put earInputAmount <>
                S.put earUpToIndex
              AmountAddedByDecryption {..} ->
                S.putWord8 15 <>
                S.put aabdAccount <>
                S.put aabdAmount
              EncryptedSelfAmountAdded{..} ->
                S.putWord8 16 <>
                S.put eaaAccount <>
                S.put eaaNewAmount <>
                S.put eaaAmount
              UpdateEnqueued {..} ->
                S.putWord8 17 <>
                S.put ueEffectiveTime <>
                S.put uePayload
              TransferredWithSchedule {..} ->
                S.putWord8 18 <>
                S.put etwsFrom <>
                S.put etwsTo <>
                putListOf S.put etwsAmount
              CredentialsUpdated {..} ->
                S.putWord8 19 <>
                S.put cuAccount <>
                putListOf S.put cuNewCredIds <>
                putListOf S.put cuRemovedCredIds <>
                S.put cuNewThreshold
              DataRegistered {..} ->
                S.putWord8 20 <>
                S.put drData
              TransferMemo {..} ->
                S.putWord8 21 <>
                S.put tmMemo
              Interrupted {..} ->
                S.putWord8 22 <>
                S.put iAddress <>
                putListOf S.put iEvents
              Resumed {..} ->
                S.putWord8 23 <>
                S.put rAddress <>
                putBool rSuccess

  get = S.getWord8 >>= \case
    0 -> do
      mref <- S.get
      return (ModuleDeployed mref)
    1 -> do
      ecRef <- S.get
      ecAddress <- S.get
      ecAmount <- S.get
      ecInitName <- S.get
      ecEvents <- getListOf S.get
      return ContractInitialized{..}
    2 -> do
      euAddress <- S.get
      euInstigator <- S.get
      euAmount <- S.get
      euMessage <- S.get
      euReceiveName <- S.get
      euEvents <- getListOf S.get
      return Updated{..}
    3 -> do
      etFrom <- S.get
      etAmount <- S.get
      etTo <- S.get
      return Transferred{..}
    4 -> do
      addr <- S.get
      return $ AccountCreated addr
    5 -> do
      ecdRegId <- S.get
      ecdAccount <- S.get
      return CredentialDeployed{..}
    6 -> do
      ebaBakerId  <- S.get
      ebaAccount  <- S.get
      ebaSignKey  <- S.get
      ebaElectionKey  <- S.get
      ebaAggregationKey  <- S.get
      ebaStake  <- S.get
      ebaRestakeEarnings <- getBool
      return BakerAdded {..}
    7 -> do
      ebrBakerId  <- S.get
      ebrAccount <- S.get
      return BakerRemoved {..}
    8 -> do
      ebsiBakerId  <- S.get
      ebsiAccount  <- S.get
      ebsiNewStake <- S.get
      return BakerStakeIncreased {..}
    9 -> do
      ebsiBakerId  <- S.get
      ebsiAccount  <- S.get
      ebsiNewStake <- S.get
      return BakerStakeDecreased {..}
    10 -> do
      ebsreBakerId  <- S.get
      ebsreAccount  <- S.get
      ebsreRestakeEarnings <- getBool
      return BakerSetRestakeEarnings {..}
    11 -> do
      ebkuBakerId  <- S.get
      ebkuAccount  <- S.get
      ebkuSignKey  <- S.get
      ebkuElectionKey  <- S.get
      ebkuAggregationKey <- S.get
      return BakerKeysUpdated {..}
    12 -> do
      ckuCredId <- S.get
      return CredentialKeysUpdated {..}
    13 -> do
      neaAccount  <- S.get
      neaNewIndex  <- S.get
      neaEncryptedAmount <- S.get
      return NewEncryptedAmount{..}
    14 -> do
      earAccount  <- S.get
      earNewAmount  <- S.get
      earInputAmount  <- S.get
      earUpToIndex <- S.get
      return EncryptedAmountsRemoved{..}
    15 -> do
      aabdAccount  <- S.get
      aabdAmount <- S.get
      return AmountAddedByDecryption {..}
    16 -> do
      eaaAccount  <- S.get
      eaaNewAmount  <- S.get
      eaaAmount <- S.get
      return EncryptedSelfAmountAdded{..}
    17 -> do
      ueEffectiveTime  <- S.get
      uePayload <- S.get
      return UpdateEnqueued {..}
    18 -> do
      etwsFrom  <- S.get
      etwsTo  <- S.get
      etwsAmount <- getListOf S.get
      return TransferredWithSchedule {..}
    19 -> do
      cuAccount  <- S.get
      cuNewCredIds  <- getListOf S.get
      cuRemovedCredIds  <- getListOf S.get
      cuNewThreshold <- S.get
      return CredentialsUpdated {..}
    20 -> do
      drData <- S.get
      return DataRegistered {..}
    21 -> do
      tmMemo <- S.get
      return  TransferMemo {..}
    22 -> do
      iAddress <- S.get
      iEvents <- getListOf S.get
      return Interrupted{..}
    23 -> do
      rAddress <- S.get
      rSuccess <- getBool
      return Resumed{..}
    n -> fail $ "Unrecognized event tag: " ++ show n



-- |Index of the transaction in a block, starting from 0.
newtype TransactionIndex = TransactionIndex Word64
    deriving(Eq, Ord, Enum, Num, Show, Read, Real, Integral, S.Serialize, AE.ToJSON, AE.FromJSON) via Word64

-- |The 'Maybe TransactionType' is to cover the case of a transaction payload
-- that cannot be deserialized. A transaction is still included in a block, but
-- it does not have a type.
data TransactionSummaryType =
  TSTAccountTransaction !(Maybe TransactionType)
  | TSTCredentialDeploymentTransaction !CredentialType
  | TSTUpdateTransaction !UpdateType
  deriving(Eq, Show)

instance AE.ToJSON TransactionSummaryType where
  toJSON (TSTAccountTransaction mtt) = AE.object ["type" .= AE.String "accountTransaction", "contents" .= mtt]
  toJSON (TSTCredentialDeploymentTransaction ct) = AE.object ["type" .= AE.String "credentialDeploymentTransaction", "contents" .= ct]
  toJSON (TSTUpdateTransaction ut) = AE.object ["type" .= AE.String "updateTransaction", "contents" .= ut]

instance AE.FromJSON TransactionSummaryType where
  parseJSON = AE.withObject "Transactions summary type" $ \v -> do
    ty <- v .: "type"
    case ty of
      AE.String "accountTransaction" -> TSTAccountTransaction <$> v .: "contents"
      AE.String "credentialDeploymentTransaction" -> TSTCredentialDeploymentTransaction <$> v .: "contents"
      AE.String "updateTransaction" -> TSTUpdateTransaction <$> v .: "contents"
      _ -> fail "Cannot parse JSON TransactionSummaryType"

-- |Result of a valid transaction is a transaction summary.
data TransactionSummary' a = TransactionSummary {
  tsSender :: !(Maybe AccountAddress),
  tsHash :: !TransactionHash,
  tsCost :: !Amount,
  tsEnergyCost :: !Energy,
  tsType :: !TransactionSummaryType,
  tsResult :: !a,
  tsIndex :: !TransactionIndex
  } deriving(Eq, Show, Generic)

type TransactionSummary = TransactionSummary' ValidResult

-- |Outcomes of a valid transaction. Either a reject with a reason or a
-- successful transaction with a list of events which occurred during execution.
-- We also record the cost of the transaction.
data ValidResult = TxSuccess { vrEvents :: ![Event] } | TxReject { vrRejectReason :: !RejectReason }
  deriving(Show, Generic, Eq)

instance S.Serialize ValidResult where
  put TxSuccess{..} = S.putWord8 0 <> putListOf S.put vrEvents
  put TxReject{..} = S.putWord8 1 <> S.put vrRejectReason

  get = S.getWord8 >>= \case
    0 -> TxSuccess <$> getListOf S.get
    1 -> TxReject <$> S.get
    n -> fail $ "Unrecognized ValidResult tag: " ++ show n

instance S.Serialize TransactionSummaryType where
  put (TSTAccountTransaction tt) = S.putWord8 0 <> putMaybe S.put tt
  put (TSTCredentialDeploymentTransaction credType) = S.putWord8 1 <> S.put credType
  put (TSTUpdateTransaction ut) = S.putWord8 2 <> S.put ut

  get = S.getWord8 >>= \case
    0 -> TSTAccountTransaction <$> getMaybe S.get
    1 -> TSTCredentialDeploymentTransaction <$> S.get
    2 -> TSTUpdateTransaction <$> S.get
    _ -> fail "Unsupported transaction summary type."

instance S.Serialize TransactionSummary where
  put TransactionSummary {..} =
    putMaybe S.put tsSender <>
    S.put tsHash <>
    S.put tsCost <>
    S.put tsEnergyCost <>
    S.put tsType <>
    S.put tsResult <>
    S.put tsIndex

  get = do
    tsSender <- getMaybe S.get
    tsHash <- S.get
    tsCost <- S.get
    tsEnergyCost <- S.get
    tsType <- S.get
    tsResult <- S.get
    tsIndex <- S.get
    return TransactionSummary {..}

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
                  | AmountTooLarge !Address !Amount
                  -- ^When one wishes to transfer an amount from A to B but there
                  -- are not enough funds on account/contract A to make this
                  -- possible. The data are the from address and the amount to transfer.
                  | SerializationFailure -- ^Serialization of the body failed.
                  | OutOfEnergy -- ^We ran of out energy to process this transaction.
                  | RejectedInit { rejectReason :: !Int32 } -- ^Rejected due to contract logic in init function of a contract.
                  | RejectedReceive { rejectReason :: !Int32,
                                      contractAddress :: !ContractAddress,
                                      receiveName :: !Wasm.ReceiveName,
                                      parameter :: !Wasm.Parameter}
                  | NonExistentRewardAccount !AccountAddress -- ^Reward account desired by the baker does not exist.
                  | InvalidProof -- ^Proof that the baker owns relevant private keys is not valid.
                  | AlreadyABaker !BakerId -- ^Tried to add baker for an account that already has a baker
                  | NotABaker !AccountAddress -- ^Tried to remove a baker for an account that has no baker
                  | InsufficientBalanceForBakerStake -- ^The amount on the account was insufficient to cover the proposed stake
                  | StakeUnderMinimumThresholdForBaking -- ^The amount provided is under the threshold required for becoming a baker
                  | BakerInCooldown -- ^The change could not be made because the baker is in cooldown for another change
                  | DuplicateAggregationKey !BakerAggregationVerifyKey -- ^A baker with the given aggregation key already exists
                  -- |Encountered credential ID that does not exist
                  | NonExistentCredentialID
                  -- |Attempted to add an account key to a key index already in use
                  | KeyIndexAlreadyInUse
                  -- |When the account threshold is updated, it must not exceed the amount of existing keys
                  | InvalidAccountThreshold
                  -- |When the credential key threshold is updated, it must not exceed the amount of existing keys
                  | InvalidCredentialKeySignThreshold
                  -- |Proof for an encrypted amount transfer did not validate.
                  | InvalidEncryptedAmountTransferProof
                  -- |Proof for a secret to public transfer did not validate.
                  | InvalidTransferToPublicProof
                  -- |Account tried to transfer an encrypted amount to itself, that's not allowed.
                  | EncryptedAmountSelfTransfer !AccountAddress
                  -- | The provided index is below the start index or above `startIndex + length incomingAmounts`
                  | InvalidIndexOnEncryptedTransfer
                  -- | The transfer with schedule is going to send 0 tokens
                  | ZeroScheduledAmount
                  -- | The transfer with schedule has a non strictly increasing schedule
                  | NonIncreasingSchedule
                  -- | The first scheduled release in a transfer with schedule has already expired
                  | FirstScheduledReleaseExpired
                  -- | Account tried to transfer with schedule to itself, that's not allowed.
                  | ScheduledSelfTransfer !AccountAddress
                  -- | At least one of the credentials was either malformed or its proof was incorrect.
                  | InvalidCredentials
                  -- | Some of the credential IDs already exist or are duplicated in the transaction.
                  | DuplicateCredIDs ![IDTypes.CredentialRegistrationID]
                  -- | A credential id that was to be removed is not part of the account.
                  | NonExistentCredIDs ![IDTypes.CredentialRegistrationID]
                  -- | Attempt to remove the first credential
                  | RemoveFirstCredential
                  -- | The credential holder of the keys to be updated did not sign the transaction
                  | CredentialHolderDidNotSign
                  -- |Account is not allowed to have multiple credentials because it contains a non-zero encrypted transfer.
                  | NotAllowedMultipleCredentials
                  -- |The account is not allowed to receive encrypted transfers because it has multiple credentials.
                  | NotAllowedToReceiveEncrypted
                  -- |The account is not allowed to send encrypted transfers (or transfer from/to public to/from encrypted)
                  | NotAllowedToHandleEncrypted
    deriving (Show, Eq, Generic)

wasmRejectToRejectReasonInit :: Wasm.ContractExecutionFailure -> RejectReason
wasmRejectToRejectReasonInit (Wasm.ContractReject reason) = RejectedInit reason
wasmRejectToRejectReasonInit Wasm.RuntimeFailure = RuntimeFailure

wasmRejectToRejectReasonReceive :: ContractAddress -> Wasm.ReceiveName -> Wasm.Parameter -> Wasm.ContractExecutionFailure -> RejectReason
wasmRejectToRejectReasonReceive addr name param (Wasm.ContractReject reason) = RejectedReceive reason addr name param
wasmRejectToRejectReasonReceive _ _ _ Wasm.RuntimeFailure = RuntimeFailure

instance S.Serialize RejectReason where
  put = \case
    ModuleNotWF -> S.putWord8 0
    ModuleHashAlreadyExists mref -> S.putWord8 1 <> S.put mref
    InvalidAccountReference addr -> S.putWord8 2 <> S.put addr
    InvalidInitMethod mref iname -> S.putWord8 3 <> S.put mref <> S.put iname
    InvalidReceiveMethod mref rname -> S.putWord8 4 <> S.put mref <> S.put rname
    InvalidModuleReference mref -> S.putWord8 5 <> S.put mref
    InvalidContractAddress caddr -> S.putWord8 6 <> S.put caddr
    RuntimeFailure -> S.putWord8 7
    AmountTooLarge addr amnt -> S.putWord8 8 <> S.put addr <> S.put amnt
    SerializationFailure -> S.putWord8 9
    OutOfEnergy -> S.putWord8 10
    RejectedInit {..} -> S.putWord8 11 <> S.putInt32be rejectReason
    RejectedReceive {..} ->
      S.putWord8 12 <>
      S.putInt32be rejectReason <>
      S.put contractAddress <>
      S.put receiveName <>
      S.put parameter
    NonExistentRewardAccount addr -> S.putWord8 13 <> S.put addr
    InvalidProof -> S.putWord8 14
    AlreadyABaker bid -> S.putWord8 15 <> S.put bid
    NotABaker addr -> S.putWord8 16 <> S.put addr
    InsufficientBalanceForBakerStake -> S.putWord8 17
    StakeUnderMinimumThresholdForBaking -> S.putWord8 18
    BakerInCooldown -> S.putWord8 19
    DuplicateAggregationKey bvfkey -> S.putWord8 20 <> S.put bvfkey
    NonExistentCredentialID -> S.putWord8 21
    KeyIndexAlreadyInUse -> S.putWord8 22
    InvalidAccountThreshold -> S.putWord8 23
    InvalidCredentialKeySignThreshold -> S.putWord8 24
    InvalidEncryptedAmountTransferProof -> S.putWord8 25
    InvalidTransferToPublicProof -> S.putWord8 26
    EncryptedAmountSelfTransfer addr -> S.putWord8 27 <> S.put addr
    InvalidIndexOnEncryptedTransfer -> S.putWord8 28
    ZeroScheduledAmount -> S.putWord8 29
    NonIncreasingSchedule -> S.putWord8 30
    FirstScheduledReleaseExpired -> S.putWord8 31
    ScheduledSelfTransfer addr -> S.putWord8 32 <> S.put addr
    InvalidCredentials -> S.putWord8 33
    DuplicateCredIDs ids -> S.putWord8 34 <> putListOf S.put ids
    NonExistentCredIDs ids -> S.putWord8 35 <> putListOf S.put ids
    RemoveFirstCredential -> S.putWord8 36
    CredentialHolderDidNotSign -> S.putWord8 37
    NotAllowedMultipleCredentials -> S.putWord8 38
    NotAllowedToReceiveEncrypted -> S.putWord8 39
    NotAllowedToHandleEncrypted -> S.putWord8 40

  get = S.getWord8 >>= \case
    0 -> return ModuleNotWF
    1 -> ModuleHashAlreadyExists <$> S.get
    2 -> InvalidAccountReference <$> S.get
    3 -> InvalidInitMethod <$> S.get <*> S.get
    4 -> InvalidReceiveMethod <$> S.get <*> S.get
    5 -> InvalidModuleReference <$> S.get
    6 -> InvalidContractAddress <$> S.get
    7 -> return RuntimeFailure
    8 -> AmountTooLarge <$> S.get <*> S.get
    9 -> return SerializationFailure
    10 -> return OutOfEnergy
    11 -> do
      rejectReason <- S.getInt32be
      return RejectedInit {..}
    12 -> do
      rejectReason <- S.getInt32be
      contractAddress <- S.get
      receiveName <- S.get
      parameter <- S.get
      return RejectedReceive {..}
    13 -> NonExistentRewardAccount <$> S.get
    14 -> return InvalidProof
    15 -> AlreadyABaker <$> S.get
    16 -> NotABaker <$> S.get
    17 -> return InsufficientBalanceForBakerStake
    18 -> return StakeUnderMinimumThresholdForBaking
    19 -> return BakerInCooldown
    20 -> DuplicateAggregationKey <$> S.get
    21 -> return NonExistentCredentialID
    22 -> return KeyIndexAlreadyInUse
    23 -> return InvalidAccountThreshold
    24 -> return InvalidCredentialKeySignThreshold
    25 -> return InvalidEncryptedAmountTransferProof
    26 -> return InvalidTransferToPublicProof
    27 -> EncryptedAmountSelfTransfer <$> S.get
    28 -> return InvalidIndexOnEncryptedTransfer
    29 -> return ZeroScheduledAmount
    30 -> return NonIncreasingSchedule
    31 -> return FirstScheduledReleaseExpired
    32 -> ScheduledSelfTransfer <$> S.get
    33 -> return InvalidCredentials
    34 -> DuplicateCredIDs <$> getListOf S.get
    35 -> NonExistentCredIDs <$> getListOf S.get
    36 -> return RemoveFirstCredential
    37 -> return CredentialHolderDidNotSign
    38 -> return NotAllowedMultipleCredentials
    39 -> return NotAllowedToReceiveEncrypted
    40 -> return NotAllowedToHandleEncrypted
    n -> fail $ "Unrecognized RejectReason tag: " ++ show n



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
                 | ExpiredTransaction -- ^The transaction has expired.
                 | ExceedsMaxBlockEnergy -- ^The transaction's deposited energy exceeds the maximum block energy limit.
                 | ExceedsMaxBlockSize -- ^The baker decided that this transaction is too big to put in a block.
                 | NonExistentIdentityProvider !IDTypes.IdentityProviderIdentity
                 | UnsupportedAnonymityRevokers -- ^One of the anonymity revokers in the credential is not known.
                 | NonExistentAccount !AccountAddress -- ^Cannot deploy credential onto a non-existing account.
                 | AccountCredentialInvalid -- ^Account credential verification failed, the proofs were invalid or malformed.
                 | DuplicateAccountRegistrationID !IDTypes.CredentialRegistrationID
                 | InvalidUpdateTime -- ^The update timeout is later than the effective time
                 | ExceedsMaxCredentialDeployments -- ^The block contains more than the limit of credential deployments
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

-- |Generate the challenge for adding a baker.
addBakerChallenge :: AccountAddress -> BakerElectionVerifyKey -> BakerSignVerifyKey -> BakerAggregationVerifyKey -> BS.ByteString
addBakerChallenge addr elec sign agg = "addBaker" <> S.runPut (S.put addr <> S.put elec <> S.put sign <> S.put agg)

-- |Generate the challenge for updating a baker's keys.
-- This is currently identical to 'addBakerChallenge'.
updateBakerKeyChallenge :: AccountAddress -> BakerElectionVerifyKey -> BakerSignVerifyKey -> BakerAggregationVerifyKey -> BS.ByteString
updateBakerKeyChallenge addr elec sign agg = "updateBakerKeys" <> S.runPut (S.put addr <> S.put elec <> S.put sign <> S.put agg)
