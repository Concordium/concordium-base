{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE EmptyCase #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE DeriveGeneric #-}
module Concordium.Types.Execution where

import Prelude hiding(fail)

import Control.Monad.Reader

import Data.Char
import qualified Data.Aeson as AE
import Data.Aeson.TH
import qualified Data.HashMap.Strict as Map
import qualified Data.Serialize.Put as P
import qualified Data.Serialize.Get as G
import qualified Data.Serialize as S
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as BSS
import Data.Word
import GHC.Generics

import qualified Concordium.Types.Acorn.Core as Core
import Concordium.Types
import Concordium.Types.Execution.TH
import Concordium.ID.Types
import Concordium.Types.Acorn.Interfaces
import qualified Concordium.ID.Types as IDTypes
import Concordium.Crypto.Proofs

-- |These are the messages that are generated as parts of contract execution.
data InternalMessage annot = TSend !ContractAddress !Amount !(Value annot) | TSimpleTransfer !Address !Amount
    deriving(Show)

type Proof = BS.ByteString

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
  parseJSON v = (AccountOwnershipProof . Map.toList) <$> AE.parseJSON v

instance AE.ToJSON AccountOwnershipProof where
  toJSON (AccountOwnershipProof proofs) = AE.toJSON $ Map.fromList proofs

-- |The transaction payload. Defines the supported kinds of transactions.
--
--  * @SPEC: <$DOCS/Transactions#transaction-body>
--  * @COMMENT: Serialization format is defined separately, this only defines the datatype.
data Payload =
  -- |Put module on the chain.
  DeployModule {
    -- |Module source.
    dmMod :: !(Core.Module Core.UA)
    }
  -- |Initialize a new contract instance.
  | InitContract {
      -- |Initial amount on the contract's account.
      icAmount :: !Amount,
      -- |Reference of the module (on-chain) in which the contract exist.
      icModRef :: !Core.ModuleRef,
      -- |Name of the contract (relative to the module) to initialize.
      icContractName :: !Core.TyName,
      -- |Parameter to the init method. Relative to the module (as if it were a term at the end of the module).
      icParam :: !(Core.Expr Core.UA Core.ModuleName)
      }
  -- |Update an existing contract instance.
  | Update {
      -- |Amount to call the receive method with.
      uAmount :: !Amount,
      -- |The address of the contract to invoke.
      uAddress :: !ContractAddress,
      -- |Message to invoke the receive method with.
      uMessage :: !(Core.Expr Core.UA Core.ModuleName)
      }
  -- |Simple transfer from an account to either a contract or an account.
  | Transfer {
      -- |Recepient.
      tToAddress :: !Address,
      -- |Amount to transfer.
      tAmount :: !Amount
      }
  -- |Deploy an encryption key to an existing account.
  | DeployEncryptionKey {
      -- |The encryption key to deploy.
      dekKey :: !IDTypes.AccountEncryptionKey
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
      rbId :: !BakerId,
      -- |Proof that we are allowed to remove the baker. One
      -- mechanism would be that the baker would remove itself only
      -- (the transaction must come from the baker's account) but
      -- possibly we want other mechanisms.
      rbProof :: !Proof
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
  deriving(Eq, Show)

$(genEnumerationType ''Payload "TransactionType" "TT" "getTransactionType")

instance S.Serialize TransactionType

-- |Payload serialization according to
--
--  * @SPEC: <$DOCS/Transactions#transaction-body>
instance S.Serialize Payload where
  put DeployModule{..} =
    P.putWord8 0 <>
    Core.putModule dmMod
  put InitContract{..} =
      P.putWord8 1 <>
      S.put icAmount <>
      putModuleRef icModRef <>
      Core.putTyName icContractName <>
      Core.putExpr icParam
  put Update{..} =
    P.putWord8 2 <>
    S.put uAmount <>
    S.put uAddress <>
    Core.putExpr uMessage
  put Transfer{..} =
    P.putWord8 3 <>
    S.put tToAddress <>
    S.put tAmount
  put DeployEncryptionKey{..} =
    P.putWord8 4 <>
    S.put dekKey
  put AddBaker{..} =
    P.putWord8 5 <>
    S.put abElectionVerifyKey <>
    S.put abSignatureVerifyKey <>
    S.put abAggregationVerifyKey <>
    S.put abAccount <>
    S.put abProofSig <>
    S.put abProofElection <>
    S.put abProofAccount <>
    S.put abProofAggregation
  put RemoveBaker{..} =
    P.putWord8 6 <>
    S.put rbId <>
    S.put rbProof
  put UpdateBakerAccount{..} =
    P.putWord8 7 <>
    S.put ubaId <>
    S.put ubaAddress <>
    S.put ubaProof
  put UpdateBakerSignKey{..} =
    P.putWord8 8 <>
    S.put ubsId <>
    S.put ubsKey <>
    S.put ubsProof
  put DelegateStake{..} =
    P.putWord8 9 <>
    S.put dsID
  put UndelegateStake =
    P.putWord8 10
  put UpdateElectionDifficulty{..} =
    P.putWord8 11 <>
    S.put uedDifficulty

  get =
    G.getWord8 >>=
      \case 0 -> do
              dmMod <- Core.getModule
              return DeployModule{..}
            1 -> do
              icAmount <- S.get
              icModRef <- getModuleRef
              icContractName <- Core.getTyName
              icParam <- Core.getExpr
              return InitContract{..}
            2 -> do
              uAmount <- S.get
              uAddress <- S.get
              uMessage <- Core.getExpr
              return Update{..}
            3 -> do
              tToAddress <- S.get
              tAmount <- S.get
              return Transfer{..}
            4 -> do
              dekKey <- S.get
              return DeployEncryptionKey{..}
            5 -> do
              abElectionVerifyKey <- S.get
              abSignatureVerifyKey <- S.get
              abAggregationVerifyKey <- S.get
              abAccount <- S.get
              abProofSig <- S.get
              abProofElection <- S.get
              abProofAccount <- S.get
              abProofAggregation <- S.get
              return AddBaker{..}
            6 -> do
              rbId <- S.get
              rbProof <- S.get
              return RemoveBaker{..}
            7 -> do
              ubaId <- S.get
              ubaAddress <- S.get
              ubaProof <- S.get
              return UpdateBakerAccount{..}
            8 -> do
              ubsId <- S.get
              ubsKey <- S.get
              ubsProof <- S.get
              return UpdateBakerSignKey{..}
            9 -> DelegateStake <$> S.get
            10 -> return UndelegateStake
            11 -> do
              uedDifficulty <- S.get
              unless (isValidElectionDifficulty uedDifficulty) $
                fail $ "Illegal election difficulty: " ++ show uedDifficulty
              return UpdateElectionDifficulty{..}
            n -> fail $ "unsupported transaction type '" ++ show n ++ "'"

{-# INLINE encodePayload #-}
encodePayload :: Payload -> EncodedPayload
encodePayload = EncodedPayload . BSS.toShort . S.encode

{-# INLINE decodePayload #-}
decodePayload :: EncodedPayload -> Either String Payload
decodePayload (EncodedPayload s) = S.decode (BSS.fromShort s)

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
data Event =
           -- |Module with the given address was deployed.
           ModuleDeployed !Core.ModuleRef
           -- |The contract was deployed.
           | ContractInitialized {
               -- |Module in which the contract source resides.
               ecRef :: !Core.ModuleRef,
               -- |Name of the contract relative to the module.
               ecName :: !Core.TyName,
               -- |Reference to the contract as deployed.
               ecAddress :: !ContractAddress,
               -- |Initial amount transferred to the contract.
               ecAmount :: !Amount
               -- TODO: We could include initial state hash here.
               -- Including the whole state is likely not a good idea.
               }
           -- |The given contract was updated.
           | Updated {
               -- |Address of the contract that was updated.
               euAddress :: !ContractAddress,
               -- |Address of the instigator of the update, an account or contract.
               euInstigator :: !Address,
               -- |Amount which was transferred to the contract.
               euAmount :: !Amount,
               -- |The message which was sent to the contract.
               euMessage :: !MessageFormat
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
           -- |A new encryption key was deployed onto an account.
           | AccountEncryptionKeyDeployed {
               -- |The encryption key.
               eaekdKey :: !IDTypes.AccountEncryptionKey,
               -- |Account to which it was deployed.
               eaekdAccount :: !AccountAddress
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
  deriving (Show, Generic, Eq)

instance S.Serialize Event

-- |Used internally by the scheduler since internal messages are sent as values,
-- and top-level messages are acorn expressions.
data MessageFormat = ValueMessage !(Value Core.NoAnnot) | ExprMessage !(LinkedExpr Core.NoAnnot)
    deriving(Show, Generic, Eq)

-- FIXME: ToJSON instance based on a show instance.
instance AE.ToJSON MessageFormat where
  toJSON fmt = AE.toJSON (show fmt)

-- FIXME: Contracts not supported.
instance AE.FromJSON MessageFormat where
  parseJSON _ = fail "FIXME: Unsupported."

instance S.Serialize MessageFormat where
    put (ValueMessage v) = S.putWord8 0 >> putStorable v
    put (ExprMessage e) = S.putWord8 1 >> S.put e
    get = do
        tag <- S.getWord8
        case tag of
            0 -> ValueMessage <$> getStorable
            1 -> ExprMessage <$> S.get
            _ -> fail "Invalid MessageFormat tag"

-- |Index of the transaction in a block, starting from 0.
newtype TransactionIndex = TransactionIndex Word64
    deriving(Eq, Ord, Enum, Num, Show, Read, Real, Integral, S.Serialize, AE.ToJSON, AE.FromJSON) via Word64

-- |Result of a valid transaction is a transaction summary.
data TransactionSummary = TransactionSummary {
  tsSender :: !(Maybe AccountAddress),
  tsHash :: !TransactionHash,
  tsCost :: !Amount,
  tsEnergyCost :: !Energy,
  tsType :: !(Maybe TransactionType),
  tsResult :: !ValidResult,
  tsIndex :: !TransactionIndex
  } deriving(Eq, Show, Generic)

-- |Outcomes of a valid transaction. Either a reject with a reason or a
-- successful transaction with a list of events which occurred during execution.
-- We also record the cost of the transaction.
data ValidResult = TxSuccess { vrEvents :: ![Event] } | TxReject { vrRejectReason :: !RejectReason }
  deriving(Show, Generic, Eq)

instance S.Serialize ValidResult
instance S.Serialize TransactionSummary

-- |Ways a single transaction can fail. Values of this type are only used for reporting of rejected transactions.
data RejectReason = ModuleNotWF -- ^Error raised when typechecking of the module has failed.
                  | MissingImports  -- ^Error when there were missing imports (determined before typechecking).
                  | ModuleHashAlreadyExists !Core.ModuleRef  -- ^As the name says.
                  | MessageTypeError -- ^Message to the receive method is of the wrong type.
                  | ParamsTypeError -- ^Parameters of the init method are of the wrong type.
                  | InvalidAccountReference !AccountAddress -- ^Account does not exists.
                  | InvalidContractReference !Core.ModuleRef !Core.TyName -- ^Reference to a non-existing contract.
                  | InvalidModuleReference !Core.ModuleRef   -- ^Reference to a non-existing module.
                  | InvalidContractAddress !ContractAddress -- ^Contract instance does not exist.
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
                  | AccountEncryptionKeyAlreadyExists AccountAddress IDTypes.AccountEncryptionKey
                  | NonExistentRewardAccount !AccountAddress -- ^Reward account desired by the baker does not exist.
                  | InvalidProof -- ^Proof that the baker owns relevant private keys is not valid.
                  | RemovingNonExistentBaker !BakerId
                  | InvalidBakerRemoveSource !AccountAddress
                  | UpdatingNonExistentBaker !BakerId
                  | InvalidStakeDelegationTarget !BakerId -- ^The target of stake delegation is not a valid baker.
                  | DuplicateSignKey !BakerSignVerifyKey -- ^A baker with the given signing key already exists.
                  -- |A transaction should be sent from the baker's current account, but is not.
                  | NotFromBakerAccount { nfbaFromAccount :: !AccountAddress, -- ^Sender account of the transaction
                                          nfbaCurrentBakerAccount :: !AccountAddress -- ^Current baker account.
                                        }
                  -- |A transaction should be sent from a special account.
                  -- The parameter is the account the transaction was sent from.
                  | NotFromSpecialAccount !AccountAddress
    deriving (Show, Eq, Generic)

instance S.Serialize RejectReason
instance AE.ToJSON RejectReason
instance AE.FromJSON RejectReason

data FailureKind = InsufficientFunds   -- ^The amount is not sufficient to cover the gas deposit.
                 | IncorrectSignature  -- ^Signature check failed.
                 | NonSequentialNonce !Nonce -- ^The transaction nonce is not
                                             -- next in sequence. The argument
                                             -- is the expected nonce.
                 | SuccessorOfInvalidTransaction -- ^A transaction from the same account was rejected, so
                                                 -- we reject the following transactions from the same account
                 | UnknownAccount !AccountAddress -- ^Transaction is coming from an unknown sender.
                 | DepositInsufficient -- ^The dedicated gas amount was lower than the minimum allowed.
                 | NoValidCredential -- ^No valid credential on the sender account.
                 | ExpiredTransaction -- ^The transaction has expired.
                 | ExceedsMaxBlockEnergy -- ^The transaction's used energy size exceeds the maximum block energy limit
                 | ExceedsMaxBlockSize -- ^The baker decided that this transaction is too big to put in a block.
                 | NonExistentIdentityProvider !IDTypes.IdentityProviderIdentity
                 | NonExistentAccount !AccountAddress -- ^Cannot deploy credential onto a non-existing account.
                 | AccountCredentialInvalid
                 | DuplicateAccountRegistrationID !IDTypes.CredentialRegistrationID
      deriving(Eq, Show)

data TxResult = TxValid !TransactionSummary | TxInvalid !FailureKind

-- FIXME: These intances need to be made clearer.
$(deriveJSON AE.defaultOptions{AE.fieldLabelModifier = map toLower . dropWhile isLower} ''Event)

-- Derive JSON instance for transaction outcomes
-- At the end of the file to avoid issues with staging restriction.
$(deriveJSON AE.defaultOptions{AE.constructorTagModifier = map toLower . drop 2,
                                 AE.sumEncoding = AE.TaggedObject{
                                    AE.tagFieldName = "outcome",
                                    AE.contentsFieldName = "details"
                                    },
                                 AE.fieldLabelModifier=map toLower . drop 2} ''ValidResult)

$(deriveJSON defaultOptions{fieldLabelModifier = map toLower . drop 2} ''TransactionSummary)

$(deriveJSON defaultOptions{AE.constructorTagModifier = map toLower . drop 2} ''TransactionType)
