{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE PatternSynonyms #-}
module Concordium.Types.Execution where

import Prelude hiding(fail)

import Control.Monad.Reader

import qualified Data.Serialize.Put as P
import qualified Data.Serialize.Get as G
import qualified Data.Serialize as S
import qualified Data.ByteString as BS


import qualified Concordium.Types.Acorn.Core as Core
import Concordium.Types
import Concordium.Types.Acorn.Interfaces
import qualified Concordium.ID.Types as IDTypes

-- |These are the messages that are generated as parts of contract execution.
data InternalMessage = TSend !ContractAddress !Amount !Value | TSimpleTransfer !Address !Amount
    deriving(Show)

type Proof = BS.ByteString

-- |The transaction payload. Defines the supported kinds of transactions.
data Payload = 
  -- |Put module on the chain.
  DeployModule {
    -- |Module source.
    dmMod :: !Core.Module
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
      icParam :: !(Core.Expr Core.ModuleName),
      -- |Derived field, serialized size of the parameter.
      icSize :: !Int
      }
  -- |Update an existing contract instance.
  | Update {
      -- |Amount to call the receive method with.
      uAmount :: !Amount,
      -- |The address of the contract to invoke.
      uAddress :: !ContractAddress,
      -- |Message to invoke the receive method with.
      uMessage :: !(Core.Expr Core.ModuleName),
      -- ^Derived field, serialized size of the message.
      uSize :: !Int
      }
  -- |Simple transfer from an account to either a contract or an account.
  | Transfer {
      -- |Recepient.
      tToAddress :: !Address,
      -- |Amount to transfer.
      tAmount :: !Amount
      }
  -- |Deploy credentials, creating a new account if one does not yet exist.
  | DeployCredential {
      -- |The credentials to deploy.
      dcCredential :: !IDTypes.CredentialDeploymentInformation
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
      -- |Address of the account the baker wants to be rewarded to.
      abAccount :: !AccountAddress,
      -- |Proof of at least the following facts
      -- 
      --   * the baker owns the account on the given address (knows the private key)
      --   * the baker owns private keys corresponding to the public keys (election and signature)
      --   * the baker is allowed to become a baker: THIS NEEDS SPEC
      abProof :: !Proof
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
  -- Can only be initiated by the baker itself.
  | UpdateBakerAccount {
      -- |Id of the baker to update.
      ubaId :: !BakerId,
      -- |Address of the new account. The account must exist.
      ubaAddress :: !AccountAddress,
      -- |Proof that the baker owns the new account.
      ubaProof :: !Proof
      }
  -- |Update the signature (verification) key of the baker.
  | UpdateBakerSignKey {
      -- |Id of the baker to update.
      ubsId :: !BakerId,
      -- |New signature verification key.
      ubsKey :: !BakerSignVerifyKey,
      -- |Proof that the baker knows the private key of this verification key.
      ubsProof :: !Proof
      }
  deriving(Eq, Show)

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
  put DeployCredential{..} =
    P.putWord8 4 <>
    S.put dcCredential
  put DeployEncryptionKey{..} =
    P.putWord8 5 <>
    S.put dekKey
  put AddBaker{..} =
    P.putWord8 6 <>
    S.put abElectionVerifyKey <>
    S.put abSignatureVerifyKey <>
    S.put abAccount <>
    S.put abProof
  put RemoveBaker{..} =
    P.putWord8 7 <>
    S.put rbId <>
    S.put rbProof
  put UpdateBakerAccount{..} =
    P.putWord8 8 <>
    S.put ubaId <>
    S.put ubaAddress <>
    S.put ubaProof
  put UpdateBakerSignKey{..} =
    P.putWord8 9 <>
    S.put ubsId <>
    S.put ubsKey <>
    S.put ubsProof


  get = do
    G.getWord8 >>=
      \case 0 -> do
              dmMod <- Core.getModule
              return DeployModule{..}
            1 -> do
              icAmount <- S.get
              icModRef <- getModuleRef
              icContractName <- Core.getTyName
              pstart <- G.bytesRead
              icParam <- Core.getExpr
              pend <- G.bytesRead
              return InitContract{icSize = pend - pstart,..}
            2 -> do
              uAmount <- S.get
              uAddress <- S.get
              pstart <- G.bytesRead
              uMessage <- Core.getExpr
              pend <- G.bytesRead
              return Update{uSize = pend - pstart,..}
            3 -> do
              tToAddress <- S.get
              tAmount <- S.get
              return Transfer{..}
            4 -> do
              dcCredential <- S.get
              return DeployCredential{..}
            5 -> do
              dekKey <- S.get
              return DeployEncryptionKey{..}
            6 -> do
              abElectionVerifyKey <- S.get
              abSignatureVerifyKey <- S.get
              abAccount <- S.get
              abProof <- S.get
              return AddBaker{..}
            7 -> do
              rbId <- S.get
              rbProof <- S.get
              return RemoveBaker{..}
            8 -> do
              ubaId <- S.get
              ubaAddress <- S.get
              ubaProof <- S.get
              return UpdateBakerAccount{..}
            9 -> do
              ubsId <- S.get
              ubsKey <- S.get
              ubsProof <- S.get
              return UpdateBakerSignKey{..}
            _ -> fail "Unsupported transaction type."

{-# INLINE encodePayload #-}
encodePayload :: Payload -> EncodedPayload
encodePayload = EncodedPayload . S.encode

{-# INLINE decodePayload #-}
decodePayload :: S.Serialize a => EncodedPayload -> Either String a
decodePayload (EncodedPayload s) = S.decode s

-- |Events which are generated during transaction execution.
-- These are only used for commited transactions.
data Event = ModuleDeployed !Core.ModuleRef
           | ContractInitialized !Core.ModuleRef !Core.TyName !ContractAddress
           | Updated !ContractAddress !Amount !MessageFormat
           | Transferred !Address !Amount !Address
           | AccountCreated !AccountAddress
           | CredentialDeployed !IDTypes.CredentialDeploymentInformation
           | AccountEncryptionKeyDeployed AccountAddress IDTypes.AccountEncryptionKey
  deriving (Show)

-- |Used internally by the scheduler since internal messages are sent as values,
-- and top-level messages are acorn expressions.
data MessageFormat = ValueMessage !Value | ExprMessage !Expr
    deriving(Show)

-- |Result of a valid transaction is either a reject with a reason or a
-- successful transaction with a list of events which occurred during execution.
type ValidResult = Either RejectReason [Event]

{-# COMPLETE TxSuccess, TxReject #-}
pattern TxSuccess :: [Event] -> ValidResult
pattern TxReject :: RejectReason -> ValidResult
pattern TxSuccess a = Right a
pattern TxReject e = Left e

-- |Ways a single transaction can fail. Values of this type are only used for reporting of rejected transactions.
data RejectReason = ModuleNotWF !TypingError -- ^Error raised when typechecking of the module has failed.
                  | MissingImports !TypingError  -- ^Error when there were missing imports (determined before typechecking).
                  | ModuleHashAlreadyExists !Core.ModuleRef  -- ^As the name says.
                  | MessageTypeError !TypingError -- ^Message to the receive method is of the wrong type.
                  | ParamsTypeError !TypingError -- ^Parameters of the init method are of the wrong type.
                  | InvalidAccountReference !AccountAddress -- ^Account does not exists.
                  | InvalidContractReference !Core.ModuleRef !Core.TyName -- ^Reference to a non-existing contract.
                  | InvalidModuleReference !Core.ModuleRef   -- ^Reference to a non-existing module.
                  | InvalidContractAddress !ContractAddress -- ^Contract instance does not exist.
                  | EvaluationError         -- ^Error during evalution. This is
                                            -- mostly for debugging purposes
                                            -- since this kind of an error should
                                            -- not happen after successful
                                            -- typechecking.
                  | AmountTooLarge !Address !Amount
                  -- ^When one wishes to transfer an amount from A to B but there
                  -- are not enough funds on account/contract A to make this
                  -- possible. The data are the from address and the amount to transfer.
                  | SerializationFailure String -- ^Serialization of the body failed for the given reason.
                  | OutOfEnergy -- ^We ran of out energy to process this transaction.
                  | Rejected -- ^Rejected due to contract logic.
                  | DuplicateAccountRegistrationID IDTypes.CredentialRegistrationID
                  | AccountCredentialInvalid
                  | AccountEncryptionKeyAlreadyExists AccountAddress IDTypes.AccountEncryptionKey
    deriving (Show)

data FailureKind = InsufficientFunds   -- ^The amount is not sufficient to cover the gas deposit.
                 | IncorrectSignature  -- ^Signature check failed.
                 | NonSequentialNonce !Nonce -- ^The transaction nonce is not
                                             -- next in sequence. The argument
                                             -- is the expected nonce.
                 | UnknownAccount !AccountAddress -- ^Transaction is coming from an unknown sender.
                 | DepositInsufficient -- ^The dedicated gas amount was lower than the minimum allowed.
      deriving(Show)

data TxResult = TxValid ValidResult | TxInvalid FailureKind
