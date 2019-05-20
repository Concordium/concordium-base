{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE PatternSynonyms #-}
module Concordium.Types.Execution where

import Prelude hiding(fail)

import Control.Monad.Reader

import qualified Data.Serialize.Put as P
import qualified Data.Serialize.Get as G
import qualified Data.Serialize as S

import qualified Concordium.Types.Acorn.Core as Core
import Concordium.Types
import Concordium.Types.Acorn.Interfaces
import qualified Concordium.ID.Types as IDTypes

-- |These are the messages that are generated as parts of contract execution.
data InternalMessage = TSend !ContractAddress !Amount !Value | TSimpleTransfer !Address !Amount
    deriving(Show)

-- |The transaction payload. Currently only 6 transaction kinds are supported.
data Payload = DeployModule !Core.Module   -- ^Put module on the chain.
             | InitContract !Amount                        -- ^Initial amount on the contract's account.
                            !Core.ModuleRef                -- ^Name of the module in which the contract exist.
                            !Core.TyName                   -- ^Name of the contract.
                            !(Core.Expr Core.ModuleName)   -- ^Parameter to the init method.
                            !Int                           -- ^Derived field, size of the parameter.
             | Update !Amount
                      !ContractAddress             -- ^The recepient address.
                      !(Core.Expr Core.ModuleName) -- ^The message.
                      !Int                         -- ^Derived field, size of the message.
             | Transfer !Address !Amount     -- ^Where (which can be a contract) and what amount to transfer.
             | CreateAccount !IDTypes.AccountCreationInformation  -- ^Create an account with no credentials.
             | DeployCredential !IDTypes.CredentialDeploymentInformation  -- ^Deploy a credential to an existing account.
  deriving(Eq, Show)

instance S.Serialize Payload where
  put (DeployModule amod) =
    P.putWord8 0 <>
    Core.putModule amod
  put (InitContract amnt mref cname params _) =
      P.putWord8 1 <>
      S.put amnt <>
      Core.putModuleRef mref <>
      Core.putTyName cname <>
      Core.putExpr params
  put (Update amnt cref msg _) =
    P.putWord8 2 <>
    S.put amnt <>
    S.put cref <>
    Core.putExpr msg
  put (Transfer addr amnt) =
    P.putWord8 3 <>
    S.put addr <>
    S.put amnt
  put (CreateAccount aci) =
    P.putWord8 4 <>
    S.put aci
  put (DeployCredential cdi) =
    P.putWord8 5 <>
    S.put cdi

  get = do
    h <- G.getWord8
    case h of
      0 -> DeployModule <$> Core.getModule
      1 -> do amnt <- S.get
              mref <- Core.getModuleRef
              cname <- Core.getTyName
              pstart <- G.bytesRead
              params <- Core.getExpr
              pend <- G.bytesRead
              return $! InitContract amnt mref cname params (pend - pstart)
      2 -> do amnt <- S.get
              cref <- S.get
              pstart <- G.bytesRead
              msg <- Core.getExpr
              pend <- G.bytesRead
              return $! Update amnt cref msg (pend - pstart)
      3 -> Transfer <$> S.get <*> S.get
      4 -> CreateAccount <$> S.get
      5 -> DeployCredential <$> S.get
      _ -> fail "Only 6 types of transactions types are currently supported."

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
                  | MissingImports !String  -- ^Error when there were missing imports (determined before typechecking).
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
                  | AccountAlreadyExists !AccountAddress
                  | AccountCreationInformationInvalid
                  | DuplicateAccountRegistrationID IDTypes.CredentialRegistrationID
                  | AccountCredentialInvalid
                  | DeployCredentialToNonExistentAccount
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
