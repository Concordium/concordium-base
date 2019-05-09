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

-- |The transaction payload. Currently only 5 transaction kinds are supported.
data Payload = DeployModule !Core.Module   -- ^Put module on the chain.
             | InitContract !Amount !Core.ModuleRef !Core.TyName !(Core.Expr Core.ModuleName)   -- ^Call init method of contract.
             | Update !Amount !ContractAddress !(Core.Expr Core.ModuleName) -- ^The last argument is the parameter.
             | Transfer !Address !Amount     -- ^Where (which can be a contract) and what amount to transfer.
             | CreateAccount !IDTypes.AccountCreationInformation

instance S.Serialize Payload where
  put (DeployModule amod) =
    P.putWord8 0 <>
    Core.putModule amod
  put (InitContract amnt mref cname params) =
      P.putWord8 1 <>
      S.put amnt <>
      Core.putModuleRef mref <>
      Core.putTyName cname <>
      Core.putExpr params
  put (Update amnt cref msg) =
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

  get = do
    h <- G.getWord8
    case h of
      0 -> DeployModule <$> Core.getModule
      1 -> InitContract <$> S.get <*> Core.getModuleRef <*> Core.getTyName <*> Core.getExpr
      2 -> Update <$> S.get <*> S.get <*> Core.getExpr
      3 -> Transfer <$> S.get <*> S.get
      4 -> CreateAccount <$> S.get
      _ -> fail "Only 5 types of transactions types are currently supported."

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
  deriving (Show)

-- |Used internally by the scheduler since internal messages are sent as values,
-- and top-level messages are acorn expressions.
data MessageFormat = ValueMessage !Value | ExprMessage !Expr
    deriving(Show)

-- |Result of a valid transaction is either a reject with a reason or a
-- successful transaction with a list of events which occurred during execution.
type ValidResult = Either RejectReason [Event]

pattern TxSuccess :: b -> Either a b
pattern TxReject :: a -> Either a b
pattern TxSuccess a = Right a
pattern TxReject e = Left e

-- |Ways a single transaction can fail. Values of this type are only used for reporting of rejected transactions.
data RejectReason = ModuleNotWF !String -- ^Error raised when typechecking of the module has failed.
                  | ModuleHashAlreadyExists !Core.ModuleRef  -- ^As the name says.
                  | MessageTypeError !String -- ^Message to the receive method is of the wrong type.
                  | ParamsTypeError !String -- ^Parameters of the init method are of the wrong type.
                  | InvalidAccountReference !AccountAddress -- ^Account does not exists.
                  | InvalidContractReference !Core.ModuleRef !Core.TyName -- ^Reference to a non-existing contract.
                  | InvalidModuleReference !Core.ModuleRef   -- ^Reference to a non-existing module.
                  | InvalidContractAddress !ContractAddress -- ^Contract instance does not exist.
                  | EvaluationError !String -- ^Error during evalution. This is
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
                  | AccountCredentialsFailure
                  | DuplicateAccountRegistrationID IDTypes.AccountRegistrationID
    deriving (Show)

data FailureKind = InsufficientFunds   -- ^The amount is not sufficient to cover the gas deposit.
                 | IncorrectSignature  -- ^Signature check failed.
                 | NonSequentialNonce !Nonce -- ^The transaction nonce is not
                                             -- next in sequence. The argument
                                             -- is the expected nonce.
                 | UnknownAccount !AccountAddress -- ^Transaction is coming from an unknown sender.
      deriving(Show)

data TxResult = TxValid ValidResult | TxInvalid FailureKind
