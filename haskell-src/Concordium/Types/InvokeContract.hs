-- |Types related to simulating contract invocations.

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NumericUnderscores #-}
module Concordium.Types.InvokeContract
  ( ContractContext(..)
  , InvokeContractResult(..)
  ) where

import qualified Data.Aeson as AE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as BS16
import qualified Data.Text.Encoding as Text


import qualified Concordium.Wasm as Wasm
import Concordium.Types (Address, Amount, ContractAddress, Energy)
import Concordium.Types.Execution (Event, RejectReason)

data ContractContext = ContractContext {
  -- |Invoker of the contract. If this is not supplied then the contract will be
  -- invoked, by an account with address 0, no credentials and sufficient amount
  -- of CCD to cover the transfer amount. If given, the relevant address must
  -- exist in the blockstate.
  ccInvoker :: !(Maybe Address),
  -- |Contract to invoke.
  ccContract :: !ContractAddress,
  -- |Amount to invoke the contract with.
  ccAmount :: !Amount,
  -- |Which entrypoint to invoke.
  ccMethod :: !Wasm.ReceiveName,
  -- |And with what parameter.
  ccParameter :: !Wasm.Parameter,
  -- |And what amount of energy to allow for execution.
  ccEnergy :: !Energy
  }

-- |This FromJSON instance defaults a number of values if they are not given
-- - energy defaults to maximum possible
-- - amount defaults to 0
-- - parameter defaults to the empty one
instance AE.FromJSON ContractContext where
  parseJSON = AE.withObject "ContractContext" $ \obj -> do
    ccInvoker <- obj AE..:? "invoker"
    ccContract <- obj AE..: "contract"
    ccAmount <- obj AE..:? "amount" AE..!= 0
    ccMethod <- obj AE..: "method"
    ccParameter <- obj AE..:? "parameter" AE..!= Wasm.emptyParameter
    ccEnergy <- obj AE..:? "energy" AE..!= 10_000_000
    return ContractContext{..}

data InvokeContractResult =
  -- |Contract execution failed for the given reason.
  Failure {
      rcrReason :: !RejectReason,
      -- |Energy used by the execution.
      rcrUsedEnergy :: !Energy
      }
  -- |Contract execution succeeded.
  | Success {
      -- |If invoking a V0 contract this is Nothing, otherwise it is
      -- the return value produced by the call.
      rcrReturnValue :: !(Maybe BS.ByteString),
      -- |Events produced by contract execution.
      rcrEvents :: ![Event],
      -- |Energy used by the execution.
      rcrUsedEnergy :: !Energy
      }

instance AE.ToJSON InvokeContractResult where
  toJSON Failure{..} = AE.object [
    "tag" AE..= AE.String "failure",
    "reason" AE..= rcrReason,
    "usedEnergy" AE..= rcrUsedEnergy
    ]
  toJSON Success{..} = AE.object [
    "tag" AE..= AE.String "success",
    ("returnValue",
     case rcrReturnValue of
      Nothing -> AE.Null
      Just rv -> AE.String . Text.decodeUtf8 . BS16.encode $ rv),
    "events" AE..= rcrEvents,
    "usedEnergy" AE..= rcrUsedEnergy
    ]
