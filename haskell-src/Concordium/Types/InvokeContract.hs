{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}

-- |Types related to simulating contract invocations.
module Concordium.Types.InvokeContract (
    ContractContext (..),
    InvokeContractResult (..),
    defaultInvokeEnergy,
) where

import qualified Data.Aeson as AE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as BS16
import qualified Data.Text.Encoding as Text

import Concordium.Types (Address, Amount, ContractAddress, Energy)
import Concordium.Types.Execution (Event, RejectReason)
import qualified Concordium.Wasm as Wasm

-- |Default energy used when using the invoke method functionality.
-- This is here and not in the Constants module because it would otherwise
-- result in circular module dependencies.
defaultInvokeEnergy :: Energy
defaultInvokeEnergy = 10_000_000

-- |Maximum allowed energy used when using the invoke method functionality.
-- This is to make sure that there are no conversion errors to interpreter energy.
maxAllowedInvokeEnergy :: Energy
maxAllowedInvokeEnergy = 100_000_000_000

data ContractContext = ContractContext
    { -- |Invoker of the contract. If this is not supplied then the contract will be
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
      -- |And what amount of energy to allow for execution. This should be small
      -- enough so that it can be converted to interpreter energy.
      ccEnergy :: !Energy
    }

-- |This FromJSON instance defaults a number of values if they are not given
-- - energy defaults to 'defaultInvokeEnergy'
-- - amount defaults to 0
-- - parameter defaults to the empty one
instance AE.FromJSON ContractContext where
    parseJSON = AE.withObject "ContractContext" $ \obj -> do
        ccInvoker <- obj AE..:? "invoker"
        ccContract <- obj AE..: "contract"
        ccAmount <- obj AE..:? "amount" AE..!= 0
        ccMethod <- obj AE..: "method"
        ccParameter <- obj AE..:? "parameter" AE..!= Wasm.emptyParameter
        ccEnergy <- obj AE..:? "energy" AE..!= defaultInvokeEnergy
        if ccEnergy <= maxAllowedInvokeEnergy
            then return ContractContext{..}
            else fail "Maximum allowed invoke energy exceeded."

instance AE.ToJSON ContractContext where
    toJSON ContractContext{..} =
        AE.object $
            [ "contract" AE..= ccContract,
              "amount" AE..= ccAmount,
              "method" AE..= ccMethod,
              "parameter" AE..= ccParameter,
              "energy" AE..= ccEnergy
            ]
                ++ case ccInvoker of
                    Nothing -> []
                    Just invoker -> [("invoker", AE.toJSON invoker)]

data InvokeContractResult
    = -- |Contract execution failed for the given reason.
      Failure
        { rcrReason :: !RejectReason,
          -- |If invoking a V0 contract this is Nothing, otherwise it is potentially
          -- a return value produced by the call unless the call failed with out of
          -- energy or runtime error.
          rcrReturnValue :: !(Maybe BS.ByteString),
          -- |Energy used by the execution.
          rcrUsedEnergy :: !Energy
        }
    | -- |Contract execution succeeded.
      Success
        { -- |If invoking a V0 contract this is Nothing, otherwise it is
          -- the return value produced by the call.
          rcrReturnValue :: !(Maybe BS.ByteString),
          -- |Events produced by contract execution.
          rcrEvents :: ![Event],
          -- |Energy used by the execution.
          rcrUsedEnergy :: !Energy
        }

instance AE.FromJSON InvokeContractResult where
    parseJSON = AE.withObject "InvokeContractResult" $ \obj -> do
        tag <- obj AE..: "tag"
        case tag of
            "failure" -> do
                rcrReason <- obj AE..: "reason"
                rv <- obj AE..:? "returnValue"
                rcrReturnValue <- decodeReturnValue rv
                rcrUsedEnergy <- obj AE..: "usedEnergy"
                return Failure{..}
            "success" -> do
                rv <- obj AE..:? "returnValue"
                rcrReturnValue <- decodeReturnValue rv
                rcrEvents <- obj AE..: "events"
                rcrUsedEnergy <- obj AE..: "usedEnergy"
                return Success{..}
            _ -> fail $ "Invalid tag: " ++ tag
      where
        decodeReturnValue rv = case BS16.decode . Text.encodeUtf8 <$> rv of
            Nothing -> return Nothing
            Just (Right bs) -> return (Just bs)
            Just (Left _) -> fail "Failed decoding return value from base16."

instance AE.ToJSON InvokeContractResult where
    toJSON Failure{..} =
        AE.object $
            [ "tag" AE..= AE.String "failure",
              "reason" AE..= rcrReason,
              "usedEnergy" AE..= rcrUsedEnergy
            ]
                ++ case rcrReturnValue of
                    Nothing -> []
                    Just rv -> [("returnValue", AE.String . Text.decodeUtf8 . BS16.encode $ rv)]
    toJSON Success{..} =
        AE.object $
            [ "tag" AE..= AE.String "success",
              "events" AE..= rcrEvents,
              "usedEnergy" AE..= rcrUsedEnergy
            ]
                ++ case rcrReturnValue of
                    Nothing -> []
                    Just rv -> [("returnValue", AE.String . Text.decodeUtf8 . BS16.encode $ rv)]
