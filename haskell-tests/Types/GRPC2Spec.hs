{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}

module Types.GRPC2Spec where

import Lens.Micro.Platform
import Test.Hspec

import Concordium.GRPC2 (convertAccountTransaction)
import Concordium.Types
import Concordium.Types.Conditionally
import Concordium.Types.Execution
import Concordium.Types.Tokens (TokenAmount (..))
import qualified Data.FixedByteString as FBS
import qualified Data.ProtoLens as Proto
import qualified Proto.V2.Concordium.ProtocolLevelTokens_Fields as PLTFields
import qualified Proto.V2.Concordium.Types as ProtoTypes
import qualified Proto.V2.Concordium.Types_Fields as ProtoFields

account :: AccountAddress
account = AccountAddress (FBS.pack (replicate 32 0))

lockId :: LockId
lockId = LockId 1 2 3

transactionDetails :: [SupplementedEvent] -> ProtoTypes.AccountTransactionDetails
transactionDetails events =
    case convertAccountTransaction (Just TTTokenUpdate) 0 account CFalse (TxSuccess events) of
        Left err -> error (show err)
        Right details -> details

tests :: Spec
tests = describe "Token Update gRPC conversion" $ do
    it "duplicates token events in the compatibility and unified fields" $ do
        let details =
                transactionDetails
                    [ TokenMint
                        { etmTokenId = TokenId "token",
                          etmTarget = HolderAccount account,
                          etmAmount = TokenAmount 1 0
                        }
                    ]
            tokenEffect = details ^. ProtoFields.effects . ProtoFields.tokenUpdateEffect
            tokenEvents = tokenEffect ^. PLTFields.tokenEvents
            operationEvents = tokenEffect ^. PLTFields.events
        length tokenEvents `shouldBe` 1
        length operationEvents `shouldBe` 1
        case (tokenEvents, operationEvents) of
            ([tokenEvent], [operationEvent]) ->
                operationEvent ^. PLTFields.tokenEvent `shouldBe` tokenEvent
            _ -> expectationFailure "expected one token event in each field"

    it "places lock events only in the unified field" $ do
        let details = transactionDetails [LockDestroyed lockId]
            tokenEffect = details ^. ProtoFields.effects . ProtoFields.tokenUpdateEffect
            operationEvents = tokenEffect ^. PLTFields.events
        tokenEffect ^. PLTFields.tokenEvents `shouldBe` []
        length operationEvents `shouldBe` 1
        case operationEvents of
            [operationEvent] ->
                operationEvent ^. PLTFields.lockEvent . PLTFields.lockDestroyEvent
                    `shouldNotBe` Proto.defMessage
            _ -> expectationFailure "expected one unified lock event"
