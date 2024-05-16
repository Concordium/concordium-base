{-# LANGUAGE DataKinds #-}
{-# LANGUAGE MonoLocalBinds #-}

-- | Tests for JSON encoding and decoding of 'Payload' and 'SignedTransaction'.
module Types.PayloadSpec (tests) where

import Concordium.Crypto.SHA256
import qualified Concordium.Crypto.SignatureScheme as ID
import qualified Concordium.ID.Types as IDTypes
import Concordium.Types
import Concordium.Types.Execution
import Concordium.Types.Transactions as ST
import Concordium.Wasm
import qualified Data.Aeson as AE
import qualified Data.ByteString.Char8 as BS
import Data.ByteString.Short as SBS
import Data.FixedByteString
import qualified Data.Map.Strict as Map
import Data.Primitive.ByteArray
import qualified Data.Text as T
import Data.Word (Word8)
import Test.Hspec

exampleHash :: FixedByteString DigestSize
exampleHash = FixedByteString $ byteArrayFromListN 32 ([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16] :: [Word8])

exampleShortByteString :: ShortByteString
exampleShortByteString = SBS.pack ([1, 2] :: [Word8])

exampleAmount :: Amount
exampleAmount = 3

exampleTimestamp :: Timestamp
exampleTimestamp = Timestamp 3

exampleParameter :: Parameter
exampleParameter = Parameter{parameter = exampleShortByteString}

exampleContractAddress :: ContractAddress
exampleContractAddress = ContractAddress 2 3

exampleAccountAddress :: IDTypes.AccountAddress
exampleAccountAddress = case IDTypes.addressFromText $ T.pack "2zR4h351M1bqhrL9UywsbHrP3ucA1xY3TBTFRuTsRout8JnLD6" of
    Right addr -> addr
    -- This does not happen since the format
    -- of the text is that of a valid address.
    Left str -> error str

exampleTransferPayload :: Payload
exampleTransferPayload = Transfer{tToAddress = exampleAccountAddress, tAmount = exampleAmount}

exampleDeployModulePayload :: Payload
exampleDeployModulePayload = DeployModule{dmMod = WasmModuleV1 (WasmModuleV{wmvSource = ModuleSource{moduleSource = BS.pack "ByteString"}})}

exampleInitContractPayload :: Payload
exampleInitContractPayload = InitContract{icAmount = exampleAmount, icModRef = ModuleRef{moduleRef = Hash exampleHash}, icInitName = InitName{initName = T.pack "init_name"}, icParam = exampleParameter}

exampleUpdateContractPayload :: Payload
exampleUpdateContractPayload =
    Update
        { uAmount = exampleAmount,
          uAddress = exampleContractAddress,
          uReceiveName = ReceiveName{receiveName = T.pack "receive.name"},
          uMessage = exampleParameter
        }

exampleRegisterDataPayload :: Payload
exampleRegisterDataPayload = RegisterData{rdData = RegisteredData exampleShortByteString}

exampleTransferWithMemoPayload :: Payload
exampleTransferWithMemoPayload = TransferWithMemo{twmToAddress = exampleAccountAddress, twmAmount = exampleAmount, twmMemo = Memo exampleShortByteString}

exampleTransferWithSchedulePayload :: Payload
exampleTransferWithSchedulePayload = TransferWithSchedule{twsTo = exampleAccountAddress, twsSchedule = [(exampleTimestamp, exampleAmount)]}

exampleTransferWithScheduleAndMemoPayload :: Payload
exampleTransferWithScheduleAndMemoPayload = TransferWithScheduleAndMemo{twswmTo = exampleAccountAddress, twswmMemo = Memo exampleShortByteString, twswmSchedule = [(exampleTimestamp, exampleAmount)]}

exampleConfigureDelegationPayload :: Payload
exampleConfigureDelegationPayload = ConfigureDelegation{cdCapital = Nothing, cdRestakeEarnings = Just True, cdDelegationTarget = Nothing}

exampleSignatureMapEmpty :: Map.Map IDTypes.KeyIndex ID.Signature
exampleSignatureMapEmpty = Map.empty

exampleSignatureMap :: Map.Map IDTypes.KeyIndex ID.Signature
exampleSignatureMap = Map.insert (1 :: IDTypes.KeyIndex) (ID.Signature exampleShortByteString) exampleSignatureMapEmpty

exampleCredentialSignatureMapEmpty :: Map.Map IDTypes.CredentialIndex (Map.Map IDTypes.KeyIndex ID.Signature)
exampleCredentialSignatureMapEmpty = Map.empty

exampleCredentialSignatureMap :: Map.Map IDTypes.CredentialIndex (Map.Map IDTypes.KeyIndex ID.Signature)
exampleCredentialSignatureMap = Map.insert (1 :: IDTypes.CredentialIndex) exampleSignatureMap exampleCredentialSignatureMapEmpty

exampleSignedTransaction :: ST.SignedTransaction
exampleSignedTransaction =
    ST.SignedTransaction
        { stEnergy = Energy 1,
          stExpiryTime = TransactionTime 2,
          stNonce = Nonce 3,
          stSigner = exampleAccountAddress,
          stPayload = exampleTransferWithSchedulePayload,
          stSignature = TransactionSignature exampleCredentialSignatureMap
        }

-- tests
tests :: Spec
tests = describe "payload JSON encode and decode" $ do
    specify "register data payload example:" $ do
        (AE.eitherDecode . AE.encode $ exampleRegisterDataPayload) `shouldBe` Right exampleRegisterDataPayload
    specify "deploy module payload example:" $ do
        (AE.eitherDecode . AE.encode $ exampleDeployModulePayload) `shouldBe` Right exampleDeployModulePayload
    specify "init contract payload example:" $ do
        (AE.eitherDecode . AE.encode $ exampleInitContractPayload) `shouldBe` Right exampleInitContractPayload
    specify "update contract payload example:" $ do
        (AE.eitherDecode . AE.encode $ exampleUpdateContractPayload) `shouldBe` Right exampleUpdateContractPayload
    specify "transfer payload example:" $ do
        (AE.eitherDecode . AE.encode $ exampleTransferPayload) `shouldBe` Right exampleTransferPayload
    specify "transfer with memo payload example:" $ do
        (AE.eitherDecode . AE.encode $ exampleTransferWithMemoPayload) `shouldBe` Right exampleTransferWithMemoPayload
    specify "transfer with schedule payload example:" $ do
        (AE.eitherDecode . AE.encode $ exampleTransferWithSchedulePayload) `shouldBe` Right exampleTransferWithSchedulePayload
    specify "transfer with schedule payload example:" $ do
        (AE.eitherDecode . AE.encode $ exampleTransferWithSchedulePayload) `shouldBe` Right exampleTransferWithSchedulePayload
    specify "transfer with schedule and memo payload example:" $ do
        (AE.eitherDecode . AE.encode $ exampleTransferWithScheduleAndMemoPayload) `shouldBe` Right exampleTransferWithScheduleAndMemoPayload
    specify "configure delegation payload example:" $ do
        (AE.eitherDecode . AE.encode $ exampleConfigureDelegationPayload) `shouldBe` Right exampleConfigureDelegationPayload
    specify "configure delegation payload example:" $ do
        (AE.eitherDecode . AE.encode $ exampleSignedTransaction) `shouldBe` Right exampleSignedTransaction
