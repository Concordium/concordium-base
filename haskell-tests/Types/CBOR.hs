{-# LANGUAGE OverloadedStrings #-}

module Types.CBOR where

import Codec.CBOR.Read
import qualified Codec.CBOR.Term as CBOR
import Codec.CBOR.Write
import qualified Codec.CBOR.Write as CBOR
import qualified Concordium.Crypto.SHA256 as SHA256
import qualified Data.Aeson as AE
import qualified Data.Aeson.KeyMap as AE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as BS16
import qualified Data.ByteString.Lazy.Char8 as B8
import qualified Data.ByteString.Short as BSS
import qualified Data.FixedByteString as FBS
import qualified Data.Map as Map
import qualified Data.Sequence as Seq
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import qualified Data.Vector as V
import Generators
import Test.HUnit
import Test.Hspec
import Test.QuickCheck

import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.ID.Types
import Concordium.Types
import Concordium.Types.ProtocolLevelTokens.CBOR
import Concordium.Types.Queries.Tokens

genText :: Gen Text.Text
genText = sized $ fmap (Text.decodeUtf8 . BS.pack) . genUtf8String

genSha256Hash :: Gen SHA256.Hash
genSha256Hash = do
    randomBytes <- BS.pack <$> vector SHA256.digestSize -- Generate 32 random bytes
    return (SHA256.hash randomBytes)

genTokenMetadataUrlSimple :: Gen TokenMetadataUrl
genTokenMetadataUrlSimple = do
    url <- genText
    checksumSha256 <- Just <$> genSha256Hash
    return TokenMetadataUrl{tmUrl = url, tmChecksumSha256 = checksumSha256, tmAdditional = Map.empty}

genTokenMetadataUrlAdditional :: Gen TokenMetadataUrl
genTokenMetadataUrlAdditional = do
    tmu <- genTokenMetadataUrlSimple
    additional <- listOf1 genKV
    return tmu{tmAdditional = Map.fromList additional}
  where
    genKV = do
        key <- genText
        val <-
            oneof
                [ CBOR.TInt <$> arbitrary,
                  CBOR.TString <$> genText,
                  CBOR.TBool <$> arbitrary,
                  pure CBOR.TNull
                ]
        return ("_" <> key, val)

genTokenInitializationParameters :: Gen TokenInitializationParameters
genTokenInitializationParameters = do
    tipName <- genText
    tipMetadata <- genTokenMetadataUrlSimple
    tipGovernanceAccount <- genCborTokenHolder
    tipAllowList <- arbitrary
    tipDenyList <- arbitrary
    tipInitialSupply <- oneof [pure Nothing, Just <$> genTokenAmount]
    tipMintable <- arbitrary
    tipBurnable <- arbitrary
    return TokenInitializationParameters{..}

-- | Generator for `TokenTransferBody`
genTokenTransfer :: Gen TokenTransferBody
genTokenTransfer = do
    ttAmount <- genTokenAmount
    ttRecipient <- genCborTokenHolder
    ttMemo <- oneof [pure Nothing, Just <$> genTaggableMemo]
    return TokenTransferBody{..}

-- | Generator for `CborTokenHolder`
genCborTokenHolder :: Gen CborTokenHolder
genCborTokenHolder =
    oneof
        [ CborHolderAccount <$> genAccountAddress <*> pure (Just CoinInfoConcordium),
          CborHolderAccount <$> genAccountAddress <*> pure Nothing
        ]

-- | Generator for `TaggableMemo`
genTaggableMemo :: Gen TaggableMemo
genTaggableMemo =
    oneof
        [ UntaggedMemo <$> genMemo,
          CBORMemo <$> genMemo
        ]

-- | Generator for 'TokenGovernanceOperation'.
genTokenOperation :: Gen TokenOperation
genTokenOperation =
    oneof
        [ TokenTransfer <$> genTokenTransfer,
          TokenMint <$> genTokenAmount,
          TokenBurn <$> genTokenAmount,
          TokenAddAllowList <$> genCborTokenHolder,
          TokenRemoveAllowList <$> genCborTokenHolder,
          TokenAddDenyList <$> genCborTokenHolder,
          TokenRemoveDenyList <$> genCborTokenHolder,
          pure TokenPause,
          pure TokenUnpause
        ]

-- | Generator for 'TokenGovernanceOperation'.
genTokenTransaction :: Gen TokenUpdateTransaction
genTokenTransaction =
    TokenUpdateTransaction . Seq.fromList
        <$> listOf genTokenOperation

genTokenModuleStateSimple :: Gen TokenModuleState
genTokenModuleStateSimple = do
    tmsName <- genText
    tmsMetadata <- genTokenMetadataUrlSimple
    tmsGovernanceAccount <- genCborTokenHolder
    tmsPaused <- arbitrary
    tmsAllowList <- arbitrary
    tmsDenyList <- arbitrary
    tmsMintable <- arbitrary
    tmsBurnable <- arbitrary
    let tmsAdditional = Map.empty
    return TokenModuleState{..}

genTokenModuleStateWithAdditional :: Gen TokenModuleState
genTokenModuleStateWithAdditional = do
    tms <- genTokenModuleStateSimple
    additional <- listOf1 genKV
    return tms{tmsAdditional = Map.fromList additional}
  where
    genKV = do
        key <- genText
        val <-
            oneof
                [ CBOR.TInt <$> arbitrary,
                  CBOR.TString <$> genText,
                  CBOR.TBool <$> arbitrary,
                  pure CBOR.TNull
                ]
        return ("_" <> key, val)

genTokenStateSimple :: Gen TokenState
genTokenStateSimple = do
    tsTokenModuleRef <- genTokenModuleRef
    tsTotalSupply <- genTokenAmount
    tsDecimals <- arbitrary
    tms <- genTokenModuleStateSimple
    let tsModuleState = tokenModuleStateToBytes tms
    return TokenState{..}

genTokenStateWithAdditional :: Gen TokenState
genTokenStateWithAdditional = do
    tsTokenModuleRef <- genTokenModuleRef
    tsTotalSupply <- genTokenAmount
    tsDecimals <- arbitrary
    tms <- genTokenModuleStateWithAdditional
    let tsModuleState = tokenModuleStateToBytes tms
    return TokenState{..}

genTokenModuleAccountState :: Gen TokenModuleAccountState
genTokenModuleAccountState = do
    tmasAllowList <- arbitrary
    tmasDenyList <- arbitrary
    let tmasAdditional = Map.empty
    return TokenModuleAccountState{..}

genTokenModuleAccountStateWithAdditional :: Gen TokenModuleAccountState
genTokenModuleAccountStateWithAdditional = do
    tmas <- genTokenModuleAccountState
    additional <- listOf1 genKV
    return tmas{tmasAdditional = Map.fromList additional}
  where
    genKV = do
        key <- genText
        val <-
            oneof
                [ CBOR.TInt <$> arbitrary,
                  CBOR.TString <$> genText,
                  CBOR.TBool <$> arbitrary,
                  pure CBOR.TNull
                ]
        return ("_" <> key, val)

genTokenEvent :: Gen TokenEvent
genTokenEvent =
    oneof
        [ AddAllowListEvent <$> genCborTokenHolder,
          RemoveAllowListEvent <$> genCborTokenHolder,
          AddDenyListEvent <$> genCborTokenHolder,
          RemoveDenyListEvent <$> genCborTokenHolder,
          pure Pause,
          pure Unpause
        ]

-- | Generator for 'TokenRejectReason'.
genTokenRejectReason :: Gen TokenRejectReason
genTokenRejectReason =
    oneof
        [ AddressNotFound <$> arbitrary <*> genCborTokenHolder,
          TokenBalanceInsufficient <$> arbitrary <*> genTokenAmount <*> genTokenAmount,
          DeserializationFailure <$> liftArbitrary genText,
          UnsupportedOperation <$> arbitrary <*> genText <*> liftArbitrary genText,
          MintWouldOverflow <$> arbitrary <*> genTokenAmount <*> genTokenAmount <*> genTokenAmount,
          OperationNotPermitted <$> arbitrary <*> liftArbitrary genCborTokenHolder <*> liftArbitrary genText
        ]

-- | An example value for governance account addresses.
exampleCborTokenHolder :: CborTokenHolder
exampleCborTokenHolder =
    CborHolderAccount accountAddress (Just CoinInfoConcordium)
  where
    accountAddress = case addressFromText "2zR4h351M1bqhrL9UywsbHrP3ucA1xY3TBTFRuTsRout8JnLD6" of
        Right addr -> addr
        -- This does not happen since the format
        -- of the text is that of a valid address.
        Left str -> error str

-- | A test value for 'TokenInitializationParameters'.
tip1 :: TokenInitializationParameters
tip1 =
    TokenInitializationParameters
        { tipName = "ABC token",
          tipMetadata =
            TokenMetadataUrl
                { tmUrl = "https://abc.token/meta",
                  -- tmChecksumSha256 = Just (SHA256.Hash (FBS.fromByteString "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")),
                  tmChecksumSha256 = Nothing,
                  tmAdditional = Map.empty
                },
          tipGovernanceAccount = exampleCborTokenHolder,
          tipAllowList = False,
          tipInitialSupply = Just (TokenAmount{taValue = 10000, taDecimals = 5}),
          tipDenyList = False,
          tipMintable = False,
          tipBurnable = False
        }

-- | Basic tests for CBOR encoding/decoding of 'TokenInitializationParameters'.
testEncodedInitializationParametersCBOR :: Spec
testEncodedInitializationParametersCBOR = describe "TokenInitializationParameters CBOR serialization" $ do
    it "Decode success" $
        assertEqual
            "Decoded CBOR"
            (Right ("", tip1))
            ( deserialiseFromBytes
                decodeTokenInitializationParameters
                "\168dnameiABC tokenhburnable\244hdenyList\244hmetadata\161curlvhttps://abc.token/metahmintable\244iallowList\244minitialSupply\196\130$\EM'\DLEqgovernanceAccount\217\157s\162\SOH\217\157q\161\SOH\EM\ETX\151\ETXX \ACK\DLEI\220\DC1]\176\b`\RS\196\224\241\145c\ETB\193\204'\141l\237\t\212t\217\148\197N\172\172\161"
            )
    it "Missing \"name\"" $
        assertEqual
            "Decoded CBOR"
            (Left (DeserialiseFailure 69 "Missing \"name\""))
            ( deserialiseFromBytes
                decodeTokenInitializationParameters
                "\xA3\x68metadata\xA1\x63url\x76https://abc.token/meta\x69\
                \allowList\xF4\x6DinitialSupply\xC4\x82\x24\x19\x27\x10"
            )
    it "Duplicate \"name\" key" $
        assertEqual
            "Decode result"
            (Left (DeserialiseFailure 95 "Key already set: \"name\""))
            ( deserialiseFromBytes
                decodeTokenInitializationParameters
                "\xA5\x64name\x69\
                \ABC token\x68metadata\xA1\x63url\x76https://abc.token/meta\x69\
                \allowList\xF4\x6DinitialSupply\xC4\x82\x24\x19\x27\x10\
                \\x64name\x65token"
            )
    it "Encode and decode (no defaults)" $ withMaxSuccess 10000 $ forAll genTokenInitializationParameters $ \tip ->
        Right ("", tip)
            === deserialiseFromBytes
                decodeTokenInitializationParameters
                (toLazyByteString $ encodeTokenInitializationParametersNoDefaults tip)
    it "Encode and decode (with defaults)" $ withMaxSuccess 10000 $ forAll genTokenInitializationParameters $ \tip ->
        Right ("", tip)
            === deserialiseFromBytes
                decodeTokenInitializationParameters
                (toLazyByteString $ encodeTokenInitializationParametersWithDefaults tip)

-- | A test value for 'TokenInitializationParameters'.
tip2 :: TokenInitializationParameters
tip2 =
    tip1
        { -- Use a token amount that is not modified by "normalization". Normalization may be removed entirely, but for now, work around it like this
          tipInitialSupply = Just (TokenAmount{taValue = 12345, taDecimals = 5})
        }

-- | Encoded 'TokenInitializationParameters' that can be successfully CBOR decoded
encTip1 :: EncodedTokenInitializationParameters
encTip1 =
    EncodedTokenInitializationParameters $
        TokenParameter $
            BSS.toShort $
                CBOR.toStrictByteString $
                    encodeTokenInitializationParametersWithDefaults tip2

-- | Encoded 'TokenInitializationParameters' that cannot be successfully CBOR decoded
invalidEncTip1 :: EncodedTokenInitializationParameters
invalidEncTip1 =
    EncodedTokenInitializationParameters $
        TokenParameter $
            BSS.pack [0x1, 0x2, 0x3, 0x4]

testEncodedInitializationParametersJSON :: Spec
testEncodedInitializationParametersJSON = describe "TokenInitializationParameters JSON serialization" $ do
    it "Serialize/Deserialize roundtrip success JSON" $
        assertEqual
            "Deserialized"
            (Just encTip1)
            ( AE.decode $
                AE.encode
                    encTip1
            )
    it "Serializes to expected JSON object" $
        case AE.toJSON encTip1 of
            AE.Object o -> assertBool "Does not contain field name" $ AE.member "name" o
            _ -> assertFailure "Does not encode to JSON object"
    it "Serialize/Deserialize roundtrip where CBOR is not a valid TokenInitializationParameters" $
        assertEqual
            "Deserialized"
            (Just invalidEncTip1)
            ( AE.decode $
                AE.encode
                    invalidEncTip1
            )

-- | A test value for 'TokenUpdateTransaction'.
tops1 :: TokenUpdateTransaction
tops1 =
    TokenUpdateTransaction $
        Seq.fromList
            [ TokenTransfer
                TokenTransferBody
                    { -- Use a token amount that is not modified by "normalization". Normalization may be removed entirely, but for now, work around it like this
                      ttAmount = TokenAmount{taValue = 12345, taDecimals = 5},
                      ttRecipient = cborHolder,
                      ttMemo = Just $ UntaggedMemo $ Memo $ BSS.pack [0x1, 0x2, 0x3, 0x4]
                    },
              TokenMint{toMintAmount = TokenAmount{taValue = 12345, taDecimals = 5}},
              TokenBurn{toBurnAmount = TokenAmount{taValue = 12345, taDecimals = 5}},
              TokenAddAllowList{toTarget = cborHolder},
              TokenRemoveAllowList{toTarget = cborHolder},
              TokenAddDenyList{toTarget = cborHolder},
              TokenRemoveDenyList{toTarget = cborHolder},
              TokenPause,
              TokenUnpause
            ]
  where
    cborHolder =
        CborHolderAccount
            { chaAccount =
                AccountAddress $
                    FBS.pack (replicate 32 1),
              chaCoinInfo = Just CoinInfoConcordium
            }

-- | The CBOR encoding of 'tops1'
tops1ExpectedCbor :: BS.ByteString
tops1ExpectedCbor =
    BS16.decodeLenient
        "89a1687472616e73666572a3646d656d6f440102030466616d6f756e74c48224\
        \19303969726563697069656e74d99d73a201d99d71a101190397035820010101\
        \0101010101010101010101010101010101010101010101010101010101a1646d\
        \696e74a166616d6f756e74c48224193039a1646275726ea166616d6f756e74c4\
        \8224193039a16c616464416c6c6f774c697374a166746172676574d99d73a201\
        \d99d71a101190397035820010101010101010101010101010101010101010101\
        \0101010101010101010101a16f72656d6f7665416c6c6f774c697374a1667461\
        \72676574d99d73a201d99d71a101190397035820010101010101010101010101\
        \0101010101010101010101010101010101010101a16b61646444656e794c6973\
        \74a166746172676574d99d73a201d99d71a10119039703582001010101010101\
        \01010101010101010101010101010101010101010101010101a16e72656d6f76\
        \6544656e794c697374a166746172676574d99d73a201d99d71a1011903970358\
        \2001010101010101010101010101010101010101010101010101010101010101\
        \01a1657061757365a0a167756e7061757365a0"

-- | Encoded 'TokenHolderTransaction' that can be successfully CBOR decoded
encTops1 :: EncodedTokenOperations
encTops1 =
    EncodedTokenOperations $
        TokenParameter $
            BSS.toShort $
                CBOR.toStrictByteString $
                    encodeTokenUpdateTransaction tops1

-- | A dummy 'CborTokenHolder' value.
dummyCborHolder :: CborTokenHolder
dummyCborHolder =
    CborHolderAccount
        { chaAccount = AccountAddress $ FBS.pack (replicate 32 1),
          chaCoinInfo = Just CoinInfoConcordium
        }

-- | The expected CBOR encoding of 'dummyCborHolder'.
expectedDummyCborHolderEncoding :: BSS.ShortByteString
expectedDummyCborHolderEncoding =
    BSS.toShort . BS16.decodeLenient $
        "a166746172676574d99d73a201d99d71a101190397035820\
        \0101010101010101010101010101010101010101010101010101010101010101"

tevents1 :: [TokenEvent]
tevents1 =
    [ AddAllowListEvent dummyCborHolder,
      RemoveAllowListEvent dummyCborHolder,
      AddDenyListEvent dummyCborHolder,
      RemoveDenyListEvent dummyCborHolder,
      Pause,
      Unpause
    ]

-- | Encoded 'TokenHolderTransaction' that cannot be successfully CBOR decoded
invalidEncTops1 :: EncodedTokenOperations
invalidEncTops1 =
    EncodedTokenOperations $
        TokenParameter $
            BSS.pack [0x1, 0x2, 0x3, 0x4]

testEncodedTokenOperationsJSON :: Spec
testEncodedTokenOperationsJSON = describe "EncodedTokenOperations JSON serialization" $ do
    it "Serialize/Deserialize roundtrip success" $
        assertEqual
            "Deserialized"
            (Just encTops1)
            ( AE.decode $
                AE.encode
                    encTops1
            )
    it "Serializes to expected JSON object" $
        case AE.toJSON encTops1 of
            AE.Array v -> case V.head v of
                AE.Object o -> assertBool "Does not contain field amount" $ AE.member "transfer" o
                _ -> assertFailure "Does not encode to JSON object"
            _ -> assertFailure "Does not encode to JSON array"

    it "Serialize/Deserialize roundtrip where CBOR is not a valid TokenUpdateTransaction" $
        assertEqual
            "Deserialized"
            (Just invalidEncTops1)
            ( AE.decode $
                AE.encode
                    invalidEncTops1
            )

testEncodedTokenOperationsCBOR :: Spec
testEncodedTokenOperationsCBOR = describe "EncodedTokenOperations CBOR serialization" $ do
    it "Serialize/Deserialize roundtrip" $
        assertEqual
            "Deserialized"
            (tokenUpdateTransactionFromBytes $ B8.fromStrict $ tokenUpdateTransactionToBytes tops1)
            (Right tops1)
    it "Serializes to expected CBOR bytestring" $
        assertEqual
            "CBOR serialized"
            (tokenUpdateTransactionToBytes tops1)
            tops1ExpectedCbor

testEncodedTokenEvents :: Spec
testEncodedTokenEvents = describe "TokenEvents CBOR serialization" $ do
    it "Serialize/Deserialize roundtrip" $
        assertEqual
            "Deserialized"
            (map (decodeTokenEvent . encodeTokenEvent) tevents1)
            (map Right tevents1)
    it "Serializes to expected CBOR bytestring" $ do
        assertEqual
            "Serialized to expected CBOR bytestring"
            [ EncodedTokenEvent
                { eteType = TokenEventType "addAllowList",
                  eteDetails = TokenEventDetails expectedDummyCborHolderEncoding
                },
              EncodedTokenEvent
                { eteType = TokenEventType "removeAllowList",
                  eteDetails = TokenEventDetails expectedDummyCborHolderEncoding
                },
              EncodedTokenEvent
                { eteType = TokenEventType "addDenyList",
                  eteDetails = TokenEventDetails expectedDummyCborHolderEncoding
                },
              EncodedTokenEvent
                { eteType = TokenEventType "removeDenyList",
                  eteDetails = TokenEventDetails expectedDummyCborHolderEncoding
                },
              EncodedTokenEvent
                { eteType = TokenEventType "pause",
                  eteDetails = TokenEventDetails $ BSS.pack [160]
                },
              EncodedTokenEvent
                { eteType = TokenEventType "unpause",
                  eteDetails = TokenEventDetails $ BSS.pack [160]
                }
            ]
            (map encodeTokenEvent tevents1)

emptyStringHash :: Hash.Hash
emptyStringHash = Hash.hash ""

testTokenModuleStateSimpleJSON :: Spec
testTokenModuleStateSimpleJSON = describe "TokenModuleState JSON serialization without additional state" $ do
    let tokenMetadataURL =
            TokenMetadataUrl
                { tmUrl = "https://example.com/token-metadata",
                  tmChecksumSha256 = Nothing,
                  tmAdditional = Map.empty
                }
    let object =
            TokenModuleState
                { tmsMetadata = tokenMetadataURL,
                  tmsName = "bla bla",
                  tmsGovernanceAccount = exampleCborTokenHolder,
                  tmsPaused = Just False,
                  tmsAllowList = Just True,
                  tmsDenyList = Just True,
                  tmsMintable = Just True,
                  tmsBurnable = Just False,
                  tmsAdditional = Map.empty
                }

    it "Serialize/Deserialize roundtrip success" $
        assertEqual
            "Deserialized"
            (Just object)
            ( AE.decode $
                AE.encode
                    object
            )

    it "Compare JSON object" $ do
        let jsonString = "{\"allowList\":true,\"denyList\":true,\"burnable\":false,\"mintable\":true,\"metadata\":{\"url\":\"https://example.com/token-metadata\"},\"name\":\"bla bla\",\"governanceAccount\":{\"address\":\"2zR4h351M1bqhrL9UywsbHrP3ucA1xY3TBTFRuTsRout8JnLD6\",\"coinInfo\":\"CCD\",\"type\":\"account\"}, \"paused\":false}"
            expectedValue = AE.decode (B8.pack jsonString) :: Maybe AE.Value
            actualValue = Just (AE.toJSON object)
        assertEqual "Comparing JSON object failed" expectedValue actualValue

    it "Serializes to expected JSON object" $
        case AE.toJSON object of
            AE.Object o -> do
                assertBool "Does not contain field metadata" $ AE.member "metadata" o
                assertBool "Does not contain field name" $ AE.member "name" o
                assertBool "Does not contain field allowList" $ AE.member "allowList" o
                assertBool "Does not contain field denyList" $ AE.member "denyList" o
                assertBool "Does not contain field mintable" $ AE.member "mintable" o
                assertBool "Does not contain field burnable" $ AE.member "burnable" o
            _ -> assertFailure "Does not encode to JSON object"

testTokenModuleStateJSON :: Spec
testTokenModuleStateJSON = describe "TokenModuleState JSON serialization with additional state" $ do
    let tokenMetadataURL =
            TokenMetadataUrl
                { tmUrl = "https://example.com/token-metadata",
                  tmChecksumSha256 = Nothing,
                  tmAdditional = Map.empty
                }
    let object =
            TokenModuleState
                { tmsMetadata = tokenMetadataURL,
                  tmsName = "bla bla",
                  tmsGovernanceAccount = exampleCborTokenHolder,
                  tmsPaused = Just False,
                  tmsAllowList = Just True,
                  tmsDenyList = Just True,
                  tmsMintable = Just True,
                  tmsBurnable = Just False,
                  tmsAdditional = Map.fromList [("otherField" :: Text.Text, CBOR.TBool True)]
                }

    it "Serialize/Deserialize roundtrip success" $
        assertEqual
            "Deserialized"
            (Just object)
            ( AE.decode $
                AE.encode
                    object
            )

    it "Compare JSON object" $ do
        let jsonString = "{\"_additional\":{\"otherField\":\"f5\"},\"allowList\":true,\"denyList\":true,\"burnable\":false,\"mintable\":true,\"metadata\":{\"url\":\"https://example.com/token-metadata\"},\"name\":\"bla bla\",\"governanceAccount\":{\"address\":\"2zR4h351M1bqhrL9UywsbHrP3ucA1xY3TBTFRuTsRout8JnLD6\",\"coinInfo\":\"CCD\",\"type\":\"account\"}, \"paused\":false}"
            expectedValue = AE.decode (B8.pack jsonString) :: Maybe AE.Value
            actualValue = Just (AE.toJSON object)
        assertEqual "Comparing JSON object failed" expectedValue actualValue
    it "Serializes to expected JSON object" $
        case AE.toJSON object of
            AE.Object o -> do
                assertBool "Does not contain field metadata" $ AE.member "metadata" o
                assertBool "Does not contain field name" $ AE.member "name" o
                assertBool "Does not contain field allowList" $ AE.member "allowList" o
                assertBool "Does not contain field denyList" $ AE.member "denyList" o
                assertBool "Does not contain field mintable" $ AE.member "mintable" o
                assertBool "Does not contain field burnable" $ AE.member "burnable" o
                assertBool "Does not contain field _additional" $ AE.member "_additional" o
            _ -> assertFailure "Does not encode to JSON object"

testTokenStateSimpleJSON :: Spec
testTokenStateSimpleJSON = describe "TokenState JSON serialization without additional state" $ do
    let tokenMetadataURL =
            TokenMetadataUrl
                { tmUrl = "https://example.com/token-metadata",
                  tmChecksumSha256 = Nothing,
                  tmAdditional = Map.empty
                }
    let tokenModuleState =
            TokenModuleState
                { tmsMetadata = tokenMetadataURL,
                  tmsName = "bla bla",
                  tmsGovernanceAccount = exampleCborTokenHolder,
                  tmsPaused = Just False,
                  tmsAllowList = Just True,
                  tmsDenyList = Just True,
                  tmsMintable = Just True,
                  tmsBurnable = Just False,
                  tmsAdditional = Map.empty
                }
    let tokenModuleRef = TokenModuleRef{theTokenModuleRef = emptyStringHash}
    let object =
            TokenState
                { tsTokenModuleRef = tokenModuleRef,
                  tsTotalSupply = TokenAmount{taValue = 10000, taDecimals = 2},
                  tsDecimals = 2,
                  tsModuleState = tokenModuleStateToBytes tokenModuleState
                }

    it "Serialize/Deserialize roundtrip success" $
        assertEqual
            "Deserialized"
            (Just object)
            ( AE.decode $
                AE.encode
                    object
            )

    it "Compare JSON object" $ do
        let jsonString = "{\"totalSupply\":{\"decimals\":2.0,\"value\":\"10000\"},\"tokenModuleRef\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"decimals\":2.0,\"moduleState\":{\"allowList\":true,\"denyList\":true,\"burnable\":false,\"mintable\":true,\"metadata\":{\"url\":\"https://example.com/token-metadata\"},\"name\":\"bla bla\",\"governanceAccount\":{\"address\":\"2zR4h351M1bqhrL9UywsbHrP3ucA1xY3TBTFRuTsRout8JnLD6\",\"coinInfo\":\"CCD\",\"type\":\"account\"}, \"paused\":false}}"
            expectedValue = AE.decode (B8.pack jsonString) :: Maybe AE.Value
            actualValue = Just (AE.toJSON object)
        assertEqual "Comparing JSON object failed" expectedValue actualValue

    it "Serializes to expected JSON object" $
        case AE.toJSON object of
            AE.Object o -> do
                assertBool "Does not contain field tokenModuleRef" $ AE.member "tokenModuleRef" o
                assertBool "Does not contain field totalSupply" $ AE.member "totalSupply" o
                assertBool "Does not contain field decimals" $ AE.member "decimals" o
                assertBool "Does not contain field moduleState" $ AE.member "moduleState" o
            _ -> assertFailure "Does not encode to JSON object"

testTokenStateJSON :: Spec
testTokenStateJSON = describe "TokenState JSON serialization with additional state" $ do
    let tokenMetadataURL =
            TokenMetadataUrl
                { tmUrl = "https://example.com/token-metadata",
                  tmChecksumSha256 = Nothing,
                  tmAdditional = Map.empty
                }
    let tokenModuleState =
            TokenModuleState
                { tmsMetadata = tokenMetadataURL,
                  tmsName = "bla bla",
                  tmsGovernanceAccount = exampleCborTokenHolder,
                  tmsPaused = Just False,
                  tmsAllowList = Just True,
                  tmsDenyList = Just True,
                  tmsMintable = Just True,
                  tmsBurnable = Just False,
                  tmsAdditional = Map.fromList [("otherField1" :: Text.Text, CBOR.TString "abc"), ("otherField2" :: Text.Text, CBOR.TInt 3), ("otherField3" :: Text.Text, CBOR.TBool True), ("otherField4" :: Text.Text, CBOR.TNull)]
                }
    let tokenModuleRef = TokenModuleRef{theTokenModuleRef = emptyStringHash}
    let object =
            TokenState
                { tsTokenModuleRef = tokenModuleRef,
                  tsTotalSupply = TokenAmount{taValue = 10000, taDecimals = 2},
                  tsDecimals = 2,
                  tsModuleState = tokenModuleStateToBytes tokenModuleState
                }

    it "Serialize/Deserialize roundtrip success" $
        assertEqual
            "Deserialized"
            (Just object)
            ( AE.decode $
                AE.encode
                    object
            )

    it "Compare JSON object" $ do
        let jsonString = "{\"totalSupply\":{\"decimals\":2.0,\"value\":\"10000\"},\"tokenModuleRef\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"decimals\":2.0,\"moduleState\":{\"_additional\":{\"otherField1\":\"63616263\",\"otherField2\":\"03\",\"otherField3\":\"f5\",\"otherField4\":\"f6\"},\"allowList\":true,\"denyList\":true,\"burnable\":false,\"mintable\":true,\"metadata\":{\"url\":\"https://example.com/token-metadata\"},\"name\":\"bla bla\",\"governanceAccount\":{\"address\":\"2zR4h351M1bqhrL9UywsbHrP3ucA1xY3TBTFRuTsRout8JnLD6\",\"coinInfo\":\"CCD\",\"type\":\"account\"}, \"paused\":false}}"
            expectedValue = AE.decode (B8.pack jsonString) :: Maybe AE.Value
            actualValue = Just (AE.toJSON object)
        assertEqual "Comparing JSON object failed" expectedValue actualValue

    it "Serializes to expected JSON object" $
        case AE.toJSON object of
            AE.Object o -> do
                assertBool "Does not contain field tokenModuleRef" $ AE.member "tokenModuleRef" o
                assertBool "Does not contain field totalSupply" $ AE.member "totalSupply" o
                assertBool "Does not contain field decimals" $ AE.member "decimals" o
                assertBool "Does not contain field moduleState" $ AE.member "moduleState" o
            _ -> assertFailure "Does not encode to JSON object"

testTokenMetadataUrlJSON :: Spec
testTokenMetadataUrlJSON = describe "TokenMetadataUrl JSON serialization" $ do
    let tmUrl =
            TokenMetadataUrl
                { tmUrl = "https://example.com/token-metadata",
                  tmChecksumSha256 = Just $ SHA256.Hash (FBS.pack $ replicate 32 0xab),
                  tmAdditional = Map.empty
                }
    it "Serialize/Deserialize roundtrip success" $
        assertEqual
            "Deserialized"
            (Just tmUrl)
            ( AE.decode $
                AE.encode
                    tmUrl
            )
    it "Serializes to expected JSON object" $
        case AE.toJSON tmUrl of
            AE.Object o -> assertBool "Does not contain field url" $ AE.member "url" o
            _ -> assertFailure "Does not encode to JSON object"

testTokenMetadataUrlCBOR :: Spec
testTokenMetadataUrlCBOR = describe "TokenMetadataUrl CBOR serialization" $ do
    it "Decodes TokenMetadataUrl without additional" $
        assertEqual
            "Decoded CBOR"
            ( Right
                ( "",
                  TokenMetadataUrl
                    { tmUrl = "https://abc.token/meta",
                      tmChecksumSha256 = Just $ SHA256.Hash (FBS.pack $ replicate 32 0xab),
                      tmAdditional = Map.empty
                    }
                )
            )
            ( deserialiseFromBytes
                decodeTokenMetadataUrl
                "\xA2\x63\x75\x72\x6C\x76\x68\x74\x74\x70\x73\x3A\x2F\x2F\x61\x62\x63\x2E\x74\x6F\x6B\x65\x6E\x2F\x6D\x65\x74\x61\x6E\x63\x68\x65\x63\x6B\x73\x75\x6D\x53\x68\x61\x32\x35\x36\x58\x20\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB"
            )
    it "Decode TokenMetadataUrl with only url" $
        assertEqual
            "Decoded TokenMetadataUrl"
            ( Right
                ( "",
                  TokenMetadataUrl
                    { tmUrl = "https://abc.token/meta",
                      tmChecksumSha256 = Nothing,
                      tmAdditional = Map.empty
                    }
                )
            )
            ( deserialiseFromBytes
                decodeTokenMetadataUrl
                "\xA1\x63\x75\x72\x6C\x76\x68\x74\x74\x70\x73\x3A\x2F\x2F\x61\x62\x63\x2E\x74\x6F\x6B\x65\x6E\x2F\x6D\x65\x74\x61"
            )
    it "Decode TokenMetadataUrl with url, checksumSha256, and additional fields" $
        assertEqual
            "Decoded TokenMetadataUrl"
            ( Right
                ( "",
                  TokenMetadataUrl
                    { tmUrl = "https://abc.token/meta",
                      tmChecksumSha256 = Just $ SHA256.Hash (FBS.pack $ replicate 32 0xab),
                      tmAdditional =
                        Map.fromList
                            [ ("key1", CBOR.TInt 42),
                              ("key2", CBOR.TString "extra value")
                            ]
                    }
                )
            )
            ( deserialiseFromBytes
                decodeTokenMetadataUrl
                "\xA4\x63\x75\x72\x6C\x76\x68\x74\x74\x70\x73\x3A\x2F\x2F\x61\x62\x63\x2E\x74\x6F\x6B\x65\x6E\x2F\x6D\x65\x74\x61\x6E\x63\x68\x65\x63\x6B\x73\x75\x6D\x53\x68\x61\x32\x35\x36\x58\x20\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\x64\x6B\x65\x79\x31\x18\x2A\x64\x6B\x65\x79\x32\x6B\x65\x78\x74\x72\x61\x20\x76\x61\x6C\x75\x65"
            )

tests :: Spec
tests = parallel $ describe "CBOR" $ do
    testEncodedInitializationParametersCBOR
    testEncodedInitializationParametersJSON
    testEncodedTokenOperationsJSON
    testEncodedTokenOperationsCBOR
    testEncodedTokenEvents
    testTokenMetadataUrlJSON
    testTokenMetadataUrlCBOR
    testTokenModuleStateSimpleJSON
    testTokenModuleStateJSON
    testTokenStateSimpleJSON
    testTokenStateJSON
    it "JSON (de-)serialization roundtrip for TokenState (simple)" $ withMaxSuccess 1000 $ forAll genTokenStateSimple $ \tt ->
        assertEqual
            "JSON (de-)serialization roundtrip failed for TokenState (simple)"
            (Just tt)
            ( AE.decode $
                AE.encode
                    tt
            )
    it "JSON (de-)serialization roundtrip for TokenState (complex)" $ withMaxSuccess 1000 $ forAll genTokenStateWithAdditional $ \tt ->
        assertEqual
            "JSON (de-)serialization roundtrip failed for TokenState (complex)"
            (Just tt)
            ( AE.decode $
                AE.encode
                    tt
            )
    it "JSON (de-)serialization roundtrip for TokenModuleState (simple)" $ withMaxSuccess 1000 $ forAll genTokenModuleStateSimple $ \tt ->
        assertEqual
            "JSON (de-)serialization roundtrip failed for TokenModuleState (simple)"
            (Just tt)
            ( AE.decode $
                AE.encode
                    tt
            )
    it "JSON (de-)serialization roundtrip for TokenModuleState (complex)" $ withMaxSuccess 1000 $ forAll genTokenModuleStateWithAdditional $ \tt ->
        assertEqual
            "JSON (de-)serialization roundtrip failed for TokenModuleState (complex)"
            (Just tt)
            ( AE.decode $
                AE.encode
                    tt
            )
    it "Encode and decode TokenTransfer" $ withMaxSuccess 1000 $ forAll genTokenTransfer $ \tt ->
        Right ("", tt)
            === deserialiseFromBytes
                decodeTokenTransfer
                (toLazyByteString $ encodeTokenTransfer tt)
    it "Encode and decode TokenTransfer" $ withMaxSuccess 1000 $ forAll genTokenTransfer $ \tt ->
        (Right ("", tt))
            === ( deserialiseFromBytes
                    decodeTokenTransfer
                    (toLazyByteString $ encodeTokenTransfer tt)
                )
    it "CBOR Encode and decode TokenMetadataUrl (simple)" $ withMaxSuccess 1000 $ forAll genTokenMetadataUrlSimple $ \tmu ->
        Right ("", tmu)
            === deserialiseFromBytes
                decodeTokenMetadataUrl
                (toLazyByteString $ encodeTokenMetadataUrl tmu)
    it "CBOR Encode and decode TokenMetadataUrl (with additional)" $ withMaxSuccess 1000 $ forAll genTokenMetadataUrlAdditional $ \tmu ->
        Right ("", tmu)
            === deserialiseFromBytes
                decodeTokenMetadataUrl
                (toLazyByteString $ encodeTokenMetadataUrl tmu)
    it "JSON Encode and decode TokenMetadataUrl (with simple)" $ withMaxSuccess 1000 $ forAll genTokenMetadataUrlSimple $ \tmu ->
        Just tmu === AE.decode (AE.encode tmu)
    it "JSON Encode and decode TokenMetadataUrl (with additional)" $ withMaxSuccess 1000 $ forAll genTokenMetadataUrlAdditional $ \tmu ->
        Just tmu === AE.decode (AE.encode tmu)
    it "JSON Encode and decode CborTokenHolder" $ withMaxSuccess 1000 $ forAll genTokenHolder $ \th -> Just th == AE.decode (AE.encode th)
    it "CBOR Encode and decode CborTokenHolder" $ withMaxSuccess 1000 $ forAll genCborTokenHolder $ \th ->
        Right ("", th)
            === deserialiseFromBytes
                decodeCborTokenHolder
                (toLazyByteString $ encodeCborTokenHolder th)
    it "Encode and decode TokenUpdateTransaction" $ withMaxSuccess 1000 $ forAll genTokenTransaction $ \tt ->
        Right ("", tt)
            === deserialiseFromBytes
                decodeTokenUpdateTransaction
                (toLazyByteString $ encodeTokenUpdateTransaction tt)
    it "Encode and decode TokenOperation" $ withMaxSuccess 1000 $ forAll genTokenOperation $ \tt ->
        Right ("", tt)
            === deserialiseFromBytes
                decodeTokenOperation
                (toLazyByteString $ encodeTokenOperation tt)
    it "Encode and decode TokenModuleState (simple)" $ withMaxSuccess 1000 $ forAll genTokenModuleStateSimple $ \tt ->
        Right ("", tt)
            === deserialiseFromBytes
                decodeTokenModuleState
                (toLazyByteString $ encodeTokenModuleState tt)
    it "Encode and decode TokenModuleState (with additional)" $ withMaxSuccess 1000 $ forAll genTokenModuleStateWithAdditional $ \tt ->
        Right ("", tt)
            === deserialiseFromBytes
                decodeTokenModuleState
                (toLazyByteString $ encodeTokenModuleState tt)
    it "Encode and decode TokenModuleAccountState (simple)" $ withMaxSuccess 1000 $ forAll genTokenModuleAccountState $ \tt ->
        (Right ("", tt))
            === ( deserialiseFromBytes
                    decodeTokenModuleAccountState
                    (toLazyByteString $ encodeTokenModuleAccountState tt)
                )
    it "Encode and decode TokenModuleAccountState (with additional)" $ withMaxSuccess 1000 $ forAll genTokenModuleAccountStateWithAdditional $ \tt ->
        (Right ("", tt))
            === ( deserialiseFromBytes
                    decodeTokenModuleAccountState
                    (toLazyByteString $ encodeTokenModuleAccountState tt)
                )
    it "Encode and decode TokenEvent" $ withMaxSuccess 1000 $ forAll genTokenEvent $ \tt ->
        Right tt === decodeTokenEvent (encodeTokenEvent tt)
    it "Encode and decode TokenRejectReason" $ withMaxSuccess 1000 $ forAll genTokenRejectReason $ \tt ->
        Right tt === decodeTokenRejectReason (encodeTokenRejectReason tt)
