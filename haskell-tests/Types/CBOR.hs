{-# LANGUAGE OverloadedStrings #-}

module Types.CBOR where

import Codec.CBOR.Read
import qualified Codec.CBOR.Term as CBOR
import Codec.CBOR.Write
import qualified Codec.CBOR.Write as CBOR
import qualified Data.Aeson as AE
import qualified Data.Aeson.KeyMap as AE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as BSS
import qualified Data.Map as Map
import qualified Data.Sequence as Seq
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import qualified Data.Vector as V
import Test.HUnit
import Test.Hspec
import Test.QuickCheck

import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.Types
import Concordium.Types.ProtocolLevelTokens.CBOR
import Concordium.Types.Queries.Tokens
import qualified Data.FixedByteString as FBS
import Generators

genText :: Gen Text.Text
genText = sized $ \s -> Text.decodeUtf8 . BS.pack <$> genUtf8String s

genTokenInitializationParameters :: Gen TokenInitializationParameters
genTokenInitializationParameters = do
    tipName <- genText
    tipMetadata <- genText
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
    ttRecipient <- genTokenHolder
    ttMemo <- oneof [pure Nothing, Just <$> genTaggableMemo]
    return TokenTransferBody{..}

-- | Generator for `TokenHolder`
genTokenHolder :: Gen TokenHolder
genTokenHolder =
    oneof
        [ HolderAccount <$> genAccountAddress <*> pure (Just CoinInfoConcordium),
          HolderAccount <$> genAccountAddress <*> pure Nothing
        ]

-- | Generator for `TaggableMemo`
genTaggableMemo :: Gen TaggableMemo
genTaggableMemo =
    oneof
        [ UntaggedMemo <$> genMemo,
          CBORMemo <$> genMemo
        ]

-- | Generator for 'TokenHolderTransaction'.
genTokenHolderTransaction :: Gen TokenHolderTransaction
genTokenHolderTransaction =
    TokenHolderTransaction . Seq.fromList
        <$> listOf (TokenHolderTransfer <$> genTokenTransfer)

-- | Generator for 'TokenGovernanceOperation'.
genTokenGovernanceOperation :: Gen TokenGovernanceOperation
genTokenGovernanceOperation =
    oneof
        [ TokenMint <$> genTokenAmount,
          TokenBurn <$> genTokenAmount,
          TokenAddAllowList <$> genTokenHolder,
          TokenRemoveAllowList <$> genTokenHolder,
          TokenAddDenyList <$> genTokenHolder,
          TokenRemoveDenyList <$> genTokenHolder
        ]

-- | Generator for 'TokenGovernanceOperation'.
genTokenGovernanceTransaction :: Gen TokenGovernanceTransaction
genTokenGovernanceTransaction =
    TokenGovernanceTransaction . Seq.fromList
        <$> listOf genTokenGovernanceOperation

genTokenModuleStateSimple :: Gen TokenModuleState
genTokenModuleStateSimple = do
    tmsName <- genText
    tmsMetadata <- genText
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

genTokenEvent :: Gen TokenEvent
genTokenEvent =
    oneof
        [ AddAllowListEvent <$> genTokenHolder,
          RemoveAllowListEvent <$> genTokenHolder,
          AddDenyListEvent <$> genTokenHolder,
          RemoveDenyListEvent <$> genTokenHolder
        ]

-- | Generator for 'TokenRejectReason'.
genTokenRejectReason :: Gen TokenRejectReason
genTokenRejectReason =
    oneof
        [ AddressNotFound <$> arbitrary <*> genTokenHolder,
          TokenBalanceInsufficient <$> arbitrary <*> genTokenAmount <*> genTokenAmount,
          DeserializationFailure <$> liftArbitrary genText,
          UnsupportedOperation <$> arbitrary <*> genText <*> liftArbitrary genText,
          MintWouldOverflow <$> arbitrary <*> genTokenAmount <*> genTokenAmount <*> genTokenAmount,
          OperationNotPermitted <$> arbitrary <*> liftArbitrary genTokenHolder <*> liftArbitrary genText
        ]

-- | A test value for 'TokenInitializationParameters'.
tip1 :: TokenInitializationParameters
tip1 =
    TokenInitializationParameters
        { tipName = "ABC token",
          tipMetadata = "https://abc.token/meta",
          tipAllowList = False,
          tipInitialSupply = Just (TokenAmount{taValue = 10000, taDecimals = 5}),
          tipDenyList = False,
          tipMintable = False,
          tipBurnable = False
        }

-- | Basic tests for CBOR encoding/decoding of 'TokenInitializationParameters'.
testInitializationParameters :: Spec
testInitializationParameters = describe "token-initialization-parameters decoding" $ do
    it "Decode success" $
        assertEqual
            "Decoded CBOR"
            (Right ("", tip1))
            ( deserialiseFromBytes
                decodeTokenInitializationParameters
                "\xA4\x64name\x69\
                \ABC token\x68metadata\x76https://abc.token/meta\x69\
                \allowList\xF4\x6DinitialSupply\xC4\x82\x24\x19\x27\x10"
            )
    it "Missing \"name\"" $
        assertEqual
            "Decoded CBOR"
            (Left (DeserialiseFailure 64 "Missing \"name\""))
            ( deserialiseFromBytes
                decodeTokenInitializationParameters
                "\xA3\x68metadata\x76https://abc.token/meta\x69\
                \allowList\xF4\x6DinitialSupply\xC4\x82\x24\x19\x27\x10"
            )
    it "Duplicate \"name\" key" $
        assertEqual
            "Decode result"
            (Left (DeserialiseFailure 90 "Key already set: \"name\""))
            ( deserialiseFromBytes
                decodeTokenInitializationParameters
                "\xA5\x64name\x69\
                \ABC token\x68metadata\x76https://abc.token/meta\x69\
                \allowList\xF4\x6DinitialSupply\xC4\x82\x24\x19\x27\x10\
                \\x64name\x65token"
            )
    it "Encode and decode (no defaults)" $ withMaxSuccess 10000 $ forAll genTokenInitializationParameters $ \tip ->
        (Right ("", tip))
            === ( deserialiseFromBytes
                    decodeTokenInitializationParameters
                    (toLazyByteString $ encodeTokenInitializationParametersNoDefaults tip)
                )
    it "Encode and decode (with defaults)" $ withMaxSuccess 10000 $ forAll genTokenInitializationParameters $ \tip ->
        (Right ("", tip))
            === ( deserialiseFromBytes
                    decodeTokenInitializationParameters
                    (toLazyByteString $ encodeTokenInitializationParametersWithDefaults tip)
                )

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

testEncodedInitializationParameters :: Spec
testEncodedInitializationParameters = describe "TokenInitializationParameters JSON serialization" $ do
    it "Serialize/Deserialize roundtrip success" $
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

-- | A test value for 'TokenHolderTransaction'.
tops1 :: TokenHolderTransaction
tops1 =
    TokenHolderTransaction $
        Seq.fromList
            [ TokenHolderTransfer
                TokenTransferBody
                    { -- Use a token amount that is not modified by "normalization". Normalization may be removed entirely, but for now, work around it like this
                      ttAmount = TokenAmount{taValue = 12345, taDecimals = 5},
                      ttRecipient =
                        HolderAccount
                            { holderAccountAddress = AccountAddress $ FBS.pack [0x1, 0x1],
                              holderAccountCoinInfo = Just CoinInfoConcordium
                            },
                      ttMemo = Just $ UntaggedMemo $ Memo $ BSS.pack [0x1, 0x2, 0x3, 0x4]
                    }
            ]

-- | Encoded 'TokenHolderTransaction' that can be successfully CBOR decoded
encTops1 :: EncodedTokenOperations
encTops1 =
    EncodedTokenOperations $
        TokenParameter $
            BSS.toShort $
                CBOR.toStrictByteString $
                    encodeTokenHolderTransaction tops1

-- | Encoded 'TokenHolderTransaction' that cannot be successfully CBOR decoded
invalidEncTops1 :: EncodedTokenOperations
invalidEncTops1 =
    EncodedTokenOperations $
        TokenParameter $
            BSS.pack [0x1, 0x2, 0x3, 0x4]

testEncodedTokenOperations :: Spec
testEncodedTokenOperations = describe "EncodedTokenOperations JSON serialization" $ do
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
    it "Serialize/Deserialize roundtrip where CBOR is not a valid TokenHolderTransaction" $
        assertEqual
            "Deserialized"
            (Just invalidEncTops1)
            ( AE.decode $
                AE.encode
                    invalidEncTops1
            )

emptyStringHash :: Hash.Hash
emptyStringHash = Hash.Hash (FBS.pack [0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55])

testTokenModuleStateSimpleJSON :: Spec
testTokenModuleStateSimpleJSON = describe "TokenModuleState JSON serialization without additional state" $ do
    let object =
            TokenModuleState
                { tmsMetadata = "https://example.com/token-metadata",
                  tmsName = "bla bla",
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

    it "toJSON/fromJSON roundtrip success" $ do
        let
            val = AE.toJSON object
            result :: AE.Result TokenModuleState
            result = AE.fromJSON val

            parsed :: Maybe TokenModuleState
            parsed = case result of
                AE.Success x -> Just x
                AE.Error _ -> Nothing

        assertEqual
            "JSON roundtrip"
            (Just object)
            parsed

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
    let object =
            TokenModuleState
                { tmsMetadata = "https://example.com/token-metadata",
                  tmsName = "bla bla",
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

    it "toJSON/fromJSON roundtrip success" $ do
        let
            val = AE.toJSON object
            result :: AE.Result TokenModuleState
            result = AE.fromJSON val

            parsed :: Maybe TokenModuleState
            parsed = case result of
                AE.Success x -> Just x
                AE.Error _ -> Nothing

        assertEqual
            "JSON roundtrip"
            (Just object)
            parsed

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
    let tokenModuleState =
            TokenModuleState
                { tmsMetadata = "https://example.com/token-metadata",
                  tmsName = "bla bla",
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
                  tsIssuer = AccountAddress $ FBS.pack [0x1, 0x1],
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

    it "toJSON/fromJSON roundtrip success" $ do
        let
            val = AE.toJSON object
            result :: AE.Result TokenState
            result = AE.fromJSON val

            parsed :: Maybe TokenState
            parsed = case result of
                AE.Success x -> Just x
                AE.Error _ -> Nothing

        assertEqual
            "JSON roundtrip"
            (Just object)
            parsed

    it "Serializes to expected JSON object" $
        case AE.toJSON object of
            AE.Object o -> do
                assertBool "Does not contain field tokenModuleRef" $ AE.member "tokenModuleRef" o
                assertBool "Does not contain field issuer" $ AE.member "issuer" o
                assertBool "Does not contain field totalSupply" $ AE.member "totalSupply" o
                assertBool "Does not contain field decimals" $ AE.member "decimals" o
                assertBool "Does not contain field moduleState" $ AE.member "moduleState" o
            _ -> assertFailure "Does not encode to JSON object"

testTokenStateJSON :: Spec
testTokenStateJSON = describe "TokenState JSON serialization with additional state" $ do
    let tokenModuleState =
            TokenModuleState
                { tmsMetadata = "https://example.com/token-metadata",
                  tmsName = "bla bla",
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
                  tsIssuer = AccountAddress $ FBS.pack [0x1, 0x1],
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

    it "toJSON/fromJSON roundtrip success" $ do
        let
            val = AE.toJSON object
            result :: AE.Result TokenState
            result = AE.fromJSON val

            parsed :: Maybe TokenState
            parsed = case result of
                AE.Success x -> Just x
                AE.Error _ -> Nothing

        assertEqual
            "JSON roundtrip"
            (Just object)
            parsed

    it "Serializes to expected JSON object" $
        case AE.toJSON object of
            AE.Object o -> do
                assertBool "Does not contain field tokenModuleRef" $ AE.member "tokenModuleRef" o
                assertBool "Does not contain field issuer" $ AE.member "issuer" o
                assertBool "Does not contain field totalSupply" $ AE.member "totalSupply" o
                assertBool "Does not contain field decimals" $ AE.member "decimals" o
                assertBool "Does not contain field moduleState" $ AE.member "moduleState" o
            _ -> assertFailure "Does not encode to JSON object"

tests :: Spec
tests = parallel $ describe "CBOR" $ do
    testInitializationParameters
    testEncodedInitializationParameters
    testEncodedTokenOperations
    testTokenModuleStateSimpleJSON
    testTokenModuleStateJSON
    testTokenStateSimpleJSON
    testTokenStateJSON
    it "Encode and decode TokenTransfer" $ withMaxSuccess 1000 $ forAll genTokenTransfer $ \tt ->
        (Right ("", tt))
            === ( deserialiseFromBytes
                    decodeTokenTransfer
                    (toLazyByteString $ encodeTokenTransfer tt)
                )
    it "Encode and decode TokenHolderTransaction" $ withMaxSuccess 1000 $ forAll genTokenHolderTransaction $ \tt ->
        (Right ("", tt))
            === ( deserialiseFromBytes
                    decodeTokenHolderTransaction
                    (toLazyByteString $ encodeTokenHolderTransaction tt)
                )
    it "Encode and decode TokenGovernanceOperation" $ withMaxSuccess 1000 $ forAll genTokenGovernanceOperation $ \tt ->
        (Right ("", tt))
            === ( deserialiseFromBytes
                    decodeTokenGovernanceOperation
                    (toLazyByteString $ encodeTokenGovernanceOperation tt)
                )
    it "Encode and decode TokenGovernanceTransaction" $ withMaxSuccess 1000 $ forAll genTokenGovernanceTransaction $ \tt ->
        (Right ("", tt))
            === ( deserialiseFromBytes
                    decodeTokenGovernanceTransaction
                    (toLazyByteString $ encodeTokenGovernanceTransaction tt)
                )
    it "Encode and decode TokenModuleState (simple)" $ withMaxSuccess 1000 $ forAll genTokenModuleStateSimple $ \tt ->
        (Right ("", tt))
            === ( deserialiseFromBytes
                    decodeTokenModuleState
                    (toLazyByteString $ encodeTokenModuleState tt)
                )
    it "Encode and decode TokenModuleState (with additional)" $ withMaxSuccess 1000 $ forAll genTokenModuleStateWithAdditional $ \tt ->
        (Right ("", tt))
            === ( deserialiseFromBytes
                    decodeTokenModuleState
                    (toLazyByteString $ encodeTokenModuleState tt)
                )
    it "Encode and decode TokenEvent" $ withMaxSuccess 1000 $ forAll genTokenEvent $ \tt ->
        Right tt === decodeTokenEvent (encodeTokenEvent tt)
    it "Encode and decode TokenRejectReason" $ withMaxSuccess 1000 $ forAll genTokenRejectReason $ \tt ->
        Right tt === decodeTokenRejectReason (encodeTokenRejectReason tt)
