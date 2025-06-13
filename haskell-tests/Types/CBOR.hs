{-# LANGUAGE OverloadedStrings #-}

module Types.CBOR where

import Codec.CBOR.Read
import qualified Codec.CBOR.Term as CBOR
import Codec.CBOR.Write
import qualified Codec.CBOR.Write as CBOR
import qualified Concordium.Crypto.SHA256 as SHA256
import Concordium.Types
import Concordium.Types.ProtocolLevelTokens.CBOR
import Concordium.Types.Queries.Tokens
import qualified Data.Aeson as AE
import qualified Data.Aeson.KeyMap as AE
import qualified Data.ByteString as BS
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
    tmsMetadata <- genTokenMetadataUrlSimple
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
          tipMetadata =
            TokenMetadataUrl
                { tmUrl = "https://abc.token/meta",
                  -- tmChecksumSha256 = Just (SHA256.Hash (FBS.fromByteString "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")),
                  tmChecksumSha256 = Nothing,
                  tmAdditional = Map.empty
                },
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
                \ABC token\x68metadata\xA1\x63url\x76https://abc.token/meta\x69\
                \allowList\xF4\x6DinitialSupply\xC4\x82\x24\x19\x27\x10"
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
    testInitializationParameters
    testEncodedInitializationParameters
    testEncodedTokenOperations
    testTokenMetadataUrlJSON
    testTokenMetadataUrlCBOR
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
