{-# LANGUAGE OverloadedStrings #-}

module Types.CBOR where

import Codec.CBOR.Read
import qualified Codec.CBOR.Term as CBOR
import Codec.CBOR.Write
import qualified Data.ByteString as BS
import qualified Data.Map as Map
import qualified Data.Sequence as Seq
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import Test.HUnit
import Test.Hspec
import Test.QuickCheck

import Concordium.Types.ProtocolLevelTokens.CBOR
import Concordium.Types.Queries.Tokens

import Generators

genText :: Gen Text.Text
genText = sized $ \s -> Text.decodeUtf8 . BS.pack <$> genUtf8String s

genTokenAmount :: Gen TokenAmount
genTokenAmount = TokenAmount <$> arbitrary <*> chooseBoundedIntegral (0, 255)

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
    ttRecipient <- genTokenReceiver
    ttMemo <- oneof [pure Nothing, Just <$> genTaggableMemo]
    return TokenTransferBody{..}

-- | Generator for `TokenReceiver`
genTokenReceiver :: Gen TokenReceiver
genTokenReceiver =
    oneof
        [ ReceiverAccount <$> genAccountAddress <*> pure (Just CoinInfoConcordium),
          ReceiverAccount <$> genAccountAddress <*> pure Nothing
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
          TokenAddAllowList <$> genTokenReceiver,
          TokenRemoveAllowList <$> genTokenReceiver,
          TokenAddDenyList <$> genTokenReceiver,
          TokenRemoveDenyList <$> genTokenReceiver
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

-- | A test value for 'TokenInitializationParameters'.
tip1 :: TokenInitializationParameters
tip1 =
    TokenInitializationParameters
        { tipName = "ABC token",
          tipMetadata = "https://abc.token/meta",
          tipAllowList = False,
          tipInitialSupply = Just (TokenAmount{digits = 10000, nrDecimals = 5}),
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

tests :: Spec
tests = parallel $ describe "CBOR" $ do
    testInitializationParameters
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
