{-# LANGUAGE OverloadedStrings #-}

module Types.CBOR where

import Codec.CBOR.Read
import Codec.CBOR.Write
import qualified Data.ByteString.Base16.Lazy as B16L
import qualified Data.ByteString.Lazy.Char8 as LBS

import Test.HUnit
import Test.Hspec

import Concordium.Types.ProtocolLevelTokens.CBOR
import Concordium.Types.Queries.Tokens

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
    it "example 1" $
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
    it "Encode and decode (no defaults)" $ do
        -- LBS.putStrLn $ B16L.encode $ toLazyByteString $ encodeTokenInitializationParametersNoDefaults tip1
        assertEqual
            "Decode result"
            (Right ("", tip1))
            ( deserialiseFromBytes
                decodeTokenInitializationParameters
                (toLazyByteString $ encodeTokenInitializationParametersNoDefaults tip1)
            )
    it "Encode and decode (with defaults)" $ do
        LBS.putStrLn $ B16L.encode $ toLazyByteString $ encodeTokenInitializationParametersWithDefaults tip1
        assertEqual
            "Decode result"
            (Right ("", tip1))
            ( deserialiseFromBytes
                decodeTokenInitializationParameters
                (toLazyByteString $ encodeTokenInitializationParametersWithDefaults tip1)
            )

tests :: Spec
tests = describe "CBOR" $ do
    testInitializationParameters
