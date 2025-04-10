{-# LANGUAGE OverloadedStrings #-}

module Types.CBOR where

import Codec.CBOR.Read

-- import qualified Data.ByteString as BS
import Test.HUnit
import Test.Hspec

import Concordium.Types.ProtocolLevelTokens.CBOR
import Concordium.Types.Queries.Tokens

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

testInitializationParameters :: Spec
testInitializationParameters = describe "token-initialization-parameters decoding" $ do
    it "example 1 " $
        assertEqual
            "Decoded CBOR"
            (Right ("", tip1))
            ( deserialiseFromBytes
                decodeTokenInitializationParameters
                "\xA4\x64name\x69\
                \ABC token\x68metadata\x76https://abc.token/meta\x69\
                \allowList\xF4\x6DinitialSupply\xC4\x82\x24\x19\x27\x10"
            )

tests = focus $ testInitializationParameters
