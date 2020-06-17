{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE GeneralizedNewtypeDeriving, RecordWildCards, OverloadedStrings, LambdaCase #-}
{-# LANGUAGE TypeFamilies, ExistentialQuantification, FlexibleContexts, DeriveGeneric, DerivingVia, DeriveDataTypeable #-}
module ConcordiumTests.Common.Version where

import Concordium.Common.Version
import qualified Data.ByteString.Lazy.Char8 as BSL8
import qualified Data.ByteString as BS
import qualified Data.Serialize as S

import Data.Word
import Test.QuickCheck
import Test.Hspec
import Data.Aeson

newtype ExampleType = ExampleType Word32
    deriving (Eq, Show, Ord, FromJSON, ToJSON)

testVersionToBytes :: Property
testVersionToBytes = S.encode (Version 1700794014) === (BS.pack [0x86, 0xab, 0x80, 0x9d, 0x1e])

testVersionToJSON :: Property
testVersionToJSON = jsonValue === "{\"value\":2,\"v\":4}"
  where
    jsonValue = BSL8.unpack $ encode versioned
    versioned = Versioned version value
    version = Version 4
    value = ExampleType $ fromIntegral 2

testVersionFromJSON :: Property
testVersionFromJSON = objectValue === Just realversioned
  where
    objectValue = decode "{\"value\":2,\"v\":4}"
    realversioned = Versioned version value
    version = Version 4
    value = ExampleType $ fromIntegral 2

tests :: Spec
tests = describe "Concordium.Common" $ do
  specify "versioning to bytes" $ testVersionToBytes
  specify "versioning to json" $ testVersionToJSON
  specify "versioning from json" $ testVersionFromJSON
