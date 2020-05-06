{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE GeneralizedNewtypeDeriving, RecordWildCards, OverloadedStrings, LambdaCase #-}
{-# LANGUAGE TypeFamilies, ExistentialQuantification, FlexibleContexts, DeriveGeneric, DerivingVia, DeriveDataTypeable #-}
module ConcordiumTests.Common.Version where

import Concordium.Common.Version
import qualified Data.FixedByteString as FBS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy.Char8 as BSL8
import qualified Data.ByteString as BS
import qualified Data.Serialize as S

import Data.Word
import Test.QuickCheck
import Test.Hspec
import Test.HUnit
import Data.Aeson

newtype ExampleType = ExampleType Word32
    deriving (Eq, Show, Ord)
    deriving (FromJSON, ToJSON) via Word32

testVersionToBytes :: Property
testVersionToBytes = S.encode (Version 1700794014) === (BS.pack [0x86, 0xab, 0x80, 0x9d, 0x1e])

testVersionToJSON :: Property
testVersionToJSON = json === "{\"value\":2,\"v\":4}"
  where
    json = BSL8.unpack $ encode versioned
    versioned = Versioned version value
    version = Version 4
    value = ExampleType $ fromIntegral 2

tests :: Spec
tests = describe "Concordium.Common" $ do
  specify "versioning to bytes" $ testVersionToBytes
  specify "versioning to json" $ testVersionToJSON
