{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE GeneralizedNewtypeDeriving, RecordWildCards, OverloadedStrings, LambdaCase #-}
{-# LANGUAGE TypeFamilies, ExistentialQuantification, FlexibleContexts, DeriveGeneric, DerivingVia, DeriveDataTypeable #-}
module ConcordiumTests.Common.Version where

import Concordium.Common.Version
import qualified Data.ByteString.Lazy.Char8 as BSL8
import qualified Data.ByteString as BS
import qualified Data.Serialize as S

import System.Random
import Data.Word
import Test.QuickCheck
import Test.Hspec
import Data.Aeson

newtype ExampleType = ExampleType Word32
    deriving (Eq, Show, Ord, FromJSON, ToJSON)

testVersionTestVector :: Property
testVersionTestVector = S.encode (Version 1700794014) === (BS.pack [0x86, 0xab, 0x80, 0x9d, 0x1e])

testVersionToJSON :: Property
testVersionToJSON = jsonValue === "{\"value\":2,\"v\":4}"
  where
    jsonValue = BSL8.unpack $ encode versioned
    versioned = Versioned version value
    version = Version 4
    value = ExampleType $ fromIntegral (2 :: Integer)

testVersionFromJSON :: Property
testVersionFromJSON = objectValue === Just realversioned
  where
    objectValue = decode "{\"value\":2,\"v\":4}"
    realversioned = Versioned version value
    version = Version 4
    value = ExampleType $ fromIntegral (2 :: Integer)

testEncodeDecode :: Int -> Property
testEncodeDecode v = (S.decode bytes) === (Right version)
  where
    version = Version (fromIntegral (v `mod` 4294967296))
    bytes = S.encode version

testRandom :: Int -> Property
testRandom seed = (S.decode bytes) === (Right (version))
  where
    gen = mkStdGen seed
    v = fst $ randomR (0 :: Integer, 4294967295) gen
    version = Version (fromIntegral v)
    bytes = S.encode version

tests :: Spec
tests = describe "Concordium.Common" $ do
  specify "versioning to bytes" $ testVersionTestVector
  specify "versioning to json" $ testVersionToJSON
  specify "versioning from json" $ testVersionFromJSON
  it "versioning encode decode" $ withMaxSuccess 1000 $ testEncodeDecode
  it "versioning random" $ withMaxSuccess 1000 $ testRandom
