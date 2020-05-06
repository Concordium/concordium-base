{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE LambdaCase #-}
module ConcordiumTests.Common.Version where

import Concordium.Common.Version
import qualified Data.FixedByteString as FBS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString as BS
import qualified Data.Serialize as S

import Test.QuickCheck
import Test.Hspec
import Test.HUnit
import Data.Aeson

testVersionBytes :: Property
testVersionBytes = S.encode (Version 1700794014) === (BS.pack [0x86, 0xab, 0x80, 0x9d, 0x1e])

testVersionJSON :: Property
testVersionJSON = 1 === 1

tests :: Spec
tests = describe "Concordium.Common" $ do
  specify "versioning to and from bytes" $ withMaxSuccess 1000 testVersionBytes
  specify "versioning to and from json" $ withMaxSuccess 1000 testVersionJSON
