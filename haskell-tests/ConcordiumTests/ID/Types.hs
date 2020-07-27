{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE LambdaCase #-}
module ConcordiumTests.ID.Types where

import Concordium.Common.Version
import Concordium.ID.Types
import qualified Data.FixedByteString as FBS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString as BS
import qualified Data.Serialize as S

import Test.QuickCheck
import Test.Hspec
import Test.HUnit
import Data.Aeson

testJSON :: Property
testJSON = forAll genAddress ck
  where ck :: AccountAddress -> Property
        ck b58 = case decode (encode b58) of
                   Nothing -> counterexample (show b58) False
                   Just x -> x === b58

testFromBytes :: Property
testFromBytes = forAll genAddress ck
  where ck :: AccountAddress -> Property
        ck addr = case addressFromBytes (BS8.pack (show addr)) of
                   Left _ -> counterexample ("Problem = " ++ show addr) False
                   Right x -> x === addr

genAddress :: Gen AccountAddress
genAddress = do
  AccountAddress . FBS.pack <$> vector accountAddressSize

-- Check that serializations in Haskell and rust, json and binary are compatible.
checkCDICompatibility :: FilePath -> FilePath -> Expectation
checkCDICompatibility filename referenceFile = do
  eitherDecodeFileStrict filename >>= \case
    Left err -> assertFailure err
    Right (input :: Versioned CredentialDeploymentInformation) -> do
      referenceOutput <- BS.readFile referenceFile
      -- we do unpack for better error reporting, easier to compare lists of word8s
      assertEqual "Incompatible binary serializations." (BS.unpack referenceOutput) (BS.unpack (S.encode input))

tests :: Spec
tests = describe "Concordium.ID" $ do
  specify "account address JSON" $ withMaxSuccess 100000 testJSON
  specify "account address from bytes" $ withMaxSuccess 100000 testFromBytes
  specify "JSON/binary serialization check" $ checkCDICompatibility "testdata/cdi.json" "testdata/cdi.bin"
