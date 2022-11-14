{-# LANGUAGE ScopedTypeVariables #-}

module ConcordiumTests.ID.Types where

import Concordium.Common.Version
import Concordium.ID.Types
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.Serialize as S

import Data.Aeson
import Test.HUnit
import Test.Hspec
import Test.QuickCheck

import Generators

testJSON :: Property
testJSON = forAll genAccountAddress ck
  where
    ck :: AccountAddress -> Property
    ck b58 = case decode (encode b58) of
        Nothing -> counterexample (show b58) False
        Just x -> x === b58

testFromBytes :: Property
testFromBytes = forAll genAccountAddress ck
  where
    ck :: AccountAddress -> Property
    ck addr = case addressFromBytes (BS8.pack (show addr)) of
        Left _ -> counterexample ("Problem = " ++ show addr) False
        Right x -> x === addr

-- Check that serializations in Haskell and rust, json and binary are compatible.
checkCDICompatibility :: FilePath -> FilePath -> Expectation
checkCDICompatibility filename referenceFile = do
    eitherDecodeFileStrict filename >>= \case
        Left err -> assertFailure err
        Right (input :: Versioned CredentialDeploymentInformation) -> do
            referenceOutput <- BS.readFile referenceFile
            -- we do unpack for better error reporting, easier to compare lists of word8s
            assertEqual "Incompatible binary serializations." (BS.unpack referenceOutput) (BS.unpack (S.encode input))

-- Check that proofCommitments actually extracts the commitments. It checks this by reading a `CredentialDeploymentInformation`
-- from json, extracting the commitments, serializing them and comparing them with the provided binary (the `referenceFile`).
checkCDICommitmentsCompatibility :: FilePath -> FilePath -> Expectation
checkCDICommitmentsCompatibility filename referenceFile = do
    eitherDecodeFileStrict filename >>= \case
        Left err -> assertFailure err
        Right (input :: Versioned CredentialDeploymentInformation) -> do
            referenceOutput <- BS.readFile referenceFile
            -- we do unpack for better error reporting, easier to compare lists of word8s
            case proofCommitments $ cdiProofs $ vValue input of
                Nothing -> assertFailure "Could not parse commitments from the credential."
                Just cmms -> assertEqual "Incompatible binary serializations." (BS.unpack referenceOutput) $ BS.unpack $ S.encode $ cmms

-- Check that serializations in Haskell and rust, json and binary are compatible.
checkInitialCDICompatibility :: FilePath -> FilePath -> Expectation
checkInitialCDICompatibility filename referenceFile = do
    eitherDecodeFileStrict filename >>= \case
        Left err -> assertFailure err
        Right (input :: Versioned InitialCredentialDeploymentInfo) -> do
            referenceOutput <- BS.readFile referenceFile
            -- we do unpack for better error reporting, easier to compare lists of word8s
            assertEqual "Incompatible binary serializations." (BS.unpack referenceOutput) (BS.unpack (S.encode input))

tests :: Spec
tests = describe "Concordium.ID" $ do
    specify "account address JSON" $ withMaxSuccess 100000 testJSON
    specify "account address from bytes" $ withMaxSuccess 100000 testFromBytes
    specify "JSON/binary CDI serialization check" $ checkCDICompatibility "testdata/cdi.json" "testdata/cdi.bin"
    specify "JSON/binary CDI Commitments check" $ checkCDICommitmentsCompatibility "testdata/cdi.json" "testdata/cdi-coms.bin"
    specify "JSON/binary Initial CDI serialization check" $ checkInitialCDICompatibility "testdata/icdi.json" "testdata/icdi.bin"
