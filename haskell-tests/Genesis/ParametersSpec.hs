{-# LANGUAGE DataKinds #-}

-- |Test JSON serialization of 'GenesisChainParameters'.
module Genesis.ParametersSpec (tests) where

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

import qualified Data.Aeson as AE

import Concordium.Genesis.Parameters
import Concordium.Types.ProtocolVersion

import Generators

checkJSONToFromIsIdentityV0 :: GenesisChainParameters' 'ChainParametersV0 -> Property
checkJSONToFromIsIdentityV0 cp = do
    case AE.fromJSON (AE.toJSON cp) of
        AE.Error err -> counterexample err False
        AE.Success jsonCp -> cp === jsonCp

checkJSONToFromIsIdentityV1 :: GenesisChainParameters' 'ChainParametersV1 -> Property
checkJSONToFromIsIdentityV1 cp = do
    case AE.fromJSON (AE.toJSON cp) of
        AE.Error err -> counterexample err False
        AE.Success jsonCp -> cp === jsonCp

testJSON :: ChainParametersVersion -> Int -> Int -> Spec
testJSON cpv size num =
    modifyMaxSuccess (const num) $
        specify ("GenesisChainParameters JSON (" ++ show cpv ++ ") of size = " ++ show size ++ ":") $
            case cpv of
                ChainParametersV0 ->
                    forAll (resize size genGenesisChainParametersV0) checkJSONToFromIsIdentityV0
                ChainParametersV1 ->
                    forAll (resize size genGenesisChainParametersV1) checkJSONToFromIsIdentityV1

tests :: Spec
tests = do
    describe "GenesisChainParameters JSON tests" $ do
        testJSON ChainParametersV0 25 1000
        testJSON ChainParametersV0 50 500
        testJSON ChainParametersV1 25 1000
        testJSON ChainParametersV1 50 500
