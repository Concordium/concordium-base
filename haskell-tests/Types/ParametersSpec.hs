{-# LANGUAGE DataKinds #-}

-- |Tests for serialization of 'ChainParameters' (binary and JSON).
module Types.ParametersSpec (tests) where

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

import qualified Data.Aeson as AE
import qualified Data.Serialize as S

import Concordium.Types.Parameters
import Concordium.Types.ProtocolVersion

import Generators

checkPutGetIsIdentity :: IsProtocolVersion pv => SProtocolVersion pv -> ChainParameters pv -> Property
checkPutGetIsIdentity _ cp = do
    let putBs = S.runPut $ putChainParameters cp
    case S.runGet getChainParameters putBs of
        Left err -> counterexample err False
        Right getCp -> cp === getCp

testSerialization :: ChainParametersVersion -> Int -> Int -> Spec
testSerialization cpv size num =
    modifyMaxSuccess (const num) $
        specify ("ChainParameters serialization (" ++ show cpv ++ ") of size = " ++ show size ++ ":") $
            case cpv of
                ChainParametersV0 -> forAll (resize size genChainParametersV0) (checkPutGetIsIdentity SP1)
                ChainParametersV1 -> forAll (resize size genChainParametersV1) (checkPutGetIsIdentity SP4)

checkJSONToFromIsIdentityV0 :: ChainParameters' 'ChainParametersV0 -> Property
checkJSONToFromIsIdentityV0 cp = do
    case AE.fromJSON (AE.toJSON cp) of
        AE.Error err -> counterexample err False
        AE.Success jsonCp -> cp === jsonCp

checkJSONToFromIsIdentityV1 :: ChainParameters' 'ChainParametersV1 -> Property
checkJSONToFromIsIdentityV1 cp = do
    case AE.fromJSON (AE.toJSON cp) of
        AE.Error err -> counterexample err False
        AE.Success jsonCp -> cp === jsonCp

testJSON :: ChainParametersVersion -> Int -> Int -> Spec
testJSON cpv size num =
    modifyMaxSuccess (const num) $
        specify ("ChainParameters JSON (" ++ show cpv ++ ") of size = " ++ show size ++ ":") $
            case cpv of
                ChainParametersV0 -> forAll (resize size genChainParametersV0) checkJSONToFromIsIdentityV0
                ChainParametersV1 -> forAll (resize size genChainParametersV1) checkJSONToFromIsIdentityV1

tests :: Spec
tests = do
    describe "ChainParameters serialization tests" $ do
        testSerialization ChainParametersV0 25 1000
        testSerialization ChainParametersV0 50 500
        testSerialization ChainParametersV1 25 1000
        testSerialization ChainParametersV1 50 500
    describe "ChainParameters JSON tests" $ do
        testJSON ChainParametersV0 25 1000
        testJSON ChainParametersV0 50 500
        testJSON ChainParametersV1 25 1000
        testJSON ChainParametersV1 50 500
