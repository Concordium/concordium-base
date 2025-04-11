{-# LANGUAGE DataKinds #-}
{-# LANGUAGE MonoLocalBinds #-}

-- | Tests for serialization of 'ChainParameters' (binary and JSON).
module Types.ParametersSpec (tests) where

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

import qualified Data.Aeson as AE
import qualified Data.Serialize as S

import Concordium.Types.Parameters
import Concordium.Types.ProtocolVersion

import Generators

checkPutGetIsIdentity :: (IsProtocolVersion pv) => SProtocolVersion pv -> ChainParameters pv -> Property
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
                ChainParametersV2 -> forAll (resize size genChainParametersV2) (checkPutGetIsIdentity SP6)
                ChainParametersV3 -> forAll (resize size genChainParametersV3) (checkPutGetIsIdentity SP8)
                ChainParametersV4 -> forAll (resize size genChainParametersV4) (checkPutGetIsIdentity SP9)

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

checkJSONToFromIsIdentityV2 :: ChainParameters' 'ChainParametersV2 -> Property
checkJSONToFromIsIdentityV2 cp = do
    case AE.fromJSON (AE.toJSON cp) of
        AE.Error err -> counterexample err False
        AE.Success jsonCp -> cp === jsonCp

checkJSONToFromIsIdentityV3 :: ChainParameters' 'ChainParametersV3 -> Property
checkJSONToFromIsIdentityV3 cp = do
    case AE.fromJSON (AE.toJSON cp) of
        AE.Error err -> counterexample err False
        AE.Success jsonCp -> cp === jsonCp

checkJSONToFromIsIdentityV4 :: ChainParameters' 'ChainParametersV4 -> Property
checkJSONToFromIsIdentityV4 cp = do
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
                ChainParametersV2 -> forAll (resize size genChainParametersV2) checkJSONToFromIsIdentityV2
                ChainParametersV3 -> forAll (resize size genChainParametersV3) checkJSONToFromIsIdentityV3
                ChainParametersV4 -> forAll (resize size genChainParametersV4) checkJSONToFromIsIdentityV4

tests :: Spec
tests = do
    describe "ChainParameters serialization tests" $ do
        testSerialization ChainParametersV0 25 1000
        testSerialization ChainParametersV0 50 500
        testSerialization ChainParametersV1 25 1000
        testSerialization ChainParametersV1 50 500
        testSerialization ChainParametersV2 25 1000
        testSerialization ChainParametersV2 50 500
        testSerialization ChainParametersV3 25 1000
        testSerialization ChainParametersV3 50 500
        testSerialization ChainParametersV4 25 1000
        testSerialization ChainParametersV4 50 500
    describe "ChainParameters JSON tests" $ do
        testJSON ChainParametersV0 25 1000
        testJSON ChainParametersV0 50 500
        testJSON ChainParametersV1 25 1000
        testJSON ChainParametersV1 50 500
        testJSON ChainParametersV2 25 1000
        testJSON ChainParametersV2 50 500
        testJSON ChainParametersV3 25 1000
        testJSON ChainParametersV3 50 500
        testJSON ChainParametersV4 25 1000
        testJSON ChainParametersV4 50 500
