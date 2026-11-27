{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

-- | Tests for genesis parameter JSON and complete genesis serialization.
module Genesis.ParametersSpec (tests) where

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

import qualified Data.Aeson as AE
import qualified Data.Aeson.KeyMap as KM
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as BS16
import qualified Data.FixedByteString as FBS
import qualified Data.Serialize as S

import qualified Concordium.Crypto.SHA256 as Hash
import qualified Concordium.Genesis.Data.P10 as P10
import qualified Concordium.Genesis.Data.P11 as P11
import qualified Concordium.Genesis.Data.P8 as P8
import qualified Concordium.Genesis.Data.P9 as P9
import Concordium.Genesis.Parameters
import Concordium.Types
import Concordium.Types.Parameters

import Examples.ChainParameters (p11ChainParametersExample)
import Examples.Genesis
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

checkJSONToFromIsIdentityV2 :: GenesisChainParameters' 'ChainParametersV2 -> Property
checkJSONToFromIsIdentityV2 cp = do
    case AE.fromJSON (AE.toJSON cp) of
        AE.Error err -> counterexample err False
        AE.Success jsonCp -> cp === jsonCp

checkJSONToFromIsIdentityV3 :: GenesisChainParameters' 'ChainParametersV3 -> Property
checkJSONToFromIsIdentityV3 cp = do
    case AE.fromJSON (AE.toJSON cp) of
        AE.Error err -> counterexample err False
        AE.Success jsonCp -> cp === jsonCp

checkJSONToFromIsIdentityV4 :: GenesisChainParameters' 'ChainParametersV4 -> Property
checkJSONToFromIsIdentityV4 cp =
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
                ChainParametersV2 ->
                    forAll (resize size genGenesisChainParametersV2) checkJSONToFromIsIdentityV2
                ChainParametersV3 ->
                    forAll (resize size genGenesisChainParametersV3) checkJSONToFromIsIdentityV3
                ChainParametersV4 ->
                    forAll (resize size genGenesisChainParametersV4) checkJSONToFromIsIdentityV4

-- | Check the complete encoding and all decoded fields against a deterministic example.
testGenesis :: (Eq genesis, Show genesis) => String -> FilePath -> Either String genesis -> S.Putter genesis -> S.Get genesis -> BS.ByteString -> Spec
testGenesis version fixturePath genesisExample putGenesis getGenesis expectedHash =
    describe ("Complete " ++ version ++ " genesis serialization") $ do
        it "preserves the fixed encoding hash" $
            case genesisExample of
                Left err -> expectationFailure err
                Right genesis ->
                    BS16.encode (Hash.hashToByteString (Hash.hash (S.runPut (putGenesis genesis))))
                        `shouldBe` expectedHash
        it "encodes the example as the fixed fixture" $ do
            bytes <- BS.readFile fixturePath
            case genesisExample of
                Left err -> expectationFailure err
                Right genesis -> S.runPut (putGenesis genesis) `shouldBe` bytes
        it "decodes every field without consuming a following sentinel" $ do
            bytes <- BS.readFile fixturePath
            case genesisExample of
                Left err -> expectationFailure err
                Right genesis -> do
                    let sentinel = 0x0102030405060708
                        input = bytes <> S.runPut (S.putWord64be sentinel)
                    S.runGet ((,,) <$> getGenesis <*> S.getWord64be <*> S.remaining) input
                        `shouldBe` Right (genesis, sentinel, 0)

tests :: Spec
tests = do
    testGenesis
        "p8"
        "testdata/p8-genesis.dat"
        p8GenesisExample
        P8.putVersionedGenesisData
        P8.getVersionedGenesisData
        "f3dceef838ebd0feaf4301953ce5522d5250836e1bf3a764c72f0e431e2d9748"
    testGenesis
        "p9"
        "testdata/p9-genesis.dat"
        p9GenesisExample
        P9.putVersionedGenesisData
        P9.getVersionedGenesisData
        "a1bd7e062efbb649d01c4ccb10db9b2eba2d8962a51262b3107bb03a6f6f236e"
    testGenesis
        "p10"
        "testdata/p10-genesis.dat"
        p10GenesisExample
        P10.putVersionedGenesisData
        P10.getVersionedGenesisData
        "c959a11e841e911fa4927b7c17d36779afb96037c5ac70798d17d0a63ff51c6c"
    testGenesis
        "p11"
        "testdata/p11-genesis.dat"
        p11GenesisExample
        P11.putVersionedGenesisData
        P11.getVersionedGenesisData
        "1ecc00bf95210bbdea549889377b3fecccc5f057831fc7403d2b710025bfb272"
    describe "GenesisChainParameters JSON tests" $ do
        testJSON ChainParametersV0 25 1000
        testJSON ChainParametersV0 50 500
        testJSON ChainParametersV1 25 1000
        testJSON ChainParametersV1 50 500
        testJSON ChainParametersV2 25 1000
        testJSON ChainParametersV2 50 500
        testJSON ChainParametersV3 50 500
        testJSON ChainParametersV4 50 500
    describe "P11 genesis JSON requirements" $ do
        let parameters :: GenesisChainParameters 'P11
            parameters =
                GenesisChainParameters
                    { gcpConsensusParameters = _cpConsensusParameters p11ChainParametersExample,
                      gcpExchangeRates = _cpExchangeRates p11ChainParametersExample,
                      gcpCooldownParameters = _cpCooldownParameters p11ChainParametersExample,
                      gcpTimeParameters = _cpTimeParameters p11ChainParametersExample,
                      gcpAccountCreationLimit = _cpAccountCreationLimit p11ChainParametersExample,
                      gcpRewardParameters = _cpRewardParameters p11ChainParametersExample,
                      gcpFoundationAccount = AccountAddress (FBS.fromByteString (BS.replicate 32 0)),
                      gcpPoolParameters = _cpPoolParameters p11ChainParametersExample,
                      gcpFinalizationCommitteeParameters = _cpFinalizationCommitteeParameters p11ChainParametersExample,
                      gcpValidatorScoreParameters = _cpValidatorScoreParameters p11ChainParametersExample,
                      gcpMaxLockDuration = _cpMaxLockDuration p11ChainParametersExample
                    }
        it "rejects a missing max-lock duration" $
            case AE.toJSON parameters of
                AE.Object fields -> do
                    AE.fromJSON (AE.Object fields) `shouldBe` AE.Success parameters
                    case AE.fromJSON (AE.Object (KM.delete "maxLockDuration" fields)) :: AE.Result (GenesisChainParameters 'P11) of
                        AE.Error _ -> return ()
                        AE.Success _ -> expectationFailure "Accepted P11 genesis parameters without duration"
                _ -> expectationFailure "Expected a genesis parameter object"
        it "rejects a null max-lock duration" $
            case AE.toJSON parameters of
                AE.Object fields -> do
                    AE.fromJSON (AE.Object fields) `shouldBe` AE.Success parameters
                    case AE.fromJSON (AE.Object (KM.insert "maxLockDuration" AE.Null fields)) :: AE.Result (GenesisChainParameters 'P11) of
                        AE.Error _ -> return ()
                        AE.Success _ -> expectationFailure "Accepted P11 genesis parameters with null duration"
                _ -> expectationFailure "Expected a genesis parameter object"
