{-# LANGUAGE DataKinds #-}
{-# LANGUAGE MonoLocalBinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

-- | Tests for serialization of 'ChainParameters' (binary and JSON).
module Types.ParametersSpec (tests) where

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

import qualified Data.Aeson as AE
import qualified Data.Aeson.KeyMap as KM
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as BS16
import qualified Data.Serialize as S
import Lens.Micro.Platform ((^.))
import qualified Proto.V2.Concordium.Types as Proto
import qualified Proto.V2.Concordium.Types_Fields as ProtoFields

import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.GRPC2 (toProto)

import Concordium.Types
import Concordium.Types.HashableTo (getHash)
import Concordium.Types.Parameters
import Concordium.Types.Queries (EChainParametersAndKeys (..))
import qualified Concordium.Types.Updates as Updates

import Examples.ChainParameters
import Generators

-- | Fixed historical encoding of 'p8ChainParametersExample', in hexadecimal.
p8ChainParametersBytesHex :: BS.ByteString
p8ChainParametersBytesHex = "0000000000002710000000000000000200000000000000010000000000000004000000000000000500000000000003e800000000000f42400000000000000001000000000000271000000000000f424000000000000000010000000000000e100000000000001c2000000000000000020000000108000a0000ea60000075300000afc80000afc8000061a8000000c800000032000000000000000000002710000013880000138800000000000186a000000000000186a000000000000186a000000045d964b800000027100000000000000005000000000000000100000032000001f4000027100000000000000001"

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
                ChainParametersV4 -> forAll (resize size genChainParametersV4) (checkPutGetIsIdentity SP11)

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
checkJSONToFromIsIdentityV4 cp =
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

-- | Check the common protobuf fields against the fixed internal example.
checkV3Fields :: AccountAddress -> Proto.ChainParametersV3 -> Property
checkV3Fields address response =
    let parameters = p8ChainParametersExample
        rewards = _cpRewardParameters parameters
        rates = _cpExchangeRates parameters
    in  conjoin
            [ response ^. ProtoFields.consensusParameters === toProto (_cpConsensusParameters parameters),
              response ^. ProtoFields.euroPerEnergy === toProto (_erEuroPerEnergy rates),
              response ^. ProtoFields.microCcdPerEuro === toProto (_erMicroGTUPerEuro rates),
              response ^. ProtoFields.cooldownParameters === toProto (_cpCooldownParameters parameters),
              response ^. ProtoFields.timeParameters === toProto (unOParam (_cpTimeParameters parameters)),
              response ^. ProtoFields.accountCreationLimit === toProto (_cpAccountCreationLimit parameters),
              response ^. ProtoFields.mintDistribution === toProto (_rpMintDistribution rewards),
              response ^. ProtoFields.transactionFeeDistribution === toProto (_rpTransactionFeeDistribution rewards),
              response ^. ProtoFields.gasRewards === toProto (_rpGASRewards rewards),
              response ^. ProtoFields.foundationAccount === toProto address,
              response ^. ProtoFields.poolParameters === toProto (_cpPoolParameters parameters),
              response ^. ProtoFields.finalizationCommitteeParameters === toProto (unOParam (_cpFinalizationCommitteeParameters parameters)),
              response ^. ProtoFields.validatorScoreParameters === toProto (unOParam (_cpValidatorScoreParameters parameters))
            ]

tests :: Spec
tests = do
    describe "ChainParameters serialization tests" $ do
        testSerialization ChainParametersV0 25 1000
        testSerialization ChainParametersV0 50 500
        testSerialization ChainParametersV1 25 1000
        testSerialization ChainParametersV1 50 500
        testSerialization ChainParametersV2 25 1000
        testSerialization ChainParametersV2 50 500
        testSerialization ChainParametersV3 50 500
        testSerialization ChainParametersV4 50 500
    describe "Historical P8 chain-parameter compatibility" $ do
        it "preserves the historical parameter bytes" $
            BS16.encode (S.encode p8ChainParametersExample)
                `shouldBe` p8ChainParametersBytesHex
        it "preserves the historical parameter hash" $
            BS16.encode (Hash.hashToByteString (getHash p8ChainParametersExample))
                `shouldBe` "92b23c9c7315d7d6681d161d459ddabc53cf7b7090287f3db01002dbdc0d06de"
    describe "P11 chain-parameter serialization" $ do
        it "appends the duration without a presence tag" $
            BS16.encode (S.encode p11ChainParametersExample)
                `shouldBe` p8ChainParametersBytesHex <> "000000000000002a"
        it "preserves the parameter hash including duration" $
            BS16.encode (Hash.hashToByteString (getHash p11ChainParametersExample))
                `shouldBe` "4f94f036d12c2614cca4c27146ce0dbc8c4e89fba66ed002db1c887fcda58c55"
        it "changes the parameter hash when duration changes" $
            let updated = p11ChainParametersExample{_cpMaxLockDuration = SomeParam (Duration 43)}
            in  (getHash updated :: Hash.Hash) `shouldNotBe` getHash p11ChainParametersExample
    describe "Shared external-v3 view" $ do
        prop "preserves every CPV3 field" $
            forAll genChainParametersV3 $ \parameters ->
                chainParametersV3FromView (chainParametersV3ToView parameters) === Right parameters
        prop "preserves every CPV4 field" $
            forAll genChainParametersV4 $ \parameters ->
                chainParametersV4FromView (chainParametersV4ToView parameters) === Right parameters
        it "rejects duration when CPV3 is selected explicitly" $
            chainParametersV3FromView (chainParametersV4ToView p11ChainParametersExample)
                `shouldBe` Left "CPV3 does not support maxLockDuration"
        it "requires duration when CPV4 is selected explicitly" $
            chainParametersV4FromView (chainParametersV3ToView p8ChainParametersExample)
                `shouldBe` Left "CPV4 requires maxLockDuration"
    describe "P11 chain-parameter API compatibility" $ do
        prop "reports JSON version 3 with max-lock duration" $
            forAll (genKeyCollection @'AuthorizationsVersion3 1) $ \(keys, _, _, _) ->
                let response = AE.toJSON (EChainParametersAndKeys p11ChainParametersExample keys)
                in  case response of
                        AE.Object fields ->
                            conjoin
                                [ KM.lookup "version" fields === Just (AE.toJSON (3 :: Int)),
                                  KM.lookup "parameters" fields === Just (AE.toJSON p11ChainParametersExample)
                                ]
                        _ -> counterexample "Expected a parameter response object" False
        prop "populates the existing gRPC v3 duration field" $
            forAll genAccountAddress $ \address ->
                forAll (genKeyCollection @'AuthorizationsVersion3 1) $ \(keys, _, _, _) ->
                    let response = toProto (address, EChainParametersAndKeys p11ChainParametersExample keys)
                        parameters = response ^. ProtoFields.v3
                    in  conjoin
                            [ checkV3Fields address parameters,
                              parameters ^. ProtoFields.rootKeys === toProto (Updates.rootKeys keys),
                              parameters ^. ProtoFields.level1Keys === toProto (Updates.level1Keys keys),
                              parameters ^. ProtoFields.level2Keys === toProto (Updates.level2Keys keys),
                              parameters ^. ProtoFields.maybe'maxLockDuration === Just (toProto (Duration 42))
                            ]
    describe "Chain-parameter wire compatibility" $ do
        it "P8-P10 use CPV3" $
            map chainParametersVersionFor [P8, P9, P10] `shouldBe` replicate 3 ChainParametersV3
        it "P11 rejects an encoding truncated before the duration" $
            let bytes = S.encode p11ChainParametersExample
                durationSize = BS.length (S.encode (unOParam (_cpMaxLockDuration p11ChainParametersExample)))
            in  case S.decode (BS.take (BS.length bytes - durationSize) bytes) :: Either String (ChainParameters 'P11) of
                    Left _ -> return ()
                    Right _ -> expectationFailure "Accepted P11 parameters without max lock duration"
    describe "ChainParameters JSON tests" $ do
        testJSON ChainParametersV0 25 1000
        testJSON ChainParametersV0 50 500
        testJSON ChainParametersV1 25 1000
        testJSON ChainParametersV1 50 500
        testJSON ChainParametersV2 25 1000
        testJSON ChainParametersV2 50 500
        testJSON ChainParametersV3 50 500
        testJSON ChainParametersV4 50 500
