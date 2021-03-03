{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -Wno-deprecations #-}
-- |Tests for the functionality implemented in Concordium.Types.Updates.
module Types.UpdatesSpec where

import qualified Data.Aeson as AE
import qualified Data.ByteString as BS
import qualified Data.Map as Map
import Data.Ratio
import Data.Serialize hiding (label)
import qualified Data.Set as Set
import qualified Data.Text as Text
import qualified Data.Vector as Vec
import Data.Word
import Test.Hspec
import Test.QuickCheck as QC

import Concordium.Crypto.DummyData ( genSigSchemeKeyPair )
import qualified Concordium.Crypto.SignatureScheme as Sig
import qualified Concordium.Crypto.SHA256 as Hash

import Concordium.Types.Updates
import Concordium.Types

import Types.PayloadSerializationSpec (genAddress)

genElectionDifficulty :: Gen ElectionDifficulty
genElectionDifficulty = makeElectionDifficulty <$> arbitrary `suchThat` (< 100000)

genAuthorizations :: Gen Authorizations
genAuthorizations = do
    size <- getSize
    nKeys <- choose (1, min 65535 (1 + size))
    asKeys <- Vec.fromList . fmap Sig.correspondingVerifyKey <$> vectorOf nKeys genSigSchemeKeyPair
    let genAccessStructure = do
            asnKeys <- choose (1, nKeys)
            accessPublicKeys <- Set.fromList . take asnKeys <$> shuffle [0..fromIntegral nKeys - 1]
            accessThreshold <- choose (1, fromIntegral asnKeys)
            return AccessStructure {..}
    asEmergency <- genAccessStructure
    asAuthorization <- genAccessStructure
    asProtocol <- genAccessStructure
    asParamElectionDifficulty <- genAccessStructure
    asParamEuroPerEnergy <- genAccessStructure
    asParamMicroGTUPerEuro <- genAccessStructure
    asParamFoundationAccount <- genAccessStructure
    asParamMintDistribution <- genAccessStructure
    asParamTransactionFeeDistribution <- genAccessStructure
    asParamGASRewards <- genAccessStructure
    asBakerStakeThreshold <- genAccessStructure
    return Authorizations{..}

genProtocolUpdate :: Gen ProtocolUpdate
genProtocolUpdate = do
        puMessage <- Text.pack <$> arbitrary
        puSpecificationURL <- Text.pack <$> arbitrary
        puSpecificationHash <- Hash.hash . BS.pack <$> arbitrary
        puSpecificationAuxiliaryData <- BS.pack <$> arbitrary
        return ProtocolUpdate{..}

genMintRate :: Gen MintRate
genMintRate = do
  mrExponent <- arbitrary
  mrMantissa <- choose (0, fromIntegral (min (toInteger (maxBound :: Word32)) (10^mrExponent)))
  return MintRate{..}

genExchangeRate :: Gen ExchangeRate
genExchangeRate = do
        num <- choose (1, maxBound)
        den <- choose (1, maxBound)
        return $ ExchangeRate (num % den)

genMintDistribution :: Gen MintDistribution
genMintDistribution = do
        _mdMintPerSlot <- genMintRate
        bf <- choose (0,100000)
        ff <- choose (0,100000-bf)
        let _mdBakingReward = makeRewardFraction bf
            _mdFinalizationReward = makeRewardFraction ff
        return MintDistribution{..}

genTransactionFeeDistribution :: Gen TransactionFeeDistribution
genTransactionFeeDistribution = do
        bf <- choose (0,100000)
        gf <- choose (0,100000-bf)
        let _tfdBaker = makeRewardFraction bf
            _tfdGASAccount = makeRewardFraction gf
        return TransactionFeeDistribution{..}

genGASRewards :: Gen GASRewards
genGASRewards = do
        _gasBaker <- makeRewardFraction <$> choose (0,100000)
        _gasFinalizationProof <- makeRewardFraction <$> choose (0,100000)
        _gasAccountCreation <- makeRewardFraction <$> choose (0,100000)
        _gasChainUpdate <- makeRewardFraction <$> choose (0,100000)
        return GASRewards{..}

genUpdatePayload :: Gen UpdatePayload
genUpdatePayload = oneof [
        AuthorizationUpdatePayload <$> genAuthorizations,
        ProtocolUpdatePayload <$> genProtocolUpdate,
        ElectionDifficultyUpdatePayload <$> genElectionDifficulty,
        EuroPerEnergyUpdatePayload <$> genExchangeRate,
        MicroGTUPerEuroUpdatePayload <$> genExchangeRate,
        FoundationAccountUpdatePayload <$> genAddress,
        MintDistributionUpdatePayload <$> genMintDistribution,
        TransactionFeeDistributionUpdatePayload <$> genTransactionFeeDistribution,
        GASRewardsUpdatePayload <$> genGASRewards,
        BakerStakeThresholdPayload <$> arbitrary]

genRawUpdateInstruction :: Gen RawUpdateInstruction
genRawUpdateInstruction = do
        ruiSeqNumber <- Nonce <$> arbitrary
        ruiEffectiveTime <- oneof [return 0, TransactionTime <$> arbitrary]
        ruiTimeout <- TransactionTime <$> arbitrary
        ruiPayload <- genUpdatePayload
        return RawUpdateInstruction{..}

-- |Generate an 'Authorizations' structure and the list of key pairs.
-- The threshold for each access structure is specified.
genAuthorizationsAndKeys :: 
    Word16 -- ^Threshold for each access structure
    -> Gen (Authorizations, [Sig.KeyPair])
genAuthorizationsAndKeys thr = do
        let nKeys = fromIntegral thr * 12
        kps <- vectorOf nKeys genSigSchemeKeyPair
        let asKeys = Vec.fromList $ Sig.correspondingVerifyKey <$> kps
        let genAccessStructure = do
                asnKeys <- choose (fromIntegral thr, nKeys)
                accessPublicKeys <- Set.fromList . take asnKeys <$> shuffle [0..fromIntegral nKeys - 1]
                return AccessStructure {accessThreshold = thr, ..}
        asEmergency <- genAccessStructure
        asAuthorization <- genAccessStructure
        asProtocol <- genAccessStructure
        asParamElectionDifficulty <- genAccessStructure
        asParamEuroPerEnergy <- genAccessStructure
        asParamMicroGTUPerEuro <- genAccessStructure
        asParamFoundationAccount <- genAccessStructure
        asParamMintDistribution <- genAccessStructure
        asParamTransactionFeeDistribution <- genAccessStructure
        asParamGASRewards <- genAccessStructure
        asBakerStakeThreshold <- genAccessStructure
        return (Authorizations{..}, kps)

{-
genUpdateInstruction :: Gen UpdateInstruction
genUpdateInstruction = do
        uiPayload <- genUpdatePayload
        return UpdateInstruction{..}
-}

checkSerialization :: (Serialize a, Eq a, Show a) => a -> Property
checkSerialization v = case decode (encode v) of
        Left err -> counterexample err False
        Right v' -> v' === v

-- |Test that if we serialize then deserialize an 'UpdatePayload',
-- we get back the value we started with.
testSerializeUpdatePayload :: Property
testSerializeUpdatePayload = forAll (resize 50 genUpdatePayload) checkSerialization

-- |Test that if we JSON-encode and decode an 'UpdatePayload',
-- we get back the value we started with.
testJSONUpdatePayload :: Property
testJSONUpdatePayload = forAll (resize 50 genUpdatePayload) chk
    where
        chk up = case AE.eitherDecode (AE.encode up) of
                Left err -> counterexample err False
                Right up' -> up === up'

-- |Function type for generating a set of keys to sign an update instruction with.
type SignKeyGen = [Sig.KeyPair] -> Set.Set UpdateKeyIndex -> Int -> Gen (Map.Map UpdateKeyIndex Sig.KeyPair)

-- |Generate an update instruction signed using the keys generated by the parameter.
-- The second argument indicates whether the signature should be valid.
testUpdateInstruction :: SignKeyGen -> Bool -> Property
testUpdateInstruction keyGen isValid = forAll (genAuthorizationsAndKeys 3) $ \(auths,keys) ->
        forAll genRawUpdateInstruction $ \rui -> do
            let AccessStructure{..} = case ruiPayload rui of
                    AuthorizationUpdatePayload{} -> asAuthorization auths
                    ProtocolUpdatePayload{} -> asProtocol auths
                    ElectionDifficultyUpdatePayload{} -> asParamElectionDifficulty auths
                    EuroPerEnergyUpdatePayload{} -> asParamEuroPerEnergy auths
                    MicroGTUPerEuroUpdatePayload{} -> asParamMicroGTUPerEuro auths
                    FoundationAccountUpdatePayload{} -> asParamFoundationAccount auths
                    MintDistributionUpdatePayload{} -> asParamMintDistribution auths
                    TransactionFeeDistributionUpdatePayload{} -> asParamTransactionFeeDistribution auths
                    GASRewardsUpdatePayload{} -> asParamGASRewards auths
                    BakerStakeThresholdPayload{} -> asBakerStakeThreshold auths
            useKeys <- keyGen keys accessPublicKeys (fromIntegral accessThreshold)
            let ui = makeUpdateInstruction rui useKeys
            return $ label "Signature check" (counterexample (show ui) $ isValid == checkAuthorizedUpdate auths ui)
                .&&. label "Serialization check" (checkSerialization ui)

-- |Make a collection of keys that should be sufficient to sign.
makeKeysGood :: SignKeyGen
makeKeysGood keys authIxs threshold = do
        nGoodSigs <- choose (threshold, Set.size authIxs)
        goodKeyIxs <- take nGoodSigs <$> shuffle (Set.toList authIxs)
        return $ Map.fromList [(k, keys !! fromIntegral k) | k <- goodKeyIxs]

-- |Make a collection of keys that are authorized but do not meet
-- the threshold for signing.
makeKeysFewGood :: SignKeyGen
makeKeysFewGood keys authIxs threshold = do
        nGoodSigs <- choose (1, threshold - 1)
        goodKeyIxs <- take nGoodSigs <$> shuffle (Set.toList authIxs)
        return $ Map.fromList [(k, keys !! fromIntegral k) | k <- goodKeyIxs]

-- |Make a collection of keys, none of which are authorized to sign.
makeKeysOther :: SignKeyGen
makeKeysOther keys authIxs _ = do
        let otherKeys = [(i, k) | (i, k) <- [0..] `zip` keys, i `Set.notMember` authIxs]
        nKeys <- choose (1, length otherKeys)
        Map.fromList . take nKeys <$> shuffle otherKeys

-- |Make a key that is different to one in the keys.
makeKeyInvalid :: SignKeyGen
makeKeyInvalid keys _ _ = do
        idx <- choose (0, length keys - 1)
        let genKey = do
                k <- genSigSchemeKeyPair
                if k /= keys !! idx then return k else genKey
        Map.singleton (fromIntegral idx) <$> genKey

-- |Make a key that has an index that is out of bounds.
makeKeyBadIndex :: SignKeyGen
makeKeyBadIndex keys _ _ = do
        idx <- choose (fromIntegral (length keys), maxBound)
        Map.singleton idx <$> genSigSchemeKeyPair

-- |Combine two key generators, preferring the left one where indexes overlap.
combineKeys :: SignKeyGen -> SignKeyGen -> SignKeyGen
combineKeys kg1 kg2 keys authIxs threshold = do
        k1 <- kg1 keys authIxs threshold
        k2 <- kg2 keys authIxs threshold
        return $ Map.union k1 k2

tests :: Spec
tests = parallel $ do
    specify "UpdatePayload serialization" $ withMaxSuccess 1000 testSerializeUpdatePayload
    specify "UpdatePayload JSON" $ withMaxSuccess 1000 testJSONUpdatePayload
    specify "Valid update instructions" $ withMaxSuccess 1000 (testUpdateInstruction makeKeysGood True)
    specify "Valid update instructions, extraneous signatures" $ withMaxSuccess 1000 (testUpdateInstruction (combineKeys makeKeysOther makeKeysGood) True)
    specify "Update instructions, too few good" $ withMaxSuccess 1000 (testUpdateInstruction makeKeysFewGood False)
    specify "Update instructions, too few good, extraneous singatures" $ withMaxSuccess 1000 (testUpdateInstruction (combineKeys makeKeysOther makeKeysFewGood) False)
    specify "Update instructions, enough good, one bad" $ withMaxSuccess 1000 (testUpdateInstruction (combineKeys makeKeyInvalid makeKeysGood) False)
    specify "Update instructions, enough good, one bad (bad index)" $ withMaxSuccess 1000 (testUpdateInstruction (combineKeys makeKeyBadIndex makeKeysGood) False)
