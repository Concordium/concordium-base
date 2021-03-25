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
            accessThreshold <- UpdateKeysThreshold <$> choose (1, fromIntegral asnKeys)
            return AccessStructure {..}
    asEmergency <- genAccessStructure
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

genHigherLevelKeys :: Gen (HigherLevelKeys a)
genHigherLevelKeys = do
  size <- getSize
  nKeys <- choose (1, min 65535 (1 + size))
  hlkKeys <- Vec.fromList . fmap Sig.correspondingVerifyKey <$> vectorOf nKeys genSigSchemeKeyPair
  hlkThreshold <- UpdateKeysThreshold <$> choose (1, fromIntegral nKeys)
  return HigherLevelKeys {..}

genRootUpdate :: Gen RootUpdate
genRootUpdate = oneof [
       RootKeysRootUpdate <$> genHigherLevelKeys,
       Level1KeysRootUpdate <$> genHigherLevelKeys,
       Level2KeysRootUpdate <$> genAuthorizations
       ]

genLevel1Update :: Gen Level1Update
genLevel1Update = oneof [
  Level1KeysLevel1Update <$> genHigherLevelKeys,
  Level2KeysLevel1Update <$> genAuthorizations
  ]

genLevel2UpdatePayload :: Gen UpdatePayload
genLevel2UpdatePayload = oneof [
        ProtocolUpdatePayload <$> genProtocolUpdate,
        ElectionDifficultyUpdatePayload <$> genElectionDifficulty,
        EuroPerEnergyUpdatePayload <$> genExchangeRate,
        MicroGTUPerEuroUpdatePayload <$> genExchangeRate,
        FoundationAccountUpdatePayload <$> genAddress,
        MintDistributionUpdatePayload <$> genMintDistribution,
        TransactionFeeDistributionUpdatePayload <$> genTransactionFeeDistribution,
        GASRewardsUpdatePayload <$> genGASRewards,
        BakerStakeThresholdUpdatePayload <$> arbitrary]

genUpdatePayload :: Gen UpdatePayload
genUpdatePayload = oneof [
        genLevel2UpdatePayload,
        RootUpdatePayload <$> genRootUpdate,
        Level1UpdatePayload <$> genLevel1Update
        ]

genRawUpdateInstruction :: Gen RawUpdateInstruction
genRawUpdateInstruction = do
        ruiSeqNumber <- Nonce <$> arbitrary
        ruiEffectiveTime <- oneof [return 0, TransactionTime <$> arbitrary]
        ruiTimeout <- TransactionTime <$> arbitrary
        ruiPayload <- genUpdatePayload
        return RawUpdateInstruction{..}

genLevel2RawUpdateInstruction :: Gen RawUpdateInstruction
genLevel2RawUpdateInstruction = do
        ruiSeqNumber <- Nonce <$> arbitrary
        ruiEffectiveTime <- oneof [return 0, TransactionTime <$> arbitrary]
        ruiTimeout <- TransactionTime <$> arbitrary
        ruiPayload <- genLevel2UpdatePayload
        return RawUpdateInstruction{..}

-- |Generate an 'Authorizations' structure and the list of key pairs.
-- The threshold for each access structure is specified.
genAuthorizationsAndKeys :: 
    UpdateKeysThreshold -- ^Threshold for each access structure
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

genLevel1Keys ::
  UpdateKeysThreshold
  -> Gen (HigherLevelKeys Level1KeysKind, [Sig.KeyPair])
genLevel1Keys thr = do
  kps <- vectorOf (fromIntegral thr * 2) genSigSchemeKeyPair
  let hlkKeys = Vec.fromList $ Sig.correspondingVerifyKey <$> kps
  return (HigherLevelKeys{hlkThreshold = thr,..}, kps)

genRootKeys ::
  UpdateKeysThreshold
  -> Gen (HigherLevelKeys RootKeysKind, [Sig.KeyPair])
genRootKeys thr = do
  kps <- vectorOf (fromIntegral thr * 2) genSigSchemeKeyPair
  let hlkKeys = Vec.fromList $ Sig.correspondingVerifyKey <$> kps
  return (HigherLevelKeys{hlkThreshold = thr,..}, kps)

genKeyCollection :: UpdateKeysThreshold -> Gen (UpdateKeysCollection, [Sig.KeyPair], [Sig.KeyPair], [Sig.KeyPair])
genKeyCollection thr = do
  (rootKeys, a) <- genRootKeys thr
  (level1Keys, b) <- genLevel1Keys thr
  (level2Keys, c) <- genAuthorizationsAndKeys thr
  return (UpdateKeysCollection{..}, a, b, c)

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
type SignKeyGen =
  -- available keys
  [Sig.KeyPair] ->
  -- a set of key indices authorized
  Set.Set UpdateKeyIndex ->
  -- The threshold
  Int ->
  -- The keys then used to sign the update
  Gen (Map.Map UpdateKeyIndex Sig.KeyPair)

-- |Generate an update instruction signed using the keys generated by the parameter.
-- The second argument indicates whether the signature should be valid.
testUpdateInstruction :: SignKeyGen -> Bool -> Property
testUpdateInstruction keyGen isValid =
  forAll (genKeyCollection 3) $ \(kc, rootK, level1K, level2K) ->
  forAll genRawUpdateInstruction $ \rui -> do
  let p = ruiPayload rui
  keysToSign <- case p of
             RootUpdatePayload{} -> f p kc rootK
             Level1UpdatePayload{} -> f p kc level1K
             _ -> f p kc level2K
  let ui = makeUpdateInstruction rui keysToSign
  return $ label "Signature check" (counterexample (show ui) $ isValid == checkAuthorizedUpdate kc ui)
           .&&. label "Serialization check" (checkSerialization ui)
  where
    f :: UpdatePayload -> UpdateKeysCollection -> [Sig.KeyPair] -> Gen (Map.Map UpdateKeyIndex Sig.KeyPair)
    f pld ukc availableKeys = do
          let (keyIndices, thr) = extractKeysIndices pld ukc
          keyGen availableKeys keyIndices (fromIntegral thr)

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
  if length keys == Set.size authIxs
    then do
    -- in this case, which can only happen when doing a level1 or root update
    -- the generated key will be an invalid one instead of a non-authorized one
    -- because there are no not-authorized keys in that case.
    -- Essentially it will just fail (as it should do).
    idx <- (length keys +) <$> choose (0, length keys - 1)
    Map.singleton (fromIntegral idx) <$> genSigSchemeKeyPair
    else do
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

-- |Combine two key generators, preferring the left one where indices overlap.
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
    specify "Valid update instructions, extraneous signatures" $ withMaxSuccess 1000 (testUpdateInstruction (combineKeys makeKeysOther makeKeysGood) False)
    specify "Update instructions, too few good" $ withMaxSuccess 1000 (testUpdateInstruction makeKeysFewGood False)
    specify "Update instructions, too few good, extraneous signatures" $ withMaxSuccess 1000 (testUpdateInstruction (combineKeys makeKeysOther makeKeysFewGood) False)
    specify "Update instructions, enough good, one bad" $ withMaxSuccess 1000 (testUpdateInstruction (combineKeys makeKeyInvalid makeKeysGood) False)
    specify "Update instructions, enough good, one bad (bad index)" $ withMaxSuccess 1000 (testUpdateInstruction (combineKeys makeKeyBadIndex makeKeysGood) False)
