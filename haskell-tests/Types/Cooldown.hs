module Types.Cooldown where

import Test.Hspec
import Test.QuickCheck

import Concordium.Types
import Concordium.Types.Accounts

genCooldownTime :: Gen CooldownTime
genCooldownTime =
    oneof
        [ CooldownTimestamp . Timestamp <$> chooseBoundedIntegral (0, 0x7fffffffffffffff),
          PreCooldownTS . Timestamp <$> chooseBoundedIntegral (0, 0x3ffffffffffffffe),
          return PreCooldown,
          PrePreCooldownTS . Timestamp <$> chooseBoundedIntegral (0, 0x3ffffffffffffffe),
          return PrePreCooldown
        ]

genCooldownTimeCode :: Gen CooldownTimeCode
genCooldownTimeCode = CooldownTimeCode <$> arbitrary

propEncodeDecodeId :: Property
propEncodeDecodeId = forAll genCooldownTime $ \t ->
    decodeCooldownTime (encodeCooldownTime t) === t

propDecodeEncodeId :: Property
propDecodeEncodeId = forAll genCooldownTimeCode $ \t ->
    encodeCooldownTime (decodeCooldownTime t) === t

propEncodePreservesOrder :: Property
propEncodePreservesOrder = forAll genCooldownTime $ \t1 -> forAll genCooldownTime $ \t2 ->
    compare (encodeCooldownTime t1) (encodeCooldownTime t2) === compare t1 t2

propDecodePreservesOrder :: Property
propDecodePreservesOrder = forAll genCooldownTimeCode $ \t1 -> forAll genCooldownTimeCode $ \t2 ->
    compare (decodeCooldownTime t1) (decodeCooldownTime t2) === compare t1 t2

tests :: Spec
tests = describe "Cooldown" $ parallel $ do
    it "encode then decode CooldownTime" $ withMaxSuccess 10000 propEncodeDecodeId
    it "decode then encode CooldownTimeCode" $ withMaxSuccess 10000 propDecodeEncodeId
    it "encode preserves order" $ withMaxSuccess 10000 propEncodePreservesOrder
    it "decode preserves order" $ withMaxSuccess 10000 propDecodePreservesOrder
