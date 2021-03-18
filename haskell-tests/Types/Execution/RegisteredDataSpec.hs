-- | Tests for RegisteredData.
module Types.Execution.RegisteredDataSpec where

import qualified Concordium.Crypto.ByteStringHelpers as BSH
import qualified Concordium.Types.Execution as Types

import qualified Data.Aeson as AE
import qualified Data.ByteString.Short as BSS
import qualified Data.Serialize as S
import Test.Hspec
import Test.QuickCheck

tests :: Spec
tests = describe "RegisteredData" $ do
  it "serialization: decode is inverse of encode" $
    forAll genRegisteredData $ \d -> (S.decode . S.encode) d === Right d
  it "json: decode is inverse of encode" $
    forAll genRegisteredData $ \d -> (AE.decode . AE.encode) d === Just d

genRegisteredData :: Gen Types.RegisteredData
genRegisteredData = do
  n <- chooseInt (0, Types.maxRegisteredDataSize)
  bss <- BSS.pack <$> vectorOf n arbitrary
  return . Types.RegisteredData . BSH.ByteStringHex $ bss
