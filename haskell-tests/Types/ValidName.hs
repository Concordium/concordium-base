module Types.ValidName where

import qualified Data.Text as Text
import Test.Hspec

import Concordium.Wasm

-- | Check that the valid name characters are as expected.
testValidNameChars :: Expectation
testValidNameChars = filter isValidNameChar [minBound .. maxBound] `shouldBe` validNameChars
  where
    validNameChars = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

-- | Test valid init names.
testValidInitName :: Spec
testValidInitName = describe "valid init names" $ do
    testIt "init_contract"
    -- Max allowed length
    testIt "init_01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234"
    -- Shortest possible
    testIt "init_"
    -- All allowed symbols
    testIt "init_!\"#$%&'()*+,-/0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
  where
    testIt name = it name $ isValidInitName (Text.pack name)

-- | Test invalid init names.
testInvalidInitName :: Spec
testInvalidInitName = describe "invalid init names" $ do
    testIt "init"
    testIt "init_ "
    -- Incorrect prefix
    testIt "no_init_prefix"
    -- 1 character too long.
    testIt "init_012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345"
    testIt "init_!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
  where
    testIt name = it name $ not $ isValidInitName (Text.pack name)

-- | Test valid receive names.
testValidReceiveName :: Spec
testValidReceiveName = describe "valid receive names" $ do
    testIt "contract.receive"
    -- Max allowed length
    testIt ".012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678"
    -- Shortest possible
    testIt "."
    -- All allowed symbols
    testIt "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
  where
    testIt name = it name $ isValidReceiveName (Text.pack name)

-- | Test invalid receive names.
testInvalidReceiveName :: Spec
testInvalidReceiveName = describe "invalid receive names" $ do
    -- No dot
    testIt "no_dot_separator"
    -- Too long
    testIt ".0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
    -- Contains space
    testIt "contract. receive"
  where
    testIt name = it name $ not $ isValidReceiveName (Text.pack name)

-- | Test valid entrypoint names.
testValidEntrypointName :: Spec
testValidEntrypointName = describe "valid entrypoint names" $ do
    testIt "entrypoint"
    -- Max allowed length
    testIt "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678"
    -- Shortest possible
    testIt ""
    -- All allowed symbols
    testIt "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
  where
    testIt name = it name $ isValidEntrypointName (Text.pack name)

-- | Test invalid entrypoint names.
testInvalidEntrypointName :: Spec
testInvalidEntrypointName = describe "invalid entrypoint names" $ do
    -- Too long
    testIt "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
    -- Contains space
    testIt "entry point"
  where
    testIt name = it name $ not $ isValidEntrypointName (Text.pack name)

tests :: Spec
tests = describe "Contract name validation" $ do
    it "isValidNameChar" testValidNameChars
    testValidInitName
    testInvalidInitName
    testValidReceiveName
    testInvalidReceiveName
    testValidEntrypointName
    testInvalidEntrypointName
