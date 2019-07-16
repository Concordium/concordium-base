module Main where

import Test.Hspec

import qualified ConcordiumTests.Crypto.SHA256
import qualified ConcordiumTests.Crypto.SHA224
import qualified ConcordiumTests.Crypto.Ed25519Signature
import qualified ConcordiumTests.Crypto.VRF
import qualified ConcordiumTests.Crypto.FFIDataTypes
import qualified ConcordiumTests.Crypto.FFIVerify

main :: IO  ()
main = hspec $ parallel $ do
    ConcordiumTests.Crypto.FFIVerify.tests
    ConcordiumTests.Crypto.FFIDataTypes.tests
    ConcordiumTests.Crypto.SHA256.tests
    ConcordiumTests.Crypto.SHA224.tests
    ConcordiumTests.Crypto.Ed25519Signature.tests
    ConcordiumTests.Crypto.VRF.tests

    -- --NB: The following tests are far from complete. They do not test what
    -- -- happens when data is corrupt in various ways (number of commmited values
    -- -- is incorrect, or similar)
