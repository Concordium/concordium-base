module Main where

import Test.Hspec

import qualified ConcordiumTests.Crypto.SHA256
import qualified ConcordiumTests.Crypto.Ed25519Signature
import qualified ConcordiumTests.Crypto.VRF
import qualified ConcordiumTests.Crypto.FFIDataTypes
import qualified ConcordiumTests.Crypto.FFIVerify
import qualified ConcordiumTests.Crypto.BlsSignature
import qualified ConcordiumTests.Data.Base58Encoding
import qualified ConcordiumTests.ID.Types
import qualified ConcordiumTests.Crypto.Ed25519DlogProofs

main :: IO  ()
main = hspec $ parallel $ do
    ConcordiumTests.Crypto.FFIVerify.tests
    ConcordiumTests.Crypto.FFIDataTypes.tests
    ConcordiumTests.Crypto.SHA256.tests
    ConcordiumTests.Crypto.Ed25519Signature.tests
    ConcordiumTests.Crypto.VRF.tests
    ConcordiumTests.Crypto.BlsSignature.tests
    ConcordiumTests.Data.Base58Encoding.tests
    ConcordiumTests.ID.Types.tests
    ConcordiumTests.Crypto.Ed25519DlogProofs.tests
    -- --NB: The following tests are far from complete. They do not test what
    -- -- happens when data is corrupt in various ways (number of commmited values
    -- -- is incorrect, or similar)
