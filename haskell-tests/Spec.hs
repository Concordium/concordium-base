module Main where

import Test.Hspec

import qualified ConcordiumTests.Crypto.SHA256
import qualified ConcordiumTests.Crypto.SHA224
import qualified ConcordiumTests.Crypto.Ed25519Signature
import qualified ConcordiumTests.Crypto.VRF
import qualified ConcordiumTests.Crypto.Elgamal

main :: IO  ()
main = hspec $ do
--    ConcordiumTests.Crypto.SHA256.tests
--    ConcordiumTests.Crypto.SHA224.tests
--    ConcordiumTests.Crypto.Ed25519Signature.tests
--    ConcordiumTests.Crypto.VRF.tests
    ConcordiumTests.Crypto.Elgamal.tests
