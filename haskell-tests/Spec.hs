module Main where

import Test.Hspec

import qualified ConcordiumTests.Crypto.SHA256
import qualified ConcordiumTests.Crypto.SHA224
import qualified ConcordiumTests.Crypto.Signature
import qualified ConcordiumTests.Crypto.VRF

main :: IO  ()
main = hspec $ do
    ConcordiumTests.Crypto.SHA256.tests
    ConcordiumTests.Crypto.SHA224.tests
    ConcordiumTests.Crypto.Signature.tests
    ConcordiumTests.Crypto.VRF.tests
