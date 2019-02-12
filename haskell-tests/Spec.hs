module Main where

import Test.Hspec

import qualified ConcordiumTests.Crypto.SHA256
import qualified ConcordiumTests.Crypto.Signature

main :: IO  ()
main = hspec $ do
    ConcordiumTests.Crypto.SHA256.tests
    ConcordiumTests.Crypto.Signature.tests