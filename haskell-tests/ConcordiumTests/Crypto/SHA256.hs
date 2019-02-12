module ConcordiumTests.Crypto.SHA256 where

import qualified Concordium.Crypto.SHA256 as Hash

import Data.Serialize
import qualified Data.ByteString as BS
import Data.Word
import Test.QuickCheck
import Test.Hspec

testSerialize :: Property
testSerialize = property $ ck
    where
        ck :: [Word8] -> Bool
        ck doc = let doc' = BS.pack doc in
                    let hsh = Hash.hash doc' in
                        Right hsh == runGet get (runPut $ put hsh)

tests = parallel $ describe "Concordium.Crypto.SHA256" $ do
            it "serialization" $ testSerialize