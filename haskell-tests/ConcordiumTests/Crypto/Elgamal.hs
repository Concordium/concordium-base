{-# LANGUAGE ScopedTypeVariables #-}
module ConcordiumTests.Crypto.Elgamal where

import qualified Concordium.Crypto.Elgamal as Elgamal 

import Data.Serialize
import qualified Data.ByteString as BS
import Test.QuickCheck.Monadic
import Test.QuickCheck
import Test.Hspec
import           Foreign.Ptr
import           Foreign.ForeignPtr

testEncryptDecrypt :: Property
testEncryptDecrypt = property $ \n ->  monadicIO  $ do 
    sk <- run $ Elgamal.newSecretKey
    pk <- run $  Elgamal.publicKey sk
    c <- run $ Elgamal.encrypt_word64 pk n
    m <- run $ Elgamal.decrypt_word64 sk c
    return $ m===n
                           


tests :: Spec
tests = parallel $ describe "Concordium.Crypto.Elgamal" $ do
    describe "Encrypt decrypt" $ do
        it "Encrypt decrypt word64" $ withMaxSuccess 1000 $ testEncryptDecrypt

