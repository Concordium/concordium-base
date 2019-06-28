{-# LANGUAGE ScopedTypeVariables #-}
module ConcordiumTests.Crypto.ElgamalBLS12381_G2 where

import qualified Concordium.Crypto.ElgamalBLS12381_G2 as Elgamal 

import qualified Data.ByteString as BS
import Data.Maybe

import Test.QuickCheck.Monadic
import Test.QuickCheck
import Test.Hspec

testEncryptDecryptWord :: Property
testEncryptDecryptWord = property $ \n -> monadicIO  $ do 
  Just sk <- run $ Elgamal.newSecretKey
  let pk = Elgamal.publicKey sk
  c <- run $ Elgamal.encrypt_word64 pk n
  let Elgamal.DecryptWord64Success m = Elgamal.decryptWord64 sk c
  return $ m===n

testEncryptDecrypt :: Property
testEncryptDecrypt = property $ \n -> monadicIO $ do 
  Just sk <- run $ Elgamal.newSecretKey
  let pk = Elgamal.publicKey sk
  enc <- Elgamal.word64CipherToBytes <$> (run $ Elgamal.encrypt_word64 pk n)
  let Just message = Elgamal.messageFromBytes (BS.take 96 enc) -- hack, but should work in this case.
  c <- run $ Elgamal.encrypt pk message
  let message' = Elgamal.decrypt sk c
  return $ Elgamal.messageToBytes message === Elgamal.messageToBytes message'

testFromToSecretKey :: Property
testFromToSecretKey =
  forAll (BS.pack <$> (vector 32)) $
     \bs -> let m = Elgamal.secretKeyFromBytes bs
            in isJust m ==> bs === Elgamal.secretKeyToBytes (fromJust m)

testFromToPublicKey :: Property
testFromToPublicKey =
  forAll (BS.pack <$> (vector 96)) $
     \bs -> let m = Elgamal.publicKeyFromBytes bs
            in isJust m ==> bs === Elgamal.publicKeyToBytes (fromJust m)

tests :: Spec
tests = describe "Concordium.Crypto.Elgamal over G2" $ do
  specify "Secret key to/from bytes" $ withMaxSuccess 1000 $ testFromToSecretKey
  describe "Encrypt decrypt" $ do
    specify "Encrypt decrypt word64" $ withMaxSuccess 100 $ testEncryptDecryptWord
    specify "Encrypt decrypt" $ withMaxSuccess 100 $ testEncryptDecrypt

