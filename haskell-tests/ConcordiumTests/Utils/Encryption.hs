{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module ConcordiumTests.Utils.Encryption where

import qualified Data.Aeson as AE
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import Control.Exception hiding (assert)
import Control.Monad

import Test.HUnit
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck
import Test.QuickCheck.Monadic

import Concordium.Utils.Encryption

-- Needed for QuickCheck only.
deriving instance Show Password

genByteString :: Int -> Gen ByteString
genByteString n = BS.pack <$> vector n

genEncryptionInput :: Int -> Gen (ByteString, Password)
genEncryptionInput n = do
    text <- genByteString n
    pwdLen :: Int <- elements [1 .. 100]
    pwd <- genByteString pwdLen
    return (text, Password pwd)

-- | Test that composing decryption and encryption function with the same password
-- results in the identity function.
testEncryptionDecryption :: Int -> Spec
testEncryptionDecryption size = do
    specify (show size) $
        forAll (genEncryptionInput size) $ \(text, pwd) -> monadicIO $ do
            encrypted <- run $ encryptText AES256 PBKDF2SHA256 text pwd
            case decryptText encrypted pwd of
                Left err -> run $ assertFailure $ displayException err
                Right decrypted -> run $ assertEqual "Decryption does not recover plaintext: " decrypted text

-- | Test JSON serialization and deserialization of 'EncryptedText' by encrypting a random text
-- of the given size and checking that applying 'AE.toJSON' and then 'AE.fromJSON' to it
-- results in the same 'EncryptedText' object.
testToFromJSON :: Int -> Spec
testToFromJSON size = do
    specify (show size) $
        forAll (genEncryptionInput size) $ \(text, pwd) -> monadicIO $ do
            encrypted <- run $ encryptText AES256 PBKDF2SHA256 text pwd
            let json = AE.toJSON encrypted
            let encryptedFromJSON :: AE.Result EncryptedText = AE.fromJSON json
            case encryptedFromJSON of
                AE.Success res -> run $ assertEqual "toJSON/fromJSON does not preserve EncryptedText: " res encrypted
                AE.Error err -> run $ assertFailure $ "Error in JSON parsing: " ++ err

tests :: Spec
tests = do
    -- Example byte lengths for strings to encrypt. These are some smaller and bigger ones,
    -- as well as some around the block size of AES (16 bytes).
    let sizes = [1, 7, 15, 16, 17, 63, 64, 65, 200, 900, 5000]
    describe "Encryption" $ do
        -- NB: With the current iteration count of 100000 for key derivation,
        -- the average for one of 40 encryption/decryption tests takes already around 0.1s.
        describe "Encryption and decryption of a random ByteString of length ..." $
            modifyMaxSuccess (const 5) $
                forM_ sizes $
                    testEncryptionDecryption
        describe "Conversion of an EncryptedText of a ByteString of length ... to/from JSON" $
            modifyMaxSuccess (const 5) $
                forM_ sizes $
                    testToFromJSON
