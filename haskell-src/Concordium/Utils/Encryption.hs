{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

{-
Encryption utilities.
-}
module Concordium.Utils.Encryption where

import Control.Exception
import Control.Monad.Except

import Data.Aeson ((.:), (.=))
import qualified Data.Aeson as AE
import qualified Data.Aeson.Internal as AE
import qualified Data.Aeson.KeyMap as AEMap
import qualified Data.Aeson.Parser as AE
import qualified Data.Aeson.Types as AE
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as LazyBS
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Text.IO as T
import System.IO

import Crypto.Cipher.AES
import Crypto.Cipher.Types
import Crypto.Data.Padding
import Crypto.Error
import Crypto.KDF.PBKDF2
import Crypto.Random

import Concordium.Utils (embedErr)

-- | A wrapper for 'ByteString' to be used for passwords.
-- Using this dedicated type is supposed to reduce the risk of accidentally exposing passwords.
newtype Password = Password {getPassword :: ByteString}
    deriving (Eq)

data SupportedEncryptionMethod = AES256
    deriving (Eq, Show)

instance AE.FromJSON SupportedEncryptionMethod where
    parseJSON = AE.withText "Encryption method" $ \t ->
        if t == "AES-256"
            then return AES256
            else fail $ "Unsupported encryption method: " ++ T.unpack t

instance AE.ToJSON SupportedEncryptionMethod where
    toJSON AES256 = AE.String "AES-256"

data SupportedKeyDerivationMethod = PBKDF2SHA256
    deriving (Eq, Show)

instance AE.ToJSON SupportedKeyDerivationMethod where
    toJSON PBKDF2SHA256 = AE.String "PBKDF2WithHmacSHA256"

instance AE.FromJSON SupportedKeyDerivationMethod where
    parseJSON = AE.withText "Key derivation method" $ \t ->
        if t == "PBKDF2WithHmacSHA256"
            then return PBKDF2SHA256
            else fail $ "Unsupported key derivation method: " ++ T.unpack t

-- |Bytestring whose JSON instances use base64 encoding.
newtype Base64ByteString = Base64ByteString {theBS :: ByteString}
    deriving (Eq)

instance Show Base64ByteString where
    show (Base64ByteString x) = BS8.unpack (Base64.encode x)

instance AE.ToJSON Base64ByteString where
    -- text decode is safe here because base64 encoding will produce
    -- only ascii, hence valid utf8 characters.
    toJSON (Base64ByteString x) = AE.String (T.decodeUtf8 (Base64.encode x))

instance AE.FromJSON Base64ByteString where
    parseJSON = AE.withText "base 64 encoded bytestring" $ \t ->
        case Base64.decode (T.encodeUtf8 t) of
            Left err -> fail err
            Right x -> return (Base64ByteString x)

-- | Meta data for an encrypted text. Needed for decryption.
data EncryptionMetadata = EncryptionMetadata
    { emEncryptionMethod :: !SupportedEncryptionMethod,
      emKeyDerivationMethod :: !SupportedKeyDerivationMethod,
      emIterations :: !Word,
      emSalt :: !Base64ByteString,
      emInitializationVector :: !Base64ByteString
    }
    deriving (Eq, Show)

instance AE.ToJSON EncryptionMetadata where
    toJSON EncryptionMetadata{..} =
        case (emEncryptionMethod, emKeyDerivationMethod) of
            (AES256, PBKDF2SHA256) ->
                AE.object
                    [ "encryptionMethod" .= emEncryptionMethod,
                      "keyDerivationMethod" .= emKeyDerivationMethod,
                      "iterations" .= emIterations,
                      "salt" .= emSalt,
                      "initializationVector" .= emInitializationVector
                    ]

instance AE.FromJSON EncryptionMetadata where
    parseJSON = AE.withObject "EncryptionMetadata" $ \v -> do
        emEncryptionMethod <- v .: "encryptionMethod"
        emKeyDerivationMethod <- v .: "keyDerivationMethod"
        case (emEncryptionMethod, emKeyDerivationMethod) of
            (AES256, PBKDF2SHA256) -> do
                emIterations <- v .: "iterations"
                emSalt <- v .: "salt"
                emInitializationVector <- v .: "initializationVector"
                return EncryptionMetadata{..}

-- | An encrypted text with meta data needed for decryption.
data EncryptedText = EncryptedText
    { etMetadata :: !EncryptionMetadata,
      etCipherText :: !Base64ByteString
    }
    deriving (Eq, Show)

instance AE.ToJSON EncryptedText where
    toJSON EncryptedText{..} =
        AE.object
            [ "metadata" .= etMetadata,
              "cipherText" .= etCipherText
            ]

instance AE.FromJSON EncryptedText where
    parseJSON = AE.withObject "EncryptedText" $ \v -> do
        etMetadata <- v .: "metadata"
        etCipherText <- v .: "cipherText"
        return EncryptedText{..}

-- | Possible decryption failures for 'AES256' with 'PBKDF2SHA256'.
data DecryptionFailure
    = -- | Base64 decoding failed.
      DecodeError
        { -- | Parameter for which decoding failed.
          deParam :: String,
          -- | The decoding error.
          deErr :: String
        }
    | -- | Creating the initialization vector in the cryptonite library failed.
      -- This happens when it does not have the right length (16 bytes for AES).
      MakingInitializationVectorFailed
    | -- | Cipher initialization in the cryptonite library failed.
      CipherInitializationFailed CryptoError
    | -- | Unpadding after decryption failed. If there is no data corruption, this indicates that a wrong password was given.
      UnpaddingFailed
    deriving (Show)

instance Exception DecryptionFailure where
    displayException e =
        "decryption failure: "
            ++ case e of
                DecodeError field err -> "cannot decode " ++ field ++ ": " ++ err
                MakingInitializationVectorFailed -> "making initialization vector failed"
                CipherInitializationFailed err -> "cipher initialization failed: " ++ show err
                UnpaddingFailed -> "wrong password"

-- | Decrypt an 'EncryptedText' where cipher, initialization vector and salt are Base64-encoded.
decryptText ::
    (MonadError DecryptionFailure m) =>
    EncryptedText ->
    Password ->
    m ByteString
decryptText EncryptedText{etMetadata = EncryptionMetadata{..}, ..} pwd = do
    case (emEncryptionMethod, emKeyDerivationMethod) of
        (AES256, PBKDF2SHA256) -> do
            iv <- case makeIV (theBS emInitializationVector) of
                Nothing -> throwError MakingInitializationVectorFailed
                Just iv -> return iv
            let keyLen = 32

            -- NB: fromIntegral is safe to do as too large Word values will result in negative Int values, which should be rejected.
            let key = fastPBKDF2_SHA256 (Parameters (fromIntegral emIterations) keyLen) (getPassword pwd) (theBS emSalt) :: ByteString
            (aes :: AES256) <- case cipherInit key of
                CryptoFailed err -> throwError $ CipherInitializationFailed err
                CryptoPassed a -> return a

            let decrypted = cbcDecrypt aes iv (theBS etCipherText) :: ByteString
            -- Unpadding for 16 byte block size.
            let unpadded = unpad (PKCS7 16) decrypted
            case unpadded of
                Nothing -> throwError UnpaddingFailed
                Just text -> return text

-- | Encrypt a 'ByteString' with the given password, using the given encryption and key derivation
-- method. Initialization vector and salt are generated randomly using 'getRandomBytes' from
-- @MonadRandom IO@ and included in the returned meta data. Cipher, initialization vector and salt
-- are Base64-encoded in the output.
encryptText ::
    SupportedEncryptionMethod ->
    SupportedKeyDerivationMethod ->
    ByteString ->
    Password ->
    IO EncryptedText
encryptText emEncryptionMethod emKeyDerivationMethod text pwd =
    case (emEncryptionMethod, emKeyDerivationMethod) of
        -- See also specification RFC2898 (https://tools.ietf.org/html/rfc2898) and
        -- recommendations from NIST in SP800-132 (2010 publication, still available:
        -- https://csrc.nist.gov/publications/detail/sp/800-132/final).
        (AES256, PBKDF2SHA256) -> do
            -- NOTE: The initialization vector should only be used once for the same key.
            initVec <- getRandomBytes 16 -- Length must be block size, which is 128bit for AES.
            iv :: IV AES256 <- case makeIV initVec of
                -- NB: This should not happen because we generate a valid initialization vector above.
                Nothing -> fail "Encryption error: making initialization vector failed."
                Just iv -> return iv
            -- RFC2898 section 4.2 recommends minimum 1000 iterations; NIST as many as feasible;
            -- IOS4 uses 10000 according to https://en.wikipedia.org/wiki/Pbkdf2#Purpose_and_operation.
            -- Current wallet export (app version 0.5.8) uses 100000.
            let emIterations = 100000
            -- RFC2898 section 4.1 recommends at least 64bits; NIST recommends 128bit.
            salt <- getRandomBytes 16
            let keyLen = 32

            -- NB: fromIntegral is safe to do as too large Word values will result in negative Int values, which should be rejected.
            let key = fastPBKDF2_SHA256 (Parameters (fromIntegral emIterations) keyLen) (getPassword pwd) salt :: ByteString

            (aes :: AES256) <- case cipherInit key of
                -- NB: This should not happen because we generate a valid key above.
                CryptoFailed err -> fail $ "Encryption error: cipher initialization failed: " ++ show err
                CryptoPassed a -> return a

            -- Padding for 16 byte block size.
            let paddedText = pad (PKCS7 16) text
            let cipher = cbcEncrypt aes iv paddedText
            return
                EncryptedText
                    { etCipherText = Base64ByteString cipher,
                      etMetadata =
                        EncryptionMetadata
                            { emSalt = Base64ByteString salt,
                              emInitializationVector = Base64ByteString initVec,
                              ..
                            }
                    }

-- | An encrypted JSON serialization of a value of the given type.
newtype EncryptedJSON a = EncryptedJSON EncryptedText
    deriving (AE.FromJSON, AE.ToJSON, Show, Eq)

-- |Check whether the given JSON object likely contains an encryption. This is established
-- by the presence of fields @metadata@ and @cipherText@
isLikelyEncrypted :: AE.Value -> Bool
isLikelyEncrypted (AE.Object o) = AEMap.member "cipherText" o && AEMap.member "metadata" o
isLikelyEncrypted _ = False

-- | Failures that can occur when decrypting an 'EncryptedJSON'.
data DecryptJSONFailure
    = -- | Decryption failed.
      DecryptionFailure DecryptionFailure
    | -- | The decrypted 'ByteString' is not a valid JSON object.
      -- If there is no data corruption, this indicates that a wrong password was given.
      IncorrectJSON String
    deriving (Show)

instance Exception DecryptJSONFailure where
    displayException (DecryptionFailure df) = displayException df
    displayException (IncorrectJSON err) = "cannot decode JSON: " ++ err

-- | Decrypt and deserialize an 'EncryptedJSON'.
decryptJSON ::
    (MonadError DecryptJSONFailure m, AE.FromJSON a) =>
    EncryptedJSON a ->
    Password ->
    m a
decryptJSON ej pwd = decryptJSONWith ej pwd AE.parseJSON

-- | Decrypt and deserialize an 'EncryptedJSON' using the provided parser.
decryptJSONWith ::
    (MonadError DecryptJSONFailure m) =>
    EncryptedJSON a ->
    Password ->
    (AE.Value -> AE.Parser a) ->
    m a
decryptJSONWith (EncryptedJSON encryptedText) pwd parser = do
    decrypted <- decryptText encryptedText pwd `embedErr` DecryptionFailure
    case AE.eitherDecodeStrictWith AE.json' (AE.iparse parser) decrypted of
        Left (path, err) -> throwError (IncorrectJSON (AE.formatError path err))
        Right a -> return a

-- | Encrypt a JSON-serializable value.
encryptJSON ::
    (AE.ToJSON a) =>
    SupportedEncryptionMethod ->
    SupportedKeyDerivationMethod ->
    a ->
    Password ->
    IO (EncryptedJSON a)
encryptJSON encryptionMethod keyDerivationMethod value pwd =
    let json = LazyBS.toStrict $ AE.encode value
    in  EncryptedJSON <$> encryptText encryptionMethod keyDerivationMethod json pwd

-- | Try to decode json, which may be encrypted as 'EncryptedJSON'. If the
-- object contains the fields 'metadata' and 'cipherText' then we assume that it
-- requires decryption, otherwise we assume that it should parse as a given
-- type.
--
-- When encrypted, use the password action to retrieve a password.
decodeMaybeEncrypted ::
    (AE.FromJSON a) =>
    -- | Password action to use if data is encrypted.
    IO Password ->
    -- | JSON to decode.
    ByteString ->
    -- | Return a pair of a result and whether it was decoded from an encrypted file.
    IO (Either String (a, Bool))
decodeMaybeEncrypted getPwd json = do
    case AE.eitherDecodeStrict json of
        Left _ -> return $ (,False) <$> AE.eitherDecodeStrict json `embedErr` (\err -> "Error decoding JSON: " ++ err)
        Right encryptedJSON -> do
            pwd <- getPwd
            return $ (,True) <$> decryptJSON encryptedJSON pwd `embedErr` (("Error decoding encrypted JSON: " ++) . displayException)

-- | Encrypt a file as 'EncryptedJSON' with AES256 and PBKDF2SHA256.
--   Prompts for a password to encrypt with.
encryptFileAsEncryptedJSON ::
    -- | File to encrypt.
    FilePath ->
    -- | Out file.
    FilePath ->
    IO ()
encryptFileAsEncryptedJSON inFile outFile = do
    content <- BS.readFile inFile
    pwd <- askPassword "Enter password to encrypt with: "
    encContent <- AE.encode <$> encryptText AES256 PBKDF2SHA256 content pwd
    LazyBS.writeFile outFile encContent

-- | Ask for a password on standard input not showing what is typed.
askPassword ::
    -- | A text to display after which the password is typed (nothing is appended to this).
    String ->
    IO Password
askPassword descr = do
    putStr descr
    hFlush stdout
    -- Get the password from command line, not showing what is typed by temporarily disabling echo.
    passwordInput <- bracket_ (hSetEcho stdin False) (hSetEcho stdin True) T.getLine
    let password = T.encodeUtf8 passwordInput
    putStrLn ""
    hFlush stdout
    return (Password password)
