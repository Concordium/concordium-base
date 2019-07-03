{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE FlexibleInstances #-}
module Concordium.Crypto.ElgamalBLS12381_G2 where

import Foreign.C.Types

import Concordium.Crypto.Elgamal.TH

data G2

mkElgamal Parameters {
  cipherLength = 2 * 96,
  secretKeyLength = 32,
  publicKeyLength = 2 * 48,
  messageLength = 2 * 48,
  cFreeMessageName = "free_message_g2",
  cFreeCipherName = "free_cipher_g2",
  cFreePublicKeyName = "free_public_key_g2",
  cFreeSecretKeyName = "free_secret_key_g2",
  cNewSecretKeyName = "new_secret_key_g2",
  cDerivePublicKeyName = "derive_public_key_g2",
  cEncryptName = "encrypt_g2",
  cDecryptName = "decrypt_g2",
  cEncryptWord64Name = "encrypt_u64_g2",
  cDecryptWord64Name = "decrypt_u64_g2",
  cDecryptWord64UnsafeName = "decrypt_u64_unsafe_g2",
  cMessageToBytesName = "message_to_bytes_g2",
  cCipherToBytesName = "cipher_to_bytes_g2",
  cPublicKeyToBytesName = "public_key_to_bytes_g2",
  cSecretKeyToBytesName = "secret_key_to_bytes_g2",
  cBytesToMessageName = "bytes_to_message_g2",
  cBytesToCipherName = "bytes_to_cipher_g2",
  cBytesToPublicKeyName = "bytes_to_public_key_g2",
  cBytesToSecretKeyName = "bytes_to_secret_key_g2",
  tagName = ''G2
  }
