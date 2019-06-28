{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE FlexibleInstances #-}
module Concordium.Crypto.Elgamal where

import Foreign.C.Types

import Concordium.Crypto.Elgamal.TH

data G1

mkElgamal Parameters {
  cipherLength = 96,
  secretKeyLength = 32,
  publicKeyLength = 48,
  messageLength = 48,
  cFreeMessageName = "free_message_g1",
  cFreeCipherName = "free_cipher_g1",
  cFreePublicKeyName = "free_public_key_g1",
  cFreeSecretKeyName = "free_secret_key_g1",
  cNewSecretKeyName = "new_secret_key_g1",
  cDerivePublicKeyName = "derive_public_key_g1",
  cEncryptName = "encrypt_g1",
  cDecryptName = "decrypt_g1",
  cEncryptWord64Name = "encrypt_u64_g1",
  cDecryptWord64Name = "decrypt_u64_g1",
  cDecryptWord64UnsafeName = "decrypt_u64_unsafe_g1",
  cMessageToBytesName = "message_to_bytes_g1",
  cCipherToBytesName = "cipher_to_bytes_g1",
  cPublicKeyToBytesName = "public_key_to_bytes_g1",
  cSecretKeyToBytesName = "secret_key_to_bytes_g1",
  cBytesToMessageName = "bytes_to_message_g1",
  cBytesToCipherName = "bytes_to_cipher_g1",
  cBytesToPublicKeyName = "bytes_to_public_key_g1",
  cBytesToSecretKeyName = "bytes_to_secret_key_g1",
  tagName = ''G1
  }
