use crate::{SerdeDeserialize, SerdeSerialize};
use aes::{
    cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit},
    Aes256,
};
use hmac::Hmac;
use rand::Rng;
use serde::{Deserializer, Serializer};
use std::{convert::TryInto, str::FromStr};
use thiserror::Error;

// Encryption
type CipherC = cbc::Encryptor<Aes256>;
// Decryption
type CipherD = cbc::Decryptor<Aes256>;

/// AES block size in bytes
pub const AES_BLOCK_SIZE: usize = 16;

/// A wrapper to make it less likely to abuse passwords.
pub struct Password {
    password: String,
}

impl From<String> for Password {
    fn from(password: String) -> Self { Password { password } }
}

impl FromStr for Password {
    type Err = <String as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> { Ok(Password { password: s.into() }) }
}

// Helpers for JSON serialization in base64 standard format.
fn as_base64<A: AsRef<[u8]>, S>(key: &A, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer, {
    serializer.serialize_str(&base64::encode(key.as_ref()))
}

fn from_base64<'de, D: Deserializer<'de>, X: From<Vec<u8>>>(des: D) -> Result<X, D::Error> {
    use serde::de::Error;
    let data = String::deserialize(des)?;
    let decoded = base64::decode(&data).map_err(|err| Error::custom(err.to_string()))?;
    Ok(X::from(decoded))
}

/// This is needed before Rust 1.48 due to lacking TryFrom instances for Vec.
fn from_base64_array<'de, D: Deserializer<'de>>(des: D) -> Result<[u8; AES_BLOCK_SIZE], D::Error> {
    use serde::de::Error;
    let data: Box<[u8]> = from_base64(des)?;
    let arr: Box<[u8; AES_BLOCK_SIZE]> = data
        .try_into()
        .map_err(|_| Error::custom("Data of incorrect length."))?;
    Ok(*arr)
}

#[derive(SerdeSerialize, SerdeDeserialize)]
/// Supported encryption methods.
pub enum EncryptionMethod {
    #[serde(rename = "AES-256")]
    Aes256,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
/// Supported key derivation methods.
pub enum KeyDerivationMethod {
    #[serde(rename = "PBKDF2WithHmacSHA256")]
    Pbkdf2Sha256,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
/// Metadata that enables decryption of some encrypted data provided an
/// a password is provided.
// This type is defined to be compatible with exports in the wallet, but
// it is not the best as it is. The encryption and key derivation methods
// themselves define other fields, such as the number of iterations and salt.
// A better modelling would be for this to be an enumeration.
pub struct EncryptionMetadata {
    #[serde(rename = "encryptionMethod")]
    encryption_method:     EncryptionMethod,
    #[serde(rename = "keyDerivationMethod")]
    key_derivation_method: KeyDerivationMethod,
    #[serde(rename = "iterations")]
    /// Number of iterations for the key derivation function.
    iterations:            u32,
    #[serde(
        rename = "salt",
        serialize_with = "as_base64",
        deserialize_with = "from_base64"
    )]
    /// Salt used for the key derivation process.
    salt:                  Vec<u8>,
    #[serde(
        rename = "initializationVector",
        serialize_with = "as_base64",
        deserialize_with = "from_base64_array"
    )]
    /// Initialization vector for AES CBC mode encryption.
    initialization_vector: [u8; AES_BLOCK_SIZE],
}

#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(transparent)]
/// A wrapper around a byte array to represent a ciphertext. JSON encodings are
/// in base64.
pub struct CipherText {
    #[serde(serialize_with = "as_base64", deserialize_with = "from_base64")]
    ct: Vec<u8>,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
/// Ciphertext together with metadata describing the encryption method.
pub struct EncryptedData {
    #[serde(rename = "metadata")]
    metadata:    EncryptionMetadata,
    #[serde(rename = "cipherText")]
    cipher_text: CipherText,
}

/// The number of rounds of the key derivation function to use for hashing the
/// password.
pub const NUM_ROUNDS: u32 = 100000;

/// Encrypt the given plaintext using the provided password.
/// This uses the AES256 cipher using PBKDF2SHA256 key derivation function
/// using a randomly sampled salt.
/// The number of rounds of the key derivation function is defined by the
/// `NUM_ROUNDS` constant.
pub fn encrypt<A: AsRef<[u8]>, R: Rng>(
    pass: &Password,
    plaintext: &A,
    csprng: &mut R,
) -> EncryptedData {
    // Derive the key for AES.
    // The key will be 256 bits, we are using sha256.
    let mut key = [0u8; 32];
    // We generate a random salt, 16 bytes, as recommended by NIST.
    let salt: [u8; 16] = csprng.gen();
    // generate the key and store it in the `key` array
    pbkdf2::pbkdf2::<Hmac<sha2::Sha256>>(pass.password.as_bytes(), &salt, NUM_ROUNDS, &mut key);

    // generate the initial block for the CBC AES mode.
    // The initialization vector must correspond to AES256 block size, which is 128
    // bits (16 bytes)
    let initialization_vector: [u8; AES_BLOCK_SIZE] = csprng.gen();
    // Construct the cipher.
    let cipher = CipherC::new((&key).into(), (&initialization_vector).into());
    let cipher_text = CipherText {
        ct: cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_ref()),
    };

    let metadata = EncryptionMetadata {
        encryption_method: EncryptionMethod::Aes256,
        key_derivation_method: KeyDerivationMethod::Pbkdf2Sha256,
        iterations: NUM_ROUNDS,
        salt: salt.into(),
        initialization_vector,
    };
    EncryptedData {
        metadata,
        cipher_text,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
/// Errors that can occur during AES decryption.
pub enum DecryptionError {
    /// Error during AES decryption.
    #[error("Decryption error.")]
    BlockMode,
}

/// Dual to the `encrypt` method.
pub fn decrypt(pass: &Password, et: &EncryptedData) -> Result<Vec<u8>, DecryptionError> {
    // Derive the key for AES.
    // The key will be 256 bits, we are using sha256.
    let mut key = [0u8; 32];
    // generate the key and store it in the `key` array
    pbkdf2::pbkdf2::<Hmac<sha2::Sha256>>(
        pass.password.as_bytes(),
        &et.metadata.salt,
        et.metadata.iterations,
        &mut key,
    );
    let cipher = CipherD::new((&key).into(), (&et.metadata.initialization_vector).into());
    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(&et.cipher_text.ct)
        .map_err(|_| DecryptionError::BlockMode)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypt_decrypt_success() {
        let pass = Password {
            password: "hello".into(),
        };
        let mut rng = rand::thread_rng();
        let plaintext = rng
            .sample_iter(rand::distributions::Uniform::new_inclusive(
                u8::MIN,
                u8::MAX,
            ))
            .take(1000)
            .collect::<Vec<u8>>();
        let et = encrypt(&pass, &plaintext, &mut rng);
        let decrypted = decrypt(&pass, &et);
        assert_eq!(Ok(plaintext), decrypted, "Decryption failed.");
    }
}
