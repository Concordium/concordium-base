use crate::{
    chain::{self, CDIVerificationError},
    types::*,
};
use crypto_common::*;
use curve_arithmetic::*;
use pairing::bls12_381::{Bls12, G1};
use pedersen_scheme::key::CommitmentKey as PedersenKey;

use std::{fmt, io::Cursor, slice, str::FromStr};

use byteorder::ReadBytesExt;
use crypto_common::size_t;
use ffi_helpers::*;
use rand::thread_rng;
use serde::{
    de, de::Visitor, Deserialize as SerdeDeserialize, Deserializer, Serialize as SerdeSerialize,
    Serializer,
};

/// Concrete attribute kinds
#[derive(Clone, PartialEq, Eq, Debug)]
// All currently supported attributes are string values.
pub struct AttributeKind(pub String);

impl SerdeSerialize for AttributeKind {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.0)
    }
}

impl<'de> SerdeDeserialize<'de> for AttributeKind {
    fn deserialize<D: Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
        des.deserialize_str(AttributeKindVisitor)
    }
}

pub struct AttributeKindVisitor;

impl<'de> Visitor<'de> for AttributeKindVisitor {
    type Value = AttributeKind;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "A string less than 31 bytes when decoded.")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        if v.as_bytes().len() > 31 {
            Err(de::Error::custom("Value too big."))
        } else {
            Ok(AttributeKind(v.to_string()))
        }
    }
}

impl Deserial for AttributeKind {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<Self> {
        let len: u8 = source.get()?;
        if len <= 31 {
            let mut buf = vec![0u8; len as usize];
            source.read_exact(&mut buf)?;
            Ok(AttributeKind(String::from_utf8(buf)?))
        } else {
            bail!("Attributes can be at most 31 bytes.")
        }
    }
}

impl Serial for AttributeKind {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.put(&(self.0.as_bytes().len() as u8));
        out.write_all(self.0.as_bytes())
            .expect("Writing to buffer should succeed.");
    }
}

#[derive(Debug)]
pub enum ParseAttributeError {
    ValueTooLarge,
}

impl fmt::Display for ParseAttributeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseAttributeError::ValueTooLarge => "Value out of range.".fmt(f),
        }
    }
}

impl FromStr for AttributeKind {
    type Err = ParseAttributeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.as_bytes().len() <= 31 {
            Ok(AttributeKind(s.to_string()))
        } else {
            Err(ParseAttributeError::ValueTooLarge)
        }
    }
}

impl fmt::Display for AttributeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

impl From<u64> for AttributeKind {
    fn from(x: u64) -> Self { AttributeKind(x.to_string()) }
}

impl Attribute<<G1 as Curve>::Scalar> for AttributeKind {
    fn to_field_element(&self) -> <G1 as Curve>::Scalar {
        let mut buf = [0u8; 32];
        let len = self.0.as_bytes().len();
        buf[1 + (31 - len)..].copy_from_slice(self.0.as_bytes());
        buf[0] = len as u8; // this should be valid because len <= 31 so the first two bits will be unset
        <<G1 as Curve>::Scalar as Deserial>::deserial(&mut Cursor::new(&buf))
            .expect("31 bytes + length fits into a scalar.")
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn verify_cdi_ffi(
    gc_ptr: *const GlobalContext<G1>,
    ip_info_ptr: *const IpInfo<Bls12, G1>,
    acc_keys_ptr: *const u8,
    acc_keys_len: size_t,
    cdi_ptr: *const u8,
    cdi_len: size_t,
) -> i32 {
    if gc_ptr.is_null() {
        return -9;
    }
    if ip_info_ptr.is_null() {
        return -10;
    }

    let acc_keys = if acc_keys_ptr.is_null() {
        None
    } else {
        let acc_key_bytes = slice_from_c_bytes!(acc_keys_ptr, acc_keys_len as usize);
        if let Ok(acc_keys) = AccountKeys::deserial(&mut Cursor::new(&acc_key_bytes)) {
            Some(acc_keys)
        } else {
            return -12;
        }
    };

    let cdi_bytes = slice_from_c_bytes!(cdi_ptr, cdi_len as usize);
    match CredDeploymentInfo::<Bls12, G1, AttributeKind>::deserial(&mut Cursor::new(&cdi_bytes)) {
        Err(err) => {
            eprintln!("{}", err);
            -11
        }
        Ok(cdi) => {
            match chain::verify_cdi::<Bls12, G1, AttributeKind>(
                from_ptr!(gc_ptr),
                from_ptr!(ip_info_ptr),
                acc_keys.as_ref(),
                &cdi,
            ) {
                Ok(()) => 1, // verification succeeded
                Err(CDIVerificationError::RegId) => -1,
                Err(CDIVerificationError::IdCredPub) => -2,
                Err(CDIVerificationError::Signature) => -3,
                Err(CDIVerificationError::Dlog) => -4,
                Err(CDIVerificationError::Policy) => -5,
                Err(CDIVerificationError::AR) => -6,
                Err(CDIVerificationError::AccountOwnership) => -7,
                Err(CDIVerificationError::Proof) => -8,
            }
        }
    }
}

macro_derive_from_bytes!(
    Box
    pedersen_key_from_bytes,
    PedersenKey<G1>
);
macro_derive_to_bytes!(Box pedersen_key_to_bytes, PedersenKey<G1>);
macro_free_ffi!(Box pedersen_key_free, PedersenKey<G1>);

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn pedersen_key_gen() -> *mut PedersenKey<G1> {
    let mut csprng = thread_rng();
    Box::into_raw(Box::new(PedersenKey::generate(&mut csprng)))
}

macro_derive_from_bytes!(
    Box
    ps_sig_key_from_bytes,
    ps_sig::PublicKey<Bls12>
);
macro_derive_to_bytes!(Box ps_sig_key_to_bytes, ps_sig::PublicKey<Bls12>);
macro_free_ffi!(Box ps_sig_key_free, ps_sig::PublicKey<Bls12>);
macro_generate_commitment_key!(
    ps_sig_key_gen,
    ps_sig::PublicKey<Bls12>,
    ps_sig::PublicKey::arbitrary
);

// derive conversion methods for IpInfo to be used in Haskell.
macro_free_ffi!(Box ip_info_free, IpInfo<Bls12, G1>);
macro_derive_from_bytes!(Box ip_info_from_bytes, IpInfo<Bls12, G1>);
macro_derive_to_bytes!(Box ip_info_to_bytes, IpInfo<Bls12, G1>);
macro_derive_from_json!(ip_info_from_json, IpInfo<Bls12, G1>);
macro_derive_to_json!(ip_info_to_json, IpInfo<Bls12, G1>);

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn ip_info_ip_identity(ip_info_ptr: *const IpInfo<Bls12, G1>) -> u32 {
    let ip_info = from_ptr!(ip_info_ptr);
    ip_info.ip_identity.0
}

// derive conversion methods for GlobalContext to be used in Haskell
macro_free_ffi!(Box global_context_free, GlobalContext<G1>);
macro_derive_from_bytes!(Box global_context_from_bytes, GlobalContext<G1>);
macro_derive_to_bytes!(Box global_context_to_bytes, GlobalContext<G1>);
macro_derive_from_json!(global_context_from_json, GlobalContext<G1>);
macro_derive_to_json!(global_context_to_json, GlobalContext<G1>);

#[derive(Serialize)]
pub struct ElgamalGenerator(G1);

impl ElgamalGenerator {
    pub fn generate() -> Self { ElgamalGenerator(G1::generate(&mut thread_rng())) }
}

macro_derive_from_bytes!(
    Box elgamal_gen_from_bytes,
    ElgamalGenerator
);
macro_derive_to_bytes!(Box elgamal_gen_to_bytes, ElgamalGenerator);
macro_free_ffi!(Box elgamal_gen_free, ElgamalGenerator);
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn elgamal_gen_gen() -> *mut ElgamalGenerator {
    Box::into_raw(Box::new(ElgamalGenerator::generate()))
}

macro_derive_from_bytes!(
    Box elgamal_pub_key_from_bytes,
    elgamal::PublicKey<G1>
);
macro_derive_to_bytes!(Box elgamal_pub_key_to_bytes, elgamal::PublicKey<G1>);
macro_free_ffi!(Box elgamal_pub_key_free, elgamal::PublicKey<G1>);
#[no_mangle]
pub extern "C" fn elgamal_pub_key_gen() -> *mut elgamal::PublicKey<G1> {
    let sk = elgamal::secret::SecretKey::generate_all(&mut thread_rng());
    Box::into_raw(Box::new(elgamal::PublicKey::from(&sk)))
}

macro_derive_from_bytes!(
    Box elgamal_cipher_from_bytes,
    elgamal::cipher::Cipher<G1>
);
macro_derive_to_bytes!(Box elgamal_cipher_to_bytes, elgamal::cipher::Cipher<G1>);
macro_free_ffi!(Box elgamal_cipher_free, elgamal::cipher::Cipher<G1>);
#[no_mangle]
pub extern "C" fn elgamal_cipher_gen() -> *mut elgamal::cipher::Cipher<G1> {
    let mut csprng = thread_rng();
    Box::into_raw(Box::new(elgamal::cipher::Cipher::generate(&mut csprng)))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{account_holder::*, identity_provider::*, secret_sharing::Threshold, test::*};
    use dodis_yampolskiy_prf::secret as prf;
    use ed25519_dalek as ed25519;
    use either::Either::Left;
    use pairing::bls12_381::Bls12;
    use pedersen_scheme::key as pedersen_key;
    use std::{collections::btree_map::BTreeMap, convert::TryFrom};

    type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, AttributeKind>;
    type ExampleCurve = G1;
    #[test]
    fn test_pipeline() {
        let mut csprng = thread_rng();

        let ah_info = CredentialHolderInfo::<ExampleCurve> {
            id_cred: IdCredentials::generate(&mut csprng),
        };

        // Create IP
        let max_attrs = 10;
        let num_ars = 4;
        let mut csprng = thread_rng();
        let (
            IpData {
                public_ip_info: ip_info,
                ip_secret_key,
                metadata: _,
            },
            _,
        ) = test_create_ip_info(&mut csprng, num_ars, max_attrs);

        let prf_key = prf::SecretKey::generate(&mut csprng);

        let alist = {
            let mut alist = BTreeMap::new();
            alist.insert(AttributeTag::from(0u8), AttributeKind::from(55));
            alist.insert(AttributeTag::from(1u8), AttributeKind::from(313_123_333));
            alist
        };

        let aci = AccCredentialInfo {
            cred_holder_info: ah_info,
            prf_key,
        };

        let valid_to = YearMonth::try_from(2022 << 8 | 5).unwrap(); // May 2022
        let created_at = YearMonth::try_from(2020 << 8 | 5).unwrap(); // May 2020
        let alist = ExampleAttributeList {
            valid_to,
            created_at,
            max_accounts: 238,
            alist,
            _phantom: Default::default(),
        };

        let context = make_context_from_ip_info(ip_info.clone(), ChoiceArParameters {
            ar_identities: vec![ArIdentity(0), ArIdentity(1), ArIdentity(2)],
            threshold:     Threshold(2),
        })
        .expect("The constructed ARs are valid.");
        let (pio, randomness) =
            generate_pio(&context, &aci).expect("Creating the credential should succeed.");

        let sig_ok = verify_credentials(&pio, &ip_info, &alist, &ip_secret_key);

        // First test, check that we have a valid signature.
        assert!(sig_ok.is_ok());

        let ip_sig = sig_ok.unwrap();
        let global_ctx = GlobalContext::<G1> {
            on_chain_commitment_key: pedersen_key::CommitmentKey::generate(&mut csprng),
        };

        let policy = Policy {
            valid_to,
            created_at,
            policy_vec: {
                let mut tree = BTreeMap::new();
                tree.insert(AttributeTag::from(0u8), AttributeKind::from(55));
                tree
            },
            _phantom: Default::default(),
        };

        let wrong_policy = Policy {
            valid_to,
            created_at,
            policy_vec: {
                let mut tree = BTreeMap::new();
                tree.insert(AttributeTag::from(0u8), AttributeKind::from(5));
                tree
            },
            _phantom: Default::default(),
        };

        let mut keys = BTreeMap::new();
        keys.insert(KeyIndex(0), ed25519::Keypair::generate(&mut csprng));
        keys.insert(KeyIndex(1), ed25519::Keypair::generate(&mut csprng));
        keys.insert(KeyIndex(2), ed25519::Keypair::generate(&mut csprng));

        let acc_data = AccountData {
            keys,
            existing: Left(SignatureThreshold(2)),
        };

        let id_use_data = IdObjectUseData { aci, randomness };

        let id_object = IdentityObject {
            pre_identity_object: pio,
            alist,
            signature: ip_sig,
        };

        let cdi = create_credential(
            &ip_info,
            &global_ctx,
            &id_object,
            &id_use_data,
            0,
            &policy,
            &acc_data,
        )
        .expect("Should generate the credential successfully.");

        let wrong_cdi = create_credential(
            &ip_info,
            &global_ctx,
            &id_object,
            &id_use_data,
            0,
            &wrong_policy,
            &acc_data,
        )
        .expect("Should generate the credential successfully.");

        let cdi_bytes = to_bytes(&cdi);
        let cdi_bytes_len = cdi_bytes.len() as size_t;

        let gc_ptr = Box::into_raw(Box::new(global_ctx));
        let ip_info_ptr = Box::into_raw(Box::new(ip_info));

        let cdi_check = verify_cdi_ffi(
            gc_ptr,
            ip_info_ptr,
            std::ptr::null(),
            0,
            cdi_bytes.as_ptr(),
            cdi_bytes_len,
        );
        assert_eq!(cdi_check, 1);
        let wrong_cdi_bytes = to_bytes(&wrong_cdi);
        let wrong_cdi_bytes_len = wrong_cdi_bytes.len() as size_t;
        let wrong_cdi_check = verify_cdi_ffi(
            gc_ptr,
            ip_info_ptr,
            std::ptr::null(),
            0,
            wrong_cdi_bytes.as_ptr(),
            wrong_cdi_bytes_len,
        );
        assert_ne!(wrong_cdi_check, 1);
    }
}
