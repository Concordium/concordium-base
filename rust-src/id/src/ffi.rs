use crate::{
    chain::{self, CDIVerificationError},
    types::*,
};
use curve_arithmetic::curve_arithmetic::*;
use pairing::bls12_381::{Bls12, G1};
use pedersen_scheme::key::CommitmentKey as PedersenKey;
use std::{error::Error as StdError, fmt, io::Cursor, slice, str::FromStr};

use byteorder::ReadBytesExt;
use failure::Error;
use ffi_helpers::*;
use libc::size_t;
use num::bigint::{BigUint, ParseBigIntError};
use rand::thread_rng;
use serde_json;

/// Concrete attribute kinds
#[derive(Copy, Clone, PartialEq, Eq)]
// represented as big-endian bytes.
pub struct AttributeKind([u8; 31]);

#[derive(Debug)]
pub enum ParseAttributeError {
    IntDecodingFailed(ParseBigIntError),
    ValueTooLarge,
}

impl From<ParseBigIntError> for ParseAttributeError {
    fn from(err: ParseBigIntError) -> Self { ParseAttributeError::IntDecodingFailed(err) }
}

impl StdError for ParseAttributeError {
    fn description(&self) -> &str {
        match self {
            ParseAttributeError::IntDecodingFailed(ref x) => x.description(),
            ParseAttributeError::ValueTooLarge => "Value out of range.",
        }
    }
}

impl fmt::Display for ParseAttributeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseAttributeError::IntDecodingFailed(ref e) => e.fmt(f),
            ParseAttributeError::ValueTooLarge => "Value out of range.".fmt(f),
        }
    }
}

impl FromStr for AttributeKind {
    type Err = ParseAttributeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let buint = BigUint::from_str(s)?;
        if buint.bits() <= 31 * 8 {
            let bytes = buint.to_bytes_be();
            let mut buf = [0; 31];
            buf[31 - bytes.len()..].copy_from_slice(&bytes);
            Ok(AttributeKind(buf))
        } else {
            Err(ParseAttributeError::ValueTooLarge)
        }
    }
}

impl fmt::Display for AttributeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttributeKind(x) => write!(f, "{}", BigUint::from_bytes_be(x)),
        }
    }
}

impl From<u64> for AttributeKind {
    fn from(x: u64) -> Self {
        let mut buf = [0u8; 31];
        buf[23..].copy_from_slice(&x.to_be_bytes());
        AttributeKind(buf)
    }
}

impl Attribute<<G1 as Curve>::Scalar> for AttributeKind {
    fn to_field_element(&self) -> <G1 as Curve>::Scalar {
        let AttributeKind(x) = self;
        let mut buf = [0u8; 32];
        buf[1..].copy_from_slice(x);
        <G1 as Curve>::bytes_to_scalar(&mut Cursor::new(&buf)).unwrap()
    }

    fn to_bytes(&self) -> Box<[u8]> {
        let AttributeKind(x) = self;
        let bytes = (BigUint::from_bytes_be(x)).to_bytes_be();
        let l = bytes.len();
        let mut buf = vec![l as u8; l + 1];
        buf[1..].copy_from_slice(&bytes);
        buf.into_boxed_slice()
    }

    fn from_bytes(cur: &mut Cursor<&[u8]>) -> Option<Self> {
        let l = cur.read_u8().ok()?;
        if l <= 31 {
            let mut r = [0u8; 31];
            for i in (31 - l)..31 {
                r[i as usize] = cur.read_u8().ok()?;
            }
            Some(AttributeKind(r))
        } else {
            None
        }
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
        return -7;
    }
    if ip_info_ptr.is_null() {
        return -8;
    }

    let acc_keys = if acc_keys_ptr.is_null() {
        None
    } else {
        let acc_key_bytes = slice_from_c_bytes!(acc_keys_ptr, acc_keys_len as usize);
        if let Some(acc_keys) = AccountKeys::from_bytes(&mut Cursor::new(&acc_key_bytes)) {
            Some(acc_keys)
        } else {
            return -10;
        }
    };

    let cdi_bytes = slice_from_c_bytes!(cdi_ptr, cdi_len as usize);
    match CredDeploymentInfo::<Bls12, G1, AttributeKind>::from_bytes(&mut Cursor::new(&cdi_bytes)) {
        None => -9,
        Some(cdi) => {
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
            }
        }
    }
}

macro_derive_from_bytes!(
    pedersen_key_from_bytes,
    PedersenKey<G1>,
    PedersenKey::from_bytes
);
macro_derive_to_bytes!(pedersen_key_to_bytes, PedersenKey<G1>);
macro_free_ffi!(pedersen_key_free, PedersenKey<G1>);

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn pedersen_key_gen() -> *const PedersenKey<G1> {
    let mut csprng = thread_rng();
    Box::into_raw(Box::new(PedersenKey::generate(&mut csprng)))
}

macro_derive_from_bytes!(
    ps_sig_key_from_bytes,
    ps_sig::PublicKey<Bls12>,
    ps_sig::PublicKey::from_bytes
);
macro_derive_to_bytes!(ps_sig_key_to_bytes, ps_sig::PublicKey<Bls12>);
macro_free_ffi!(ps_sig_key_free, ps_sig::PublicKey<Bls12>);
macro_generate_commitment_key!(
    ps_sig_key_gen,
    ps_sig::PublicKey<Bls12>,
    ps_sig::PublicKey::arbitrary
);

// derive conversion methods for IpInfo to be used in Haskell.
macro_free_ffi!(ip_info_free, IpInfo<Bls12, G1>);
macro_derive_from_bytes!(ip_info_from_bytes, IpInfo<Bls12, G1>, |x| IpInfo::from_bytes(x).ok_or(()));
macro_derive_to_bytes!(ip_info_to_bytes, IpInfo<Bls12, G1>);
macro_derive_from_json!(ip_info_from_json, IpInfo<Bls12, G1>, IpInfo::from_json);
macro_derive_to_json!(ip_info_to_json, IpInfo<Bls12, G1>);

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn ip_info_ip_identity(ip_info_ptr: *const IpInfo<Bls12, G1>) -> u32 {
    let ip_info = from_ptr!(ip_info_ptr);
    ip_info.ip_identity.0
}

// derive conversion methods for GlobalContext to be used in Haskell
macro_free_ffi!(global_context_free, GlobalContext<G1>);
macro_derive_from_bytes!(global_context_from_bytes, GlobalContext<G1>, |x| {
    GlobalContext::from_bytes(x).ok_or(())
});
macro_derive_to_bytes!(global_context_to_bytes, GlobalContext<G1>);
macro_derive_from_json!(
    global_context_from_json,
    GlobalContext<G1>,
    GlobalContext::from_json
);
macro_derive_to_json!(global_context_to_json, GlobalContext<G1>);

pub struct ElgamalGenerator(G1);

impl ElgamalGenerator {
    pub fn to_bytes(&self) -> Box<[u8]> { self.0.curve_to_bytes() }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Result<Self, Error> {
        let r = G1::bytes_to_curve(cur)?;
        Ok(ElgamalGenerator(r))
    }

    pub fn generate() -> Self { ElgamalGenerator(G1::generate(&mut thread_rng())) }
}

macro_derive_from_bytes!(
    elgamal_gen_from_bytes,
    ElgamalGenerator,
    ElgamalGenerator::from_bytes
);
macro_derive_to_bytes!(elgamal_gen_to_bytes, ElgamalGenerator);
macro_free_ffi!(elgamal_gen_free, ElgamalGenerator);
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn elgamal_gen_gen() -> *const ElgamalGenerator {
    Box::into_raw(Box::new(ElgamalGenerator::generate()))
}

macro_derive_from_bytes!(
    elgamal_pub_key_from_bytes,
    elgamal::PublicKey<G1>,
    elgamal::PublicKey::from_bytes
);
macro_derive_to_bytes!(elgamal_pub_key_to_bytes, elgamal::PublicKey<G1>);
macro_free_ffi!(elgamal_pub_key_free, elgamal::PublicKey<G1>);
#[no_mangle]
pub extern "C" fn elgamal_pub_key_gen() -> *const elgamal::PublicKey<G1> {
    let sk = elgamal::secret::SecretKey::generate(&mut thread_rng());
    Box::into_raw(Box::new(elgamal::PublicKey::from(&sk)))
}

macro_derive_from_bytes!(
    elgamal_cipher_from_bytes,
    elgamal::cipher::Cipher<G1>,
    elgamal::cipher::Cipher::from_bytes
);
macro_derive_to_bytes!(elgamal_cipher_to_bytes, elgamal::cipher::Cipher<G1>);
macro_free_ffi!(elgamal_cipher_free, elgamal::cipher::Cipher<G1>);
#[no_mangle]
pub extern "C" fn elgamal_cipher_gen() -> *const elgamal::cipher::Cipher<G1> {
    let mut csprng = thread_rng();
    Box::into_raw(Box::new(elgamal::cipher::Cipher::generate(&mut csprng)))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{account_holder::*, identity_provider::*, secret_sharing::Threshold};
    use dodis_yampolskiy_prf::secret as prf;
    use eddsa_ed25519 as ed25519;
    use either::Either::Left;
    use elgamal::{public::PublicKey, secret::SecretKey};
    use pairing::bls12_381::Bls12;
    use pedersen_scheme::{key as pedersen_key, Value as PedersenValue};
    use ps_sig;
    use std::collections::btree_map::BTreeMap;

    type ExampleAttributeList = AttributeList<<Bls12 as Pairing>::ScalarField, AttributeKind>;
    type ExampleCurve = G1;
    #[test]
    fn test_pipeline() {
        let mut csprng = thread_rng();

        let secret = ExampleCurve::generate_scalar(&mut csprng);
        let public = ExampleCurve::one_point().mul_by_scalar(&secret);
        let ah_info = CredentialHolderInfo::<ExampleCurve> {
            id_ah:   "ACCOUNT_HOLDER".to_owned(),
            id_cred: IdCredentials {
                id_cred_sec: PedersenValue { value: secret },
                id_cred_pub: public,
            },
        };

        let ip_secret_key = ps_sig::secret::SecretKey::<Bls12>::generate(10, &mut csprng);
        let ip_public_key = ps_sig::public::PublicKey::from(&ip_secret_key);

        let ar1_secret_key = SecretKey::generate(&mut csprng);
        let ar1_public_key = PublicKey::from(&ar1_secret_key);
        let ar1_info = ArInfo::<G1> {
            ar_identity:    ArIdentity(1),
            ar_description: "A good AR".to_string(),
            ar_public_key:  ar1_public_key,
        };

        let ar2_secret_key = SecretKey::generate(&mut csprng);
        let ar2_public_key = PublicKey::from(&ar2_secret_key);
        let ar2_info = ArInfo::<G1> {
            ar_identity:    ArIdentity(2),
            ar_description: "A nice AR".to_string(),
            ar_public_key:  ar2_public_key,
        };

        let ar3_secret_key = SecretKey::generate(&mut csprng);
        let ar3_public_key = PublicKey::from(&ar3_secret_key);
        let ar3_info = ArInfo::<G1> {
            ar_identity:    ArIdentity(3),
            ar_description: "Weird AR".to_string(),
            ar_public_key:  ar3_public_key,
        };

        let ar4_secret_key = SecretKey::generate(&mut csprng);
        let ar4_public_key = PublicKey::from(&ar4_secret_key);
        let ar4_info = ArInfo::<G1> {
            ar_identity:    ArIdentity(4),
            ar_description: "Ok AR".to_string(),
            ar_public_key:  ar4_public_key,
        };

        let ar_ck = pedersen_key::CommitmentKey::generate(&mut csprng);
        let dlog_base = <G1 as Curve>::one_point();

        let ip_info = IpInfo {
            ip_identity: IpIdentity(88),
            ip_description: "IP88".to_string(),
            ip_verify_key: ip_public_key,
            dlog_base,
            ar_info: (vec![ar1_info, ar2_info, ar3_info, ar4_info], ar_ck),
        };

        let prf_key = prf::SecretKey::generate(&mut csprng);

        let variant = 0;
        let expiry_date = 123123123;
        let alist = vec![AttributeKind::from(55), AttributeKind::from(313123333)];

        let aci = AccCredentialInfo {
            acc_holder_info: ah_info,
            prf_key,
            attributes: ExampleAttributeList {
                variant,
                expiry: expiry_date,
                alist,
                _phantom: Default::default(),
            },
        };

        let context = make_context_from_ip_info(
            ip_info.clone(),
            (
                vec![ArIdentity(1), ArIdentity(2), ArIdentity(4)],
                Threshold(2),
            ),
        );
        let (pio, randomness) = generate_pio(&context, &aci);

        let sig_ok = verify_credentials(&pio, &ip_info, &ip_secret_key);

        // First test, check that we have a valid signature.
        assert!(sig_ok.is_ok());

        let ip_sig = sig_ok.unwrap();
        let global_ctx = GlobalContext::<G1> {
            dlog_base_chain:         ExampleCurve::one_point(),
            on_chain_commitment_key: pedersen_key::CommitmentKey::generate(&mut csprng),
        };

        let policy = Policy {
            variant,
            expiry: expiry_date,
            policy_vec: {
                let mut tree = BTreeMap::new();
                tree.insert(0u16, AttributeKind::from(55));
                tree
            },
            _phantom: Default::default(),
        };

        let wrong_policy = Policy {
            variant,
            expiry: expiry_date,
            policy_vec: {
                let mut tree = BTreeMap::new();
                tree.insert(0u16, AttributeKind::from(5));
                tree
            },
            _phantom: Default::default(),
        };

        let mut keys = BTreeMap::new();
        keys.insert(KeyIndex(0), ed25519::generate_keypair());
        keys.insert(KeyIndex(1), ed25519::generate_keypair());
        keys.insert(KeyIndex(2), ed25519::generate_keypair());

        let acc_data = AccountData {
            keys,
            existing: Left(SignatureThreshold(2)),
        };

        let cdi = generate_cdi(
            &ip_info,
            &global_ctx,
            &aci,
            &pio,
            0,
            &ip_sig,
            &policy,
            &acc_data,
            &randomness,
        );

        let wrong_cdi = generate_cdi(
            &ip_info,
            &global_ctx,
            &aci,
            &pio,
            0,
            &ip_sig,
            &wrong_policy,
            &acc_data,
            &randomness,
        );

        let cdi_bytes = cdi.to_bytes();
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
        let wrong_cdi_bytes = &*wrong_cdi.to_bytes();
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
