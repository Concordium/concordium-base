use anyhow::bail;
use byteorder::ReadBytesExt;

use concordium_contracts_common::{constants::SHA256, hashes::HashBytes, NonZeroThresholdU8};

use super::serialize::*;

impl Serial for concordium_contracts_common::Timestamp {
    fn serial<B: Buffer>(&self, out: &mut B) { self.timestamp_millis().serial(out) }
}

impl Deserial for concordium_contracts_common::Timestamp {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let millis: u64 = source.get()?;
        Ok(Self::from_timestamp_millis(millis))
    }
}

// Implementations for the dalek curve.

use ed25519_dalek::*;

impl Deserial for VerifyingKey {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let mut buf = [0u8; PUBLIC_KEY_LENGTH];
        source.read_exact(&mut buf)?;
        Ok(VerifyingKey::from_bytes(&buf)?)
    }
}

impl Serial for VerifyingKey {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_all(self.as_bytes())
            .expect("Writing to buffer should succeed.");
    }
}

impl Deserial for SigningKey {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let mut buf = [0u8; KEYPAIR_LENGTH];
        source.read_exact(&mut buf)?;
        Ok(SigningKey::from_keypair_bytes(&buf)?)
    }
}

impl Serial for SigningKey {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_all(&self.to_bytes())
            .expect("Writing to buffer should succeed.");
    }
}

impl Deserial for Signature {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let mut buf = [0u8; SIGNATURE_LENGTH];
        source.read_exact(&mut buf)?;
        Ok(Signature::from(buf))
    }
}

impl Serial for Signature {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_all(&self.to_bytes())
            .expect("Writing to buffer should succeed.");
    }
}

impl<Kind> Deserial for NonZeroThresholdU8<Kind> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let threshold: u8 = source.get()?;
        let r = threshold.try_into()?;
        Ok(r)
    }
}

impl<Kind> Serial for NonZeroThresholdU8<Kind> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let thr = u8::from(*self);
        thr.serial(out)
    }
}

// implementations for the Either type
use either::*;

impl<L: Deserial, R: Deserial> Deserial for Either<L, R> {
    fn deserial<X: ReadBytesExt>(source: &mut X) -> ParseResult<Self> {
        let l: u8 = source.get()?;
        if l == 0 {
            Ok(Either::Left(source.get()?))
        } else if l == 1 {
            Ok(Either::Right(source.get()?))
        } else {
            bail!("Unknown variant {}", l)
        }
    }
}

impl<L: Serial, R: Serial> Serial for Either<L, R> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            Either::Left(ref left) => {
                out.put(&0u8);
                out.put(left);
            }
            Either::Right(ref right) => {
                out.put(&1u8);
                out.put(right);
            }
        }
    }
}

use std::rc::Rc;
/// Use the underlying type's instance.
impl<T: Serial> Serial for Rc<T> {
    fn serial<B: Buffer>(&self, out: &mut B) { out.put(self.as_ref()) }
}

/// Use the underlying type's instance. Note that serial + deserial does not
/// preserve sharing. It will allocate a new copy of the structure.
impl<T: Deserial> Deserial for Rc<T> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> { Ok(Rc::new(source.get()?)) }
}

/// Deserialization is strict. It only accepts `0` or `1` tags.
impl<T: Deserial> Deserial for Option<T> {
    fn deserial<X: ReadBytesExt>(source: &mut X) -> ParseResult<Self> {
        let l: u8 = source.get()?;
        if l == 0 {
            Ok(None)
        } else if l == 1 {
            Ok(Some(source.get()?))
        } else {
            bail!("Unknown variant {}", l)
        }
    }
}

/// `None` is serialized as `0u8`, `Some(v)` is serialized by prepending `1u8`
/// to the serialization of `v`.
impl<T: Serial> Serial for Option<T> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            None => {
                out.put(&0u8);
            }
            Some(ref x) => {
                out.put(&1u8);
                out.put(x);
            }
        }
    }
}

impl<Purpose> Serial for HashBytes<Purpose> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_all(&self.bytes)
            .expect("Writing to buffer always succeeds.");
    }
}

impl<Purpose> Deserial for HashBytes<Purpose> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let mut bytes = [0u8; SHA256];
        source.read_exact(&mut bytes)?;
        Ok(bytes.into())
    }
}
