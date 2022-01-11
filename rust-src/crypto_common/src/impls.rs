use anyhow::bail;
use byteorder::ReadBytesExt;

use ff::PrimeField;
use group::{CurveAffine, CurveProjective, EncodedPoint};
use pairing::bls12_381::{
    Fq12, FqRepr, Fr, FrRepr, G1Affine, G1Compressed, G2Affine, G2Compressed, G1, G2,
};
use std::convert::TryFrom;

use crate::serialize::*;

impl Deserial for Fr {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Fr> {
        let mut frrepr: FrRepr = FrRepr([0u64; 4]);
        // Read the scalar in big endian.
        for digit in frrepr.as_mut().iter_mut().rev() {
            *digit = source.get()?;
        }
        Ok(Fr::from_repr(frrepr)?)
    }
}

impl Serial for Fr {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let frpr = &self.into_repr();
        for a in frpr.as_ref().iter().rev() {
            a.serial(out);
        }
    }
}

impl Deserial for G1 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<G1> {
        let mut g = G1Compressed::empty();
        source.read_exact(g.as_mut())?;
        Ok(g.into_affine()?.into_projective())
    }
}

impl Serial for G1 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let g = self.into_affine().into_compressed();
        let g_bytes = g.as_ref();
        if let Err(e) = out.write_all(g_bytes) {
            panic!(
                "Precondition violated. Buffer should be safe to write {}.",
                e
            );
        }
    }
}

impl Deserial for G1Affine {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<G1Affine> {
        let mut g = G1Compressed::empty();
        source.read_exact(g.as_mut())?;
        Ok(g.into_affine()?)
    }
}

impl Serial for G1Affine {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let g = self.into_compressed();
        let g_bytes = g.as_ref();
        if let Err(e) = out.write_all(g_bytes) {
            panic!(
                "Precondition violated. Buffer should be safe to write {}.",
                e
            );
        }
    }
}

impl Deserial for G2 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<G2> {
        let mut g = G2Compressed::empty();
        source.read_exact(g.as_mut())?;
        Ok(g.into_affine()?.into_projective())
    }
}

impl Serial for G2 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let g = self.into_affine().into_compressed();
        let g_bytes = g.as_ref();
        if let Err(e) = out.write_all(g_bytes) {
            panic!(
                "Precondition violated. Buffer should be safe to write {}.",
                e
            );
        }
    }
}

impl Deserial for G2Affine {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<G2Affine> {
        let mut g = G2Compressed::empty();
        source.read_exact(g.as_mut())?;
        Ok(g.into_affine()?)
    }
}

impl Serial for G2Affine {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let g = self.into_compressed();
        let g_bytes = g.as_ref();
        if let Err(e) = out.write_all(g_bytes) {
            panic!(
                "Precondition violated. Buffer should be safe to write {}.",
                e
            );
        }
    }
}

/// This implementation is ad-hoc, using the fact that Fq12 is defined
/// via that specific tower of extensions (of degrees) 2 -> 3 -> 2,
/// and the specific representation of those fields.
/// We use big-endian representation all the way down to the field Fq.
impl Serial for Fq12 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        // coefficients in the extension F_6
        let c0_6 = self.c0;
        let c1_6 = self.c1;

        let coeffs = [
            // coefficients of c1_6 in the extension F_2
            c1_6.c2, c1_6.c1, c1_6.c0, // coefficients of c0_6 in the extension F_2
            c0_6.c2, c0_6.c1, c0_6.c0,
        ];
        for p in coeffs.iter() {
            let repr_c1 = FqRepr::from(p.c1);
            let repr_c0 = FqRepr::from(p.c0);
            for d in repr_c1.as_ref().iter() {
                d.serial(out);
            }
            for d in repr_c0.as_ref().iter() {
                d.serial(out);
            }
        }
    }
}

// Implementations for the dalek curve.

use ed25519_dalek::*;

impl Deserial for PublicKey {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let mut buf = [0u8; PUBLIC_KEY_LENGTH];
        source.read_exact(&mut buf)?;
        Ok(PublicKey::from_bytes(&buf)?)
    }
}

impl Serial for PublicKey {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_all(self.as_bytes())
            .expect("Writing to buffer should succeed.");
    }
}

impl Deserial for SecretKey {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let mut buf = [0u8; SECRET_KEY_LENGTH];
        source.read_exact(&mut buf)?;
        Ok(SecretKey::from_bytes(&buf)?)
    }
}

impl Serial for SecretKey {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_all(self.as_bytes())
            .expect("Writing to buffer should succeed.");
    }
}

impl Deserial for Keypair {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let mut buf = [0u8; KEYPAIR_LENGTH];
        source.read_exact(&mut buf)?;
        Ok(Keypair::from_bytes(&buf)?)
    }
}

impl Serial for Keypair {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_all(&self.to_bytes())
            .expect("Writing to buffer should succeed.");
    }
}

impl Deserial for Signature {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let mut buf = [0u8; SIGNATURE_LENGTH];
        source.read_exact(&mut buf)?;
        Ok(Signature::try_from(buf)?)
    }
}

impl Serial for Signature {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_all(&self.to_bytes())
            .expect("Writing to buffer should succeed.");
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
