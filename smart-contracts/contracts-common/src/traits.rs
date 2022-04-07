use crate::types::*;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::{default::Default, mem::MaybeUninit, slice};

/// This is essentially equivalent to the
/// [SeekFrom](https://doc.rust-lang.org/std/io/enum.SeekFrom.html) type from
/// the rust standard library, but reproduced here to avoid dependency on
/// `std::io`, as well as to use 32-bit integers to specify positions. This
/// saves some computation and space, and is adequate for the kind of data sizes
/// that are possible in smart contracts.
pub enum SeekFrom {
    Start(u32),
    End(i32),
    Current(i32),
}

/// The `Seek` trait provides a cursor which can be moved within a stream of
/// bytes. This is essentially a copy of
/// [std::io::Seek](https://doc.rust-lang.org/std/io/trait.Seek.html), but
/// avoiding its dependency on `std::io::Error`, and the associated code size
/// increase. Additionally, the positions are expressed in terms of 32-bit
/// integers since this is adequate for the sizes of data in smart contracts.
pub trait Seek {
    type Err;
    /// Seek to the new position. If successful, return the new position from
    /// the beginning of the stream.
    fn seek(&mut self, pos: SeekFrom) -> Result<u32, Self::Err>;
}

/// Reads `n` bytes from a given `source` without initializing the byte array
/// beforehand using MaybeUninit.
macro_rules! read_n_bytes {
    ($n:expr, $source:tt) => {{
        let mut bytes: MaybeUninit<[u8; $n]> = MaybeUninit::uninit();
        let write_bytes = unsafe { slice::from_raw_parts_mut(bytes.as_mut_ptr() as *mut u8, $n) };
        $source.read_exact(write_bytes)?;
        unsafe { bytes.assume_init() }
    }};
}

/// The `Read` trait provides a means of reading from byte streams.
pub trait Read {
    /// Read a number of bytes into the provided buffer. The returned value is
    /// `Ok(n)` if a read was successful, and `n` bytes were read (`n` could be
    /// 0).
    fn read(&mut self, buf: &mut [u8]) -> ParseResult<usize>;

    /// Read exactly the required number of bytes. If not enough bytes could be
    /// read the function returns `Err(_)`, and the contents of the given buffer
    /// is unspecified.
    fn read_exact(&mut self, buf: &mut [u8]) -> ParseResult<()> {
        let mut start = 0;
        while start < buf.len() {
            match self.read(&mut buf[start..]) {
                Ok(0) => break,
                Ok(n) => {
                    start += n;
                }
                Err(_e) => return Err(Default::default()),
            }
        }
        if start == buf.len() {
            Ok(())
        } else {
            Err(Default::default())
        }
    }

    /// Read a `u64` in little-endian format.
    fn read_u64(&mut self) -> ParseResult<u64> {
        let bytes = read_n_bytes!(8, self);
        Ok(u64::from_le_bytes(bytes))
    }

    /// Read a `u32` in little-endian format.
    fn read_u32(&mut self) -> ParseResult<u32> {
        let bytes = read_n_bytes!(4, self);
        Ok(u32::from_le_bytes(bytes))
    }

    /// Read a `u16` in little-endian format.
    fn read_u16(&mut self) -> ParseResult<u16> {
        let bytes = read_n_bytes!(2, self);
        Ok(u16::from_le_bytes(bytes))
    }

    /// Read a `u8`.
    fn read_u8(&mut self) -> ParseResult<u8> {
        let bytes = read_n_bytes!(1, self);
        Ok(u8::from_le_bytes(bytes))
    }

    /// Read a `i64` in little-endian format.
    fn read_i64(&mut self) -> ParseResult<i64> {
        let bytes = read_n_bytes!(8, self);
        Ok(i64::from_le_bytes(bytes))
    }

    /// Read a `i32` in little-endian format.
    fn read_i32(&mut self) -> ParseResult<i32> {
        let bytes = read_n_bytes!(4, self);
        Ok(i32::from_le_bytes(bytes))
    }

    /// Read a `i16` in little-endian format.
    fn read_i16(&mut self) -> ParseResult<i16> {
        let bytes = read_n_bytes!(2, self);
        Ok(i16::from_le_bytes(bytes))
    }

    /// Read a `i32` in little-endian format.
    fn read_i8(&mut self) -> ParseResult<i8> {
        let bytes = read_n_bytes!(1, self);
        Ok(i8::from_le_bytes(bytes))
    }

    /// Load an array of the given size.
    fn read_array<const N: usize>(&mut self) -> ParseResult<[u8; N]> { Ok(read_n_bytes!(N, self)) }
}

/// The `Write` trait provides functionality for writing to byte streams.
pub trait Write {
    type Err: Default;
    /// Try to write the given buffer into the output stream. If writes are
    /// successful returns the number of bytes written.
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Err>;

    /// Attempt to write the entirety of the buffer to the output by repeatedly
    /// calling `write` until either no more output can written, or writing
    /// fails.
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Err> {
        let mut start = 0;
        while start < buf.len() {
            match self.write(&buf[start..]) {
                Ok(n) if n > 0 => start += n,
                _ => return Err(Default::default()),
            }
        }
        Ok(())
    }

    /// Write a single byte to the output.
    fn write_u8(&mut self, x: u8) -> Result<(), Self::Err> { self.write_all(&x.to_le_bytes()) }

    /// Write a `u16` in little endian.
    fn write_u16(&mut self, x: u16) -> Result<(), Self::Err> { self.write_all(&x.to_le_bytes()) }

    /// Write a `u32` in little endian.
    fn write_u32(&mut self, x: u32) -> Result<(), Self::Err> { self.write_all(&x.to_le_bytes()) }

    /// Write a `u64` in little endian.
    fn write_u64(&mut self, x: u64) -> Result<(), Self::Err> { self.write_all(&x.to_le_bytes()) }

    /// Write a `i8` to the output.
    fn write_i8(&mut self, x: i8) -> Result<(), Self::Err> { self.write_all(&x.to_le_bytes()) }

    /// Write a `i16` in little endian.
    fn write_i16(&mut self, x: i16) -> Result<(), Self::Err> { self.write_all(&x.to_le_bytes()) }

    /// Write a `i32` in little endian.
    fn write_i32(&mut self, x: i32) -> Result<(), Self::Err> { self.write_all(&x.to_le_bytes()) }

    /// Write a `i64` in little endian.
    fn write_i64(&mut self, x: i64) -> Result<(), Self::Err> { self.write_all(&x.to_le_bytes()) }
}

/// The `write` method always appends data to the end of the vector.
impl Write for Vec<u8> {
    type Err = ();

    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Err> {
        let _ = self.extend_from_slice(buf);
        Ok(buf.len())
    }
}

/// This implementation overwrite the contents of the slice and updates the
/// reference to point to the unwritten part. The slice is (by necessity) never
/// extended.
/// This is in contrast to the `Vec<u8>` implementation which always extends the
/// vector with the data that is written.
impl Write for &mut [u8] {
    type Err = ();

    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Err> {
        let to_write = core::cmp::min(buf.len(), self.len());
        let (overwrite, rest) = core::mem::replace(self, &mut []).split_at_mut(to_write);
        overwrite.copy_from_slice(&buf[..to_write]);
        *self = rest;
        Ok(to_write)
    }
}

/// The `Serial` trait provides a means of writing structures into byte-sinks
/// (`Write`).
///
/// Can be derived using `#[derive(Serial)]` for most cases.
pub trait Serial {
    /// Attempt to write the structure into the provided writer, failing if
    /// only part of the structure could be written.
    ///
    /// NB: We use Result instead of Option for better composability with other
    /// constructs.
    fn serial<W: Write>(&self, _out: &mut W) -> Result<(), W::Err>;
}

/// The `Deserial` trait provides a means of reading structures from
/// byte-sources (`Read`).
///
/// Can be derived using `#[derive(Deserial)]` for most cases.
pub trait Deserial: Sized {
    /// Attempt to read a structure from a given source, failing if an error
    /// occurs during deserialization or reading.
    fn deserial<R: Read>(_source: &mut R) -> ParseResult<Self>;
}

/// The `Serialize` trait provides a means of writing structures into byte-sinks
/// (`Write`) or reading structures from byte sources (`Read`).
///
/// Can be derived using `#[derive(Serialized)]` for most cases.
pub trait Serialize: Serial + Deserial {}

/// Generic instance deriving Serialize for any type that implements both Serial
/// and Deserial.
impl<A: Deserial + Serial> Serialize for A {}

/// A more convenient wrapper around `Deserial` that makes it easier to write
/// deserialization code. It has a blanked implementation for any read and
/// serialize pair. The key idea is that the type to deserialize is inferred
/// from the context, enabling one to write, for example,
///
/// ```rust
/// # fn deserial<R: concordium_contracts_common::Read>(source: &mut R) -> concordium_contracts_common::ParseResult<(u8, u8)> {
/// #  use crate::concordium_contracts_common::Get;
///    let x = source.get()?;
///    let y = source.get()?;
/// #   Ok((x,y))
/// # }
/// ```
/// where `source` is any type that implements `Read`.
pub trait Get<T> {
    fn get(&mut self) -> ParseResult<T>;
}

impl<R: Read, T: Deserial> Get<T> for R {
    #[inline(always)]
    fn get(&mut self) -> ParseResult<T> { T::deserial(self) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn write_u8_slice() {
        let mut xs = [0u8; 10];
        let mut slice: &mut [u8] = &mut xs;
        assert!(0xAAAAAAAAu32.serial(&mut slice).is_ok(), "Writing u32 should succeed.");
        assert_eq!(slice.len(), 6, "The new slice should be of length 6 (= 10 - 4)");
        assert!(0xBBBBBBBBu32.serial(&mut slice).is_ok(), "Writing the second u32 should succeed.");
        assert_eq!(slice.len(), 2, "The new slice should be of length 2 (= 10 - 4 - 4)");
        assert!(0xCCCCu16.serial(&mut slice).is_ok(), "Writing the final u16 should succeed.");
        assert_eq!(slice.len(), 0, "The new slice should be of length 0 (= 10 - 4 - 4 - 2)");
        assert!(0u8.serial(&mut slice).is_err(), "Writing past the end should fail.");
        assert_eq!(
            xs,
            [0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xCC, 0xCC],
            "The original array has incorrect content."
        );
    }
}
