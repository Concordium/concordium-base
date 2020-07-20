extern crate alloc;

use alloc::vec::Vec;
use core::default::Default;

pub enum SeekFrom {
    Start(u64),
    End(i64),
    Current(i64),
}

pub trait Seek {
    type Err;
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Err>;
}

pub trait Read {
    type Err: Default;
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Err>;

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Self::Err> {
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

    fn read_u32(&mut self) -> Result<u32, Self::Err> {
        let mut bytes = [0u8; 4];
        self.read_exact(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u8(&mut self) -> Result<u8, Self::Err> {
        let mut bytes = [0u8; 1];
        self.read_exact(&mut bytes)?;
        Ok(bytes[0])
    }
}

pub trait Write {
    type Err: Default;
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Err>;

    // FIXME:
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Err> {
        let res = self.write(buf)?;
        if res == buf.len() {
            Ok(())
        } else {
            Err(Default::default())
        }
    }

    fn write_u8(&mut self, x: u8) -> Result<(), Self::Err> { self.write_all(&x.to_le_bytes()) }

    fn write_u16(&mut self, x: u16) -> Result<(), Self::Err> { self.write_all(&x.to_le_bytes()) }

    fn write_u32(&mut self, x: u32) -> Result<(), Self::Err> { self.write_all(&x.to_le_bytes()) }
}

impl Write for Vec<u8> {
    type Err = ();

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Err> {
        let _ = self.extend_from_slice(buf);
        Ok(buf.len())
    }
}

pub trait Serialize: Sized {
    fn serial<W: Write>(&self, _out: &mut W) -> Option<()>;
    fn deserial<R: Read>(_source: &mut R) -> Option<Self>;
}
