use crate::*;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

pub const VERSION_CREDENTIAL: Version = Version(0);

/// The version of a data structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
pub struct Version(pub u32);

impl Version {
    #[inline]
    pub fn value(self) -> u32 {
        self.0
    }
}

impl From<Version> for u32 {
    fn from(val: Version) -> u32 {
        val.0
    }
}

impl Serial for Version {
    fn serial<B: Buffer>(&self, out: &mut B) {
        if self.value() == 0 {
            out.write_u8(0).expect("Writing to buffer is safe");
            return;
        }

        // Create 7-bit encoding with all MSB set to 1
        let mut buf = Vec::with_capacity(5);
        let mut v = self.value();
        while v > 0 {
            let byte = (1 << 7) | (v & 0b0111_1111) as u8;
            buf.push(byte);
            v >>= 7;
        }

        // Convert to BigEndian, ensure last byte has MSB=0, write to buffer
        buf[0] &= 0b0111_1111;
        buf.reverse();
        out.write_all(&buf).expect("Writing to buffer is safe");
    }
}

impl Deserial for Version {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<Self> {
        let mut acc: u32 = 0;
        for _ in 0..5 {
            let byte = source.read_u8()? as u32;
            if byte >= 0b1000_0000 {
                acc = (acc << 7) | (byte & 0b0111_1111);
            } else {
                acc = (acc << 7) | byte;
                break;
            }
        }
        Ok(Version(acc))
    }
}

/// Versioned<T> represents T as a versioned data-structure.
/// The version is a integer number up to the implementation,
/// which is serialized using variable integer encoding.
/// The caller is responsible for ensuringe the data structure `T`
/// is compatible with the version number.
#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
pub struct Versioned<T> {
    #[serde(rename = "v")]
    pub version: Version,
    pub value: T,
}

impl<T> Versioned<T> {
    pub fn new(version: Version, value: T) -> Versioned<T> {
        Versioned { version, value }
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn value(self) -> T {
        self.value
    }
}

impl<T: Serial> Serial for Versioned<T> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.put(&self.version);
        out.put(&self.value);
    }
}

impl<T: Deserial> Deserial for Versioned<T> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<Self> {
        let version: Version = source.get()?;
        let value: T = source.get()?;
        Ok(Versioned { version, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, RngCore};

    #[test]
    fn test_version_serialization_testvector() {
        let test = Version(1700794014);
        let actual: Vec<u8> = vec![0x86, 0xab, 0x80, 0x9d, 0x1e];
        let mut buffer: Vec<u8> = Vec::new();
        test.serial(&mut buffer);
        assert_eq!(buffer, actual);
    }

    #[test]
    fn test_version_serialization_minmax() {
        let min = Version(0);
        let max = Version(u32::max_value());
        let min_actual: Vec<u8> = vec![0x00];
        let max_actual: Vec<u8> = vec![0x8F, 0xFF, 0xFF, 0xFF, 0x7F];
        let mut buffer: Vec<u8> = Vec::new();
        min.serial(&mut buffer);
        assert_eq!(buffer, min_actual);
        let mut buffer: Vec<u8> = Vec::new();
        max.serial(&mut buffer);
        assert_eq!(buffer, max_actual);
    }

    #[test]
    fn test_version_serialization_singlebits() {
        let mut current: u32 = 1;
        for _ in 0..32 {
            let actual = Version(current);
            let parsed = serialize_deserialize(&actual).unwrap();
            assert_eq!(actual, parsed);
            current = current * 2;
        }
    }

    #[test]
    fn test_version_serialization_random() {
        let mut rng = thread_rng();
        for _ in 0..1000 {
            let actual = Version(rng.next_u32());
            let parsed = serialize_deserialize(&actual).unwrap();
            assert_eq!(actual, parsed);
        }
    }

    #[test]
    fn test_version_serialization_json() {
        #[derive(SerdeSerialize, SerdeDeserialize)]
        struct Example {
            n: u32,
            s: String,
        };

        let ex = Example {
            n: 42,
            s: String::from("Test"),
        };

        let versioned = Versioned::new(Version(1337), ex);

        let json = serde_json::to_string(&versioned).unwrap();
        let actual_json = "{\"v\":1337,\"value\":{\"n\":42,\"s\":\"Test\"}}";
        assert_eq!(json, actual_json);
    }
}
