use crate::{traits::*, types::*};

#[cfg(not(feature = "std"))]
use alloc::collections;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::collections;

// Implementations of Serialize

impl<X: Serialize, Y: Serialize> Serialize for (X, Y) {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.0.serial(out)?;
        self.1.serial(out)
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let x = X::deserial(source)?;
        let y = Y::deserial(source)?;
        Ok((x, y))
    }
}

impl Serialize for u8 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_u8(*self) }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> { source.read_u8() }
}

impl Serialize for u32 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_u32(*self) }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> { source.read_u32() }
}

impl Serialize for u64 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_u64(*self) }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> { source.read_u64() }
}

impl Serialize for [u8; 32] {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_all(self) }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let mut bytes = [0u8; 32];
        source.read_exact(&mut bytes)?;
        Ok(bytes)
    }
}

impl Serialize for AccountAddress {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_all(&self.0) }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let bytes = source.get()?;
        Ok(AccountAddress(bytes))
    }
}

impl Serialize for ContractAddress {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        out.write_u64(self.index)?;
        out.write_u64(self.subindex)
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let index = source.get()?;
        let subindex = source.get()?;
        Ok(ContractAddress {
            index,
            subindex,
        })
    }
}

impl Serialize for Address {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        match self {
            Address::Account(ref acc) => {
                out.write_u8(0)?;
                acc.serial(out)
            }
            Address::Contract(ref cnt) => {
                out.write_u8(0)?;
                cnt.serial(out)
            }
        }
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let tag = u8::deserial(source)?;
        match tag {
            0 => Ok(Address::Account(source.get()?)),
            1 => Ok(Address::Contract(source.get()?)),
            _ => Err(R::Err::default()),
        }
    }
}

impl Serialize for InitContext {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.metadata.serial(out)?;
        self.init_origin.serial(out)
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let metadata = source.get()?;
        let init_origin = source.get()?;
        Ok(Self {
            metadata,
            init_origin,
        })
    }
}

impl Serialize for ReceiveContext {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.metadata.serial(out)?;
        self.invoker.serial(out)?;
        self.self_address.serial(out)?;
        self.self_balance.serial(out)?;
        self.sender.serial(out)?;
        self.owner.serial(out)
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let metadata = source.get()?;
        let invoker = source.get()?;
        let self_address = source.get()?;
        let self_balance = source.get()?;
        let sender = source.get()?;
        let owner = source.get()?;
        Ok(ReceiveContext {
            metadata,
            invoker,
            self_address,
            self_balance,
            sender,
            owner,
        })
    }
}

impl Serialize for ChainMetadata {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.slot_number.serial(out)?;
        self.block_height.serial(out)?;
        self.finalized_height.serial(out)?;
        self.slot_time.serial(out)
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let slot_number = source.get()?;
        let block_height = source.get()?;
        let finalized_height = source.get()?;
        let slot_time = source.get()?;
        Ok(Self {
            slot_number,
            block_height,
            finalized_height,
            slot_time,
        })
    }
}

impl<K: Serialize + Ord, V: Serialize> Serialize for collections::BTreeMap<K, V> {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = self.len() as u32;
        len.serial(out)?;
        for (k, v) in self.iter() {
            k.serial(out)?;
            v.serial(out)?;
        }
        Ok(())
    }

    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let len: u32 = source.get()?;
        // FIXME: Ensure order.
        let mut map = collections::BTreeMap::<K, V>::new();
        for _ in 0..len {
            let k = source.get()?;
            let v = source.get()?;
            if map.insert(k, v).is_some() {
                return Err(R::Err::default());
            }
        }
        Ok(map)
    }
}

impl InitContext {
    pub fn init_origin(&self) -> &AccountAddress { &self.init_origin }

    /// Get time in miliseconds at the beginning of this block.
    pub fn get_time(&self) -> u64 { self.metadata.slot_time }
}

impl Address {
    pub fn matches_account(&self, acc: &AccountAddress) -> bool {
        if let Address::Account(ref my_acc) = self {
            my_acc == acc
        } else {
            false
        }
    }

    pub fn matches_contract(&self, cnt: &ContractAddress) -> bool {
        if let Address::Contract(ref my_cnt) = self {
            my_cnt == cnt
        } else {
            false
        }
    }
}

impl ReceiveContext {
    pub fn sender(&self) -> &Address { &self.sender }

    /// Who invoked this transaction.
    pub fn invoker(&self) -> &AccountAddress { &self.invoker }

    /// Get time in miliseconds at the beginning of this block.
    pub fn get_time(&self) -> u64 { self.metadata.slot_time }

    /// Who is the owner of this contract.
    pub fn owner(&self) -> &AccountAddress { &self.owner }

    /// Balance on the smart contract when it was invoked.
    pub fn self_balance(&self) -> Amount { self.self_balance }

    /// Address of the smart contract.
    pub fn self_address(&self) -> &ContractAddress { &self.self_address }
}

impl<T> Cursor<T> {
    pub fn new(data: T) -> Self {
        Cursor {
            offset: 0,
            data,
        }
    }
}

impl Read for Cursor<&[u8]> {
    type Err = ();

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Err> {
        let mut len = self.data.len() - self.offset;
        if len > buf.len() {
            len = buf.len();
        }
        if len > 0 {
            buf[0..len].copy_from_slice(&self.data[self.offset..self.offset + len]);
            self.offset += len;
            Ok(len)
        } else {
            Ok(0)
        }
    }
}

impl Write for Cursor<&mut Vec<u8>> {
    type Err = ();

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Err> {
        if buf.is_empty() {
            Ok(0)
        } else {
            // remaining capacity.
            let remaining_len = self.data.len() - self.offset;
            let (to_write, to_extend): (_, &[u8]) = {
                if remaining_len >= buf.len() {
                    (buf, &[])
                } else {
                    (&buf[..remaining_len], &buf[remaining_len..])
                }
            };
            self.data[self.offset..self.offset + to_write.len()].copy_from_slice(to_write);
            self.data.extend_from_slice(to_extend);
            self.offset += buf.len();
            Ok(buf.len())
        }
    }
}

pub fn to_bytes<S: Serialize>(x: &S) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cursor = Cursor::new(&mut out);
    x.serial(&mut cursor).expect("Writing to a vector should succeed.");
    out
}

pub fn from_bytes<S: Serialize>(source: &[u8]) -> Result<S, ()> {
    let mut cursor = Cursor::new(source);
    cursor.get()
}
