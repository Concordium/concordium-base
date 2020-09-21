//! The test infrastructure module provides alternative implementations of
//! `HasInitContext`, `HasReceiveContext`, `HasParameter`, `HasActions`, and
//! `HasContractState` traits intended for testing.
//!
//! They allow writing unit tests directly in contract modules with little to no
//! external tooling, depending on what is required.
use crate::*;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(feature = "std")]
use std::boxed::Box;

/// Wrapper for all the data that goes into an init context.
pub struct InitContextWrapper<'a> {
    pub init_ctx:  InitContext,
    pub parameter: &'a [u8],
}

impl<'a> HasParameter for Cursor<&'a [u8]> {
    fn size(&self) -> u32 { self.data.len() as u32 }
}

/// # Trait implementations for the chain metadata.
impl HasChainMetadata for ChainMetadata {
    #[inline(always)]
    fn slot_time(&self) -> SlotTime { self.slot_time }

    #[inline(always)]
    fn block_height(&self) -> BlockHeight { self.block_height }

    #[inline(always)]
    fn finalized_height(&self) -> FinalizedHeight { self.finalized_height }

    #[inline(always)]
    fn slot_number(&self) -> SlotNumber { self.slot_number }
}

impl<'a> HasInitContext<()> for InitContextWrapper<'a> {
    type InitData = (InitContext, &'a [u8]);
    type MetadataType = ChainMetadata;
    type ParamType = Cursor<&'a [u8]>;

    fn open(data: Self::InitData) -> Self {
        Self {
            init_ctx:  data.0,
            parameter: data.1,
        }
    }

    fn init_origin(&self) -> AccountAddress { self.init_ctx.init_origin }

    fn parameter_cursor(&self) -> Self::ParamType { Cursor::new(self.parameter) }

    fn metadata(&self) -> &Self::MetadataType { &self.init_ctx.metadata }
}

/// Wrapper for all the data that goes into a receive context.
pub struct ReceiveContextWrapper<'a> {
    pub receive_ctx: ReceiveContext,
    pub parameter:   &'a [u8],
}

impl<'a> HasReceiveContext<()> for ReceiveContextWrapper<'a> {
    type MetadataType = ChainMetadata;
    type ParamType = Cursor<&'a [u8]>;
    type ReceiveData = (ReceiveContext, &'a [u8]);

    fn open(data: Self::ReceiveData) -> Self {
        Self {
            receive_ctx: data.0,
            parameter:   data.1,
        }
    }

    fn parameter_cursor(&self) -> Self::ParamType { Cursor::new(self.parameter) }

    fn metadata(&self) -> &Self::MetadataType { &self.receive_ctx.metadata }

    fn invoker(&self) -> AccountAddress { self.receive_ctx.invoker }

    fn self_address(&self) -> ContractAddress { self.receive_ctx.self_address }

    fn self_balance(&self) -> Amount { self.receive_ctx.self_balance }

    fn sender(&self) -> Address { self.receive_ctx.sender }

    fn owner(&self) -> AccountAddress { self.receive_ctx.owner }
}

/// A logger that simply accumulates all the logged items to be inspected at the
/// end of execution.
pub struct LogRecorder {
    pub logs: Vec<Vec<u8>>,
}

impl HasLogger for LogRecorder {
    fn init() -> Self {
        Self {
            logs: Vec::new(),
        }
    }

    fn log_bytes(&mut self, event: &[u8]) { self.logs.push(event.to_vec()) }
}

/// An actions tree.
#[derive(Eq, PartialEq, Debug)]
pub enum ActionsTree {
    Accept,
    SimpleTransfer {
        to:     AccountAddress,
        amount: Amount,
    },
    Send {
        to:           ContractAddress,
        receive_name: String,
        amount:       Amount,
        parameter:    Vec<u8>,
    },
    AndThen {
        left:  Box<ActionsTree>,
        right: Box<ActionsTree>,
    },
    OrElse {
        left:  Box<ActionsTree>,
        right: Box<ActionsTree>,
    },
}

impl HasActions for ActionsTree {
    fn accept() -> Self { ActionsTree::Accept }

    fn simple_transfer(acc: &AccountAddress, amount: Amount) -> Self {
        ActionsTree::SimpleTransfer {
            to: *acc,
            amount,
        }
    }

    fn send(ca: &ContractAddress, receive_name: &str, amount: Amount, parameter: &[u8]) -> Self {
        ActionsTree::Send {
            to: *ca,
            receive_name: receive_name.to_string(),
            amount,
            parameter: parameter.to_vec(),
        }
    }

    fn and_then(self, then: Self) -> Self {
        ActionsTree::AndThen {
            left:  Box::new(self),
            right: Box::new(then),
        }
    }

    fn or_else(self, el: Self) -> Self {
        ActionsTree::OrElse {
            left:  Box::new(self),
            right: Box::new(el),
        }
    }
}

/// Contract state for testing, mimicking the operations the scheduler allows.
pub struct ContractStateWrapper<'a> {
    pub cursor: Cursor<&'a mut Vec<u8>>,
}

impl<'a> Read for ContractStateWrapper<'a> {
    type Err = ();

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Err> { self.cursor.read(buf) }
}

impl<'a> Write for ContractStateWrapper<'a> {
    type Err = ();

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Err> { self.cursor.write(buf) }
}

// TODO: This is not tested.
impl<'a> Seek for ContractStateWrapper<'a> {
    type Err = ();

    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Err> {
        match pos {
            SeekFrom::Start(x) => {
                if x <= u64::from(self.size()) {
                    self.cursor.offset = x as usize; // safe because of <= check
                    Ok(x)
                } else {
                    Err(())
                }
            }
            SeekFrom::End(x) => {
                // cannot seek beyond end, nor before beginning
                if x > 0 || (-x) as u64 > u64::from(self.size()) {
                    Err(())
                } else {
                    use convert::TryInto;
                    let new_pos = u64::from(self.size()) - ((-x) as u64);
                    self.cursor.offset = new_pos.try_into().map_err(|_| ())?;
                    Ok(new_pos)
                }
            }
            SeekFrom::Current(x) => {
                use convert::TryInto;
                if x >= 0 {
                    let x = x.try_into().map_err(|_| ())?;
                    let new_pos = self.cursor.offset.checked_add(x).ok_or(())?;
                    if new_pos <= self.cursor.data.len() {
                        self.cursor.offset = new_pos;
                        Ok(new_pos as u64)
                    } else {
                        Err(())
                    }
                } else {
                    let x = (-x).try_into().map_err(|_| ())?;
                    let new_pos = self.cursor.offset.checked_sub(x).ok_or(())?;
                    self.cursor.offset = new_pos;
                    Ok(new_pos as u64)
                }
            }
        }
    }
}

impl<'a> HasContractState<()> for ContractStateWrapper<'a> {
    type ContractStateData = &'a mut Vec<u8>;

    fn open(data: Self::ContractStateData) -> Self {
        Self {
            cursor: Cursor::new(data),
        }
    }

    fn size(&self) -> u32 { self.cursor.data.len() as u32 }

    fn truncate(&mut self, new_size: u32) {
        if self.size() > new_size {
            let new_size = new_size as usize;
            self.cursor.data.truncate(new_size);
            if self.cursor.offset > new_size {
                self.cursor.offset = new_size
            }
        }
    }

    fn reserve(&mut self, len: u32) -> bool {
        if self.size() < len {
            self.cursor.data.resize(len as usize, 0u8);
            true
        } else {
            true
        }
    }
}
