use crate::*;

pub enum InitResult {
    Success {
        state: State,
        logs:  Logs,
    },
    Reject {
        logs: Logs,
    },
}

impl InitResult {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            InitResult::Reject {
                logs,
            } => {
                let mut out = vec![0];
                out.extend_from_slice(&logs.to_bytes());
                out
            }
            InitResult::Success {
                state,
                logs,
            } => {
                let mut out = Vec::with_capacity(5 + state.len() as usize);
                out.push(1);
                out.extend_from_slice(&(state.len() as u32).to_be_bytes());
                out.extend_from_slice(&state.get());
                out.extend_from_slice(&logs.to_bytes());
                out
            }
        }
    }
}

pub enum Action {
    Send {
        to_addr:   ContractAddress,
        name:      Vec<u8>,
        amount:    Amount,
        parameter: Vec<u8>,
    },
    SimpleTransfer {
        to_addr: AccountAddress,
        amount:  Amount,
    },
    And,
    Or,
}

// This is not implementing serialize because that is currently set-up for
// little-endian only, and we need big-endian for interoperability with the rest
// of the system at the moment.
impl Action {
    pub fn to_bytes(&self) -> Vec<u8> {
        use Action::*;
        match self {
            Or => vec![2],
            And => vec![3],
            Send {
                to_addr,
                name,
                amount,
                parameter,
            } => {
                let mut out = Vec::with_capacity(1 + 8 + 8 + name.len() + 4 + parameter.len() + 4);
                out.push(0);
                out.extend_from_slice(&to_addr.index.to_be_bytes());
                out.extend_from_slice(&to_addr.subindex.to_be_bytes());
                out.extend_from_slice(&(name.len() as u32).to_be_bytes());
                out.extend_from_slice(&name);
                out.extend_from_slice(&amount.to_be_bytes());
                out.extend_from_slice(&(parameter.len() as u32).to_be_bytes());
                out.extend_from_slice(&parameter);
                out
            }
            SimpleTransfer {
                to_addr,
                amount,
            } => {
                let mut out = Vec::with_capacity(1 + 32 + 8);
                out.push(1);
                out.extend_from_slice(&to_addr.0);
                out.extend_from_slice(&amount.to_be_bytes());
                out
            }
        }
    }
}

pub enum ReceiveResult {
    Success {
        state:   State,
        logs:    Logs,
        actions: Vec<Action>,
    },
    Reject {
        logs: Logs,
    },
}

impl ReceiveResult {
    pub fn to_bytes(&self) -> Vec<u8> {
        use ReceiveResult::*;
        match self {
            Reject {
                logs,
            } => {
                let mut out = vec![0];
                out.extend_from_slice(&logs.to_bytes());
                out
            }
            Success {
                state,
                logs,
                actions,
            } => {
                let mut out = vec![1];
                let state = state.get();
                out.extend_from_slice(&(state.len() as u32).to_be_bytes());
                out.extend_from_slice(&state);
                out.extend_from_slice(&logs.to_bytes());
                out.extend_from_slice(&(actions.len() as u32).to_be_bytes());
                for a in actions.iter() {
                    out.extend_from_slice(&a.to_bytes());
                }
                out
            }
        }
    }
}

pub enum Which<'a> {
    Init {
        init_ctx: InitContext,
    },
    Receive {
        receive_ctx:   ReceiveContext,
        current_state: &'a [u8],
    },
}
