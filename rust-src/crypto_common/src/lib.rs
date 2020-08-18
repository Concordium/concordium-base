pub mod helpers;
pub mod impls;
pub mod serialize;
pub mod types;
pub mod version;

pub use crate::{helpers::*, impls::*, serialize::*, version::*};

// Reexport for ease of use.
pub use byteorder::{ReadBytesExt, WriteBytesExt};
pub use failure::Fallible;

#[macro_use]
extern crate failure;

pub use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

#[cfg(not(target_arch = "wasm32"))]
pub use libc::size_t;
#[cfg(target_arch = "wasm32")]
#[allow(non_camel_case_types)]
pub type size_t = usize;

#[cfg(not(target_arch = "wasm32"))]
pub use libc::c_char;
#[cfg(target_arch = "wasm32")]
pub use std::os::raw::c_char;
