//! Types for creating protocol-level locks and reading their configurations.
//!
//! [`LockCreateConfig`] is the externally keyed creation input. [`LockConfig`]
//! is the flat versioned output with effective roles, including holder funding.
//! Both preserve metadata as opaque bytes and follow application-selected
//! unknown-field decoding options.

mod lock_config;
mod lock_config_simple_v0;
mod lock_id;
mod queries;

pub use lock_config::*;
pub use lock_config_simple_v0::*;
pub use lock_id::*;
pub use queries::*;
