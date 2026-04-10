//! Types for working with PLT (Protocol Level Token) locks.
//!
//! This module defines the data types used to create, configure, and manage
//! protocol-level locks on tokens. A lock restricts how tokens can be
//! transferred by specifying recipients, an expiry time, and a controller
//! that grants capabilities (such as funding, sending, returning, or
//! cancelling) to designated accounts.
//!
//! # Key types
//!
//! - [`LockId`] — Unique identifier for a lock, derived from the creating
//!   account, its sequence number, and an intra-transaction creation order.
//! - [`LockConfig`] — Top-level lock configuration containing recipients,
//!   expiry, and controller settings.
//! - [`LockController`] — Enum of controller versions (currently
//!   [`LockControllerSimpleV0`]).
//! - [`LockControllerSimpleV0`] — Controller configuration with capability
//!   grants, token list, keep-alive flag, and optional memo.
//! - [`LockControllerSimpleV0Grant`] — A grant of capabilities to a specific
//!   account.
//! - [`LockControllerSimpleV0Capability`] — Individual capability that can be
//!   granted (`Fund`, `Return`, `Send`, `Cancel`).
//!
//! All types support CBOR serialization/deserialization, and optionally
//! JSON serialization via serde when the `serde_deprecated` feature is
//! enabled.

mod lock_config;
mod lock_controller;
mod lock_controller_simple_v0;
mod lock_id;

pub use lock_config::*;
pub use lock_controller::*;
pub use lock_controller_simple_v0::*;
pub use lock_id::*;
