//! Types for working with PLT (Protocol Level Token) locks.
//!
//! This module defines the data types used to create, configure, and manage
//! protocol-level locks on tokens. A lock configuration is a tagged variant;
//! the `simpleV0` variant owns recipients, expiry, and capability grants.
//!
//! # Key types
//!
//! - [`LockId`] - Unique identifier for a lock, derived from the creating
//!   account, its sequence number, and an intra-transaction creation order.
//! - [`LockConfig`] - Tagged complete lock configuration.
//! - [`LockConfigSimpleV0`] - Complete simple configuration with recipients,
//!   expiry, grants, tokens, keep-alive, memo, and opaque metadata.
//! - [`LockControllerSimpleV0Grant`] - A grant of capabilities to a specific
//!   account.
//! - [`LockControllerSimpleV0Capability`] - Individual capability that can be
//!   granted (`Fund`, `Release`, `Send`, `Cancel`).
//!
//! All types support CBOR serialization/deserialization, and optionally
//! JSON serialization via serde when the `serde_deprecated` feature is
//! enabled.

mod lock_config;
mod lock_config_simple_v0;
mod lock_id;
mod queries;

pub use lock_config::*;
pub use lock_config_simple_v0::*;
pub use lock_id::*;
pub use queries::*;
