//! This library provides an implementation of a [Wasm](https://webassembly.org/) execution engine
//! modified to suit Concordium's needs. In particular it implements
//! - parsing and validation of Wasm modules, where validation is according to [Wasm core 1 spec](https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/) with
//!   additional restrictions necessary for blockchain use.
//! - a compiler to a lower-level format that is easier to execute
//! - an interpreter
//! - utilities for storing and loading processed code (the
//!   [`Artifact`](artifact::Artifact))
//!
//! The [`utils`] module provides the convenience wrappers that expose
//! high-level functionality. The remaining modules contain low-level details.

pub mod artifact;
mod artifact_input;
mod artifact_output;
pub mod constants;
pub mod machine;
mod metering_transformation;
pub mod output;
pub mod parse;
pub mod types;
pub mod utils;
pub mod validate;

#[cfg(test)]
mod metering_transformation_test;
