// -*- mode: rust; -*-
//
// This file is part of concordium_crypto
// Copyright (c) 2019 - 
// See LICENSE for licensing information.
//
// Authors:
// - bm@concordium.com

//! Common constants 
use pairing::bls12_381::FrRepr;

//length of public key in bytes
pub const PUBLIC_KEY_LENGTH: usize = 48; 

//length of message (block) in bytes
pub const MESSAGE_LENGTH: usize = 48; 

//length of cipher in bytes
pub const CIPHER_LENGTH: usize = 96; 

//length of secret key, in bytes
pub const SECRET_KEY_LENGTH: usize= 32;



