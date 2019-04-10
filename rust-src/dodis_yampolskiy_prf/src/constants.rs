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

//length of prf in bytes
pub const PRF_LENGTH: usize = 48;

//length of secret key, in bytes
pub const SECRET_KEY_LENGTH: usize= 32;

// The maximum possible count 255
// should be safe to unwrap
pub const MAX_COUNT : FrRepr = FrRepr ([0x232fffffdcd ,0xd5f04d67039bae33 ,0x57c9e652d111ec48 ,0xc59041b7aa57a37]); 
//max secret key equal to MODULUS - MAX_COUNT - 1 
pub const MAX_SECRET_KEY : FrRepr = FrRepr(
    [0xfffffdcc00000233,
    0x7dcd569bfc62adcb,
    0xdb6ff1b5388febbc, 
    0x6794a337aef80310]
    ); 


