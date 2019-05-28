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
#[allow(dead_code)]
pub const PRF_LENGTH: usize = 48;

//length of secret key, in bytes
pub const SECRET_KEY_LENGTH: usize = 32;

// The maximum possible count 255
// should be safe to unwrap
#[allow(dead_code)]
pub const MAX_COUNT: FrRepr = FrRepr([
    0x0232_ffff_fdcd,
    0xd5f0_4d67_039b_ae33,
    0x57c9_e652_d111_ec48,
    0x0c59_041b_7aa5_7a37,
]);
//max secret key equal to MODULUS - MAX_COUNT - 1
pub const MAX_SECRET_KEY: FrRepr = FrRepr([
    0xffff_fdcc_0000_0233,
    0x7dcd_569b_fc62_adcb,
    0xdb6f_f1b5_388f_ebbc,
    0x6794_a337_aef8_0310,
]);
