{-# LANGUAGE TemplateHaskell #-}
module Concordium.Crypto.PedersenOverBLS12G1 where

import Concordium.Crypto.PedersenScheme.TH
import Foreign.C.Types

mkPedersenScheme $ Parameters {
  cGenCommitmentKeyName = "pedersen_commitment_key_bls12_381_g1_affine",
  cCommitName = "commit_bls12_381_g1_affine",
  cOpenName = "open_bls12_381_g1_affine",
  cRandomValuesName = "random_values_bls12_381_g1_affine",
  groupElementSize = 48,
  fieldElementSize = 32
  }
