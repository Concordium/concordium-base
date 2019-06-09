{-# LANGUAGE TemplateHaskell #-}
module Concordium.Crypto.PedersenOverBLS12G2 where

import Concordium.Crypto.PedersenScheme.TH
import Foreign.C.Types

mkPedersenScheme $ Parameters {
  cGenCommitmentKeyName = "pedersen_commitment_key_bls12_381_g2_affine",
  cCommitName = "commit_bls12_381_g2_affine",
  cOpenName = "open_bls12_381_g2_affine",
  cRandomValuesName = "random_values_bls12_381_g2_affine",
  groupElementSize = 96,
  fieldElementSize = 32
  }
