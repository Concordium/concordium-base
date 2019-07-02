{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TemplateHaskell #-}
module Concordium.Crypto.SigmaProtocols.DLogOverBLS12381G1(
  module Concordium.Crypto.SigmaProtocols.DLogOverBLS12381G1,
  DLogProof,
  Public,
  Secret,
  Base
  )
  where

import Concordium.Crypto.SigmaProtocols.DLog.TH
import Foreign.C.Types

import Concordium.Crypto.Curve

mkDLog $ Parameters {
  cProveName = "prove_dlog_g1",
  cVerifyName = "verify_dlog_g1",
  cToBytesName = "dlog_proof_to_bytes_g1",
  cFromBytesName = "dlog_proof_from_bytes_g1",
  cFreeProofName = "free_dlog_proof_g1",
  cDerivePublicName = "derive_public_g1",
  tagName = ''G1
  }
