{-# OPTIONS_GHC -Wno-orphans #-}
module Types.NumericTypes where

import qualified Test.QuickCheck as QC

import Concordium.Types.Acorn.NumericTypes

-- NOTE Defining instances here because quick check is not available in src modules

instance QC.Arbitrary Int128 where
  arbitrary = QC.arbitrarySizedBoundedIntegral
  shrink    = QC.shrinkIntegral

instance QC.Arbitrary Word128 where
  arbitrary = QC.arbitrarySizedBoundedIntegral
  shrink    = QC.shrinkIntegral
