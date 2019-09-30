{-# LANGUAGE DeriveDataTypeable #-}
{-|
Provides signed and unsigned integral data types of fixed bit length with safe (checked and defaulting) arithmetic operations.

More efficient implementations of the operations will be needed in the future.
Both GCC and Clang provide checked add, mult, sub operations which we should use.
-}

{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -Wall #-}
module Concordium.Types.Acorn.NumericTypes where

import GHC.Generics
import Data.Data(Data, Typeable)
import Data.Hashable(Hashable)

import Data.Maybe

-- ** Checked operations

-- NOTE: should use toIntegralSized when having implemented Bits
-- |Converts from one Integral to another if it fits into its range
toIntegral :: forall a b . (Integral a, Integral b, Bounded b) => a -> Maybe b
toIntegral x =
  -- NOTE: do not use check whether (toInteger $ fromInteger $ toInteger x )
  -- equals toInteger x (with fromInteger :: Integer -> b) as this might be
  -- satisfied even if x is out of bounds of the target type (fromInteger uses
  -- modulo)
  if toInteger x >= toInteger (minBound :: b) && toInteger x <= toInteger (maxBound :: b)
  then Just $ fromInteger $ toInteger x
  else Nothing

-- |Convert from one Integral to another.
-- |If the argument value is withing the target type's range, the value is
-- preserved. Otherwise it is "normalized" into the target type's range such that
--
--   * @toIntegralNormalizing 1 = 1@
--   * @toIntegralNormalizing (x + y) = toIntegralNormalizing x + toIntegralNormalizing y@
--   * @toIntegralNormalizing (x * y) = toIntegralNormalizing x * toIntegralNormalizing y@
--   * @toIntegralNormalizing (-x) = - toIntegralNormalizing x@
--
-- In particular, in two's complement representation, if a and b have the same
-- bit size the bit representation is maintained.
--
-- TODO: This implementation is inefficient and will be replaced by a more
-- efficient one. On two's complement representations, if size(a) >= size(b) all
-- this does is take the lowest (least significant) n bits, where n is the size
-- of b.
toIntegralNormalizing :: (Integral a, Integral b) => a -> b
toIntegralNormalizing = fromInteger . toInteger

-- |Use the given operation on Integer to see whether the result would be out of bound for type a and convert results within bounds to a
checkOpBounds :: (Integral a, Bounded a) => (Integer -> Integer -> Integer) -> a -> a -> Maybe a
checkOpBounds op x y = toIntegral $ op (toInteger x) (toInteger y)

addC :: (Integral a, Bounded a) => a -> a -> Maybe a
addC = checkOpBounds (+)

subC :: (Integral a, Bounded a) => a -> a -> Maybe a
subC = checkOpBounds (-)

mulC :: (Integral a, Bounded a) => a -> a -> Maybe a
mulC = checkOpBounds (*)

divC :: (Integral a, Bounded a) => a -> a -> Maybe a
divC x y = if y /= 0 && (y /= -1 || x > minBound) -- This is only correct if using two's complement.
           then Just (x `div` y) -- cannot overflow, therefore use operation on a
           else Nothing

modC :: Integral a => a -> a -> Maybe a
modC x y = if y /= 0
           then Just (x `mod` y) -- cannot overflow, therefore use operation on a
           else Nothing

powC :: (Integral a, Bounded a) => a -> a -> Maybe a
powC x y = if y >= 0
           then checkOpBounds (^) x y
           else Nothing

-- ** Defaulting operations (default to 0 on error)

divD :: (Integral a, Bounded a) => a -> a -> a
divD x y = fromMaybe 0 $ divC x y

modD :: (Integral a, Bounded a) => a -> a -> a
modD x y = fromMaybe 0 $ divC x y

-- | Note: Defaults on negative exponent, normalizes on overflow
powD :: Integral a => a -> a -> a
powD x y = if y >= 0
           then fromInteger $ (toInteger x)^(toInteger y)
           else 0

-- ** Int128

nInt128 :: Integer
nInt128 = 2^(128 :: Int)

minInt128 :: Integer
minInt128 = -2^(127 :: Int)

maxInt128 :: Integer
maxInt128 = 2^(127 :: Int) - 1

-- | A 128-bit integer behaving like fixed-size integers in two's complement representation with respect to minBound/maxBound and overflow arithmetics. Note that in contrast to Data.Int.Int64, this does not produce an exception for (minBound `div` -1) but will adopt a value out of bounds. To avoid this, use the provided checked or defaulting operations. Enum methods might not be reasonable and should not be used.
newtype Int128 = Int128 Integer
  deriving(Generic, Hashable, Eq, Ord, Real, Enum, Integral, Typeable, Data)
  -- Real and Enum are required for Integral

instance Show Int128 where
  show (Int128 i) = show i

instance Bounded Int128 where
  minBound = Int128 minInt128
  maxBound = Int128 maxInt128

norm128 :: Integer -> Integer
norm128 a =
  if a > maxInt128 then ((a+maxInt128+1) `mod` nInt128) - (maxInt128+1) -- as with two's complement representation we have maxBound + 1 = minBound
  else if a < minInt128 then -(((-a+maxInt128) `mod` nInt128) - maxInt128)  -- as with two's complement representation we have minBound - 1 = maxBound
  else a

instance Num Int128 where
  (Int128 a) + (Int128 b) = Int128 $ norm128 (a + b)
  (Int128 a) - (Int128 b) = Int128 $ norm128 (a - b)
  (Int128 a) * (Int128 b) = Int128 $ norm128 (a * b)
  abs (Int128 a) = Int128 $ norm128 $ abs a
  signum (Int128 a) = Int128 $ signum a
  fromInteger a = Int128 $ norm128 a


-- ** Word128

nWord128 :: Integer
nWord128 = 2^(128 :: Int)

minWord128 :: Integer
minWord128 = 0

maxWord128 :: Integer
maxWord128 = 2^(128 :: Int) - 1

-- | A 128-bit unsigned integer adhering to the calculation rules in the ring
-- Z/(2^128)Z (that is, integer arithmetics modulo 2^128). Enum methods might
-- not be reasonable and should not be used.
newtype Word128 = Word128 Integer -- TODO is there an unlimited Word datatype / should use it?
  deriving(Generic, Hashable, Eq, Ord, Real, Enum, Integral, Typeable, Data)
  -- Real and Enum are required for Integral

instance Show Word128 where
  show (Word128 i) = show i

instance Bounded Word128 where
  minBound = Word128 minWord128
  maxBound = Word128 maxWord128

-- We have maxBound+1=minBound
instance Num Word128 where
  (Word128 a) + (Word128 b) = Word128 $ (a + b) `mod` nWord128
  (Word128 a) - (Word128 b) = Word128 $ (a - b) `mod` nWord128
  (Word128 a) * (Word128 b) = Word128 $ (a * b) `mod` nWord128
  abs (Word128 a) = Word128 a -- word is always non-negative
  signum (Word128 a) = Word128 $ signum a -- 0 or 1
  fromInteger a = Word128 $ a `mod` nWord128
