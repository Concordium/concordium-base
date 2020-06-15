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
import Data.Serialize
import Data.Bits
import Text.Read
import Data.Aeson
import System.Random
import Test.QuickCheck

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

-- Implemented following the specification on https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/divmodnote-letter.pdf

divC :: (Integral a, Bounded a) => a -> a -> Maybe a
divC x y = if y /= 0 && (y /= -1 || x > minBound) -- this is only correct if using two's complement
           then let q = x `div` y -- cannot overflow, therefore use underlying operation
                    r = x `mod` y in
                  if r > abs y then
                    Nothing
                  else Just $ if r < 0 then
                    if y > 0 then q - 1
                    else q + 1
                  else q
           else Nothing

modC :: Integral a => a -> a -> Maybe a
modC x y = if y /= 0
           then let r = x `mod` y in -- cannot overflow, therefore use operation on a
                  if r > abs y then
                    Nothing
                  else Just $ if r < 0 then
                    if y > 0 then r + y
                    else r - y
                  else r
           else Nothing

powC :: (Integral a, Bounded a) => a -> a -> Maybe a
powC = maybePow mulC

-- ** Defaulting operations (default to 0 on error)

divD :: (Integral a, Bounded a) => a -> a -> a
divD x y = fromMaybe 0 $ divC x y

modD :: Integral a => a -> a -> a
modD x y = fromMaybe 0 $ modC x y

-- |Modular exponentiation, defaulting to 0 if the exponent is negative,
-- and otherwise doing repeated multiplication as defined by the Num instance.
powD :: Integral a => a -> a -> a
powD x y = if y < 0 then 0 else x ^ y -- NB: This requires that the Num instance (*) is appropriate

-- ** Int128

nInt128 :: Integer
nInt128 = 2^(128 :: Int)

minInt128 :: Integer
minInt128 = -2^(127 :: Int)

maxInt128 :: Integer
maxInt128 = 2^(127 :: Int) - 1

-- | A 128-bit integer behaving like fixed-size integers in two's complement representation
-- with respect to minBound/maxBound and overflow arithmetics.
-- Note that in contrast to Data.Int.Int64, this does not produce an exception for (minBound `div` -1)
-- but will adopt a value out of bounds. To avoid this, use the provided checked or defaulting operations.
-- Enum methods might not be reasonable and should not be used.
newtype Int128 = Int128 Integer
  deriving(Generic, Hashable, Eq, Ord, Real, Enum, Integral, Typeable, Data)
  -- Real and Enum are required for Integral

instance Show Int128 where
  show (Int128 i) = show (norm128 i)

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

instance Arbitrary Int128 where
  arbitrary = arbitrarySizedBoundedIntegral
  shrink = shrinkIntegral

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

instance Serialize Word128 where
  put (Word128 w) = do
    putWord64be $ fromIntegral (unsafeShiftR w 64)
    putWord64be $ fromIntegral w
  get = do
    high <- getWord64be
    low <- getWord64be
    return $ Word128 $ (unsafeShiftL (toInteger high) 64) .|. toInteger low

instance Read Word128 where
  readPrec = do
    v <- readPrec
    if v < minWord128 || v > maxWord128 then
      fail "Word128: Out of bounds"
    else
      return (Word128 v)

instance ToJSON Word128 where
  toJSON (Word128 v) = toJSON v
  toEncoding (Word128 v) = toEncoding v

instance FromJSON Word128 where
  parseJSON val = do
    v <- parseJSON val
    if v < minWord128 || v > maxWord128 then
      fail "Word128: Out of bounds"
    else
      return (Word128 v)

instance Random Word128 where
  randomR (Word128 lo, Word128 hi) g = (Word128 a, g')
    where
      (a, g') = randomR (lo, hi) g
  random = randomR (Word128 minWord128, Word128 maxWord128)

instance Arbitrary Word128 where
  arbitrary = arbitrarySizedBoundedIntegral
  shrink = shrinkIntegral

-- Auxiliary functions.
-- |Compute the exponential function terminating early if
-- the given multiplication function yields a Nothing.
-- This performs modular exponentiation linear in the
-- number of bits in the exponent.
maybePow :: (Num a, Integral b) => (a -> a -> Maybe a) -> a -> b -> Maybe a
maybePow mul x0 y0 | y0 <= 0 = Nothing
                   | y0 == 0 = Just 1
                   | otherwise = f y0 x0
    where -- mutually recursive functions computing
          -- f y x = x ^ y
          f y x | even y = mul x x >>= f (y `quot` 2)
                | y == 1 = Just x
                | otherwise = mul x x >>= g (y `quot` 2) x
          -- g y z x = (x ^ y) * z
          g y z x | even y = mul x x >>= g (y `quot` 2) z
                  | y == 1 = mul x z
                  | otherwise = mul x x >>= \x' -> mul x z >>= \z' -> g (y `quot` 2) z' x'
