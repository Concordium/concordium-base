{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -Wall #-}
module Concordium.Types.Acorn.NumericTypes where

import GHC.Generics
import Data.Hashable(Hashable)

import Data.Word
import Data.Int

-- === Int128 ===

-- A 128-bit integer behaving like fixed-size integers in two's complement representation
--  This is with respect to minBound/maxBound and overflow arithmetics
newtype Int128 = Int128 Integer
  deriving(Show, Eq, Generic, Hashable, Real, Integral, Enum, Ord)
  -- TODO implement Real, Integral, Enum

nInt128 :: Integer
nInt128 = 2^(128 :: Int)

minInt128 :: Integer
minInt128 = -2^(127 :: Int)

maxInt128 :: Integer
maxInt128 = 2^(127 :: Int) - 1

instance Bounded Int128 where
  minBound = Int128 minInt128
  maxBound = Int128 maxInt128

norm128 :: Integer -> Integer
norm128 a =
  if a > maxInt128 then norm128 $ ((a+maxInt128+1) `mod` nInt128) - (maxInt128+1) -- as with two's complement representation we have maxBound + 1 = minBound
  else if a < minInt128 then norm128 $ -(((-a+maxInt128) `mod` nInt128) - maxInt128)  -- as with two's complement representation we have minBound - 1 = maxBound
  else a


instance Num Int128 where
  (Int128 a) + (Int128 b) = Int128 $ norm128 (a + b)
  (Int128 a) - (Int128 b) = Int128 $ norm128 (a - b)
  (Int128 a) * (Int128 b) = Int128 $ norm128 (a * b)
  abs (Int128 a) = Int128 $ norm128 $ abs a
  signum (Int128 a) = Int128 $ signum a
  fromInteger a = Int128 $ norm128 a


-- === Word128 ===

nWord128 :: Integer
nWord128 = 2^(128 :: Int)

minWord128 :: Integer
minWord128 = 0

maxWord128 :: Integer
maxWord128 = 2^(128 :: Int) - 1

-- A 128-bit unsigned integer adhering to the calculation rules in the ring Z/(2^128)Z (that is, integer arithmetics modulo 2^128)
newtype Word128 = Word128 Integer -- TODO is there an unlimited Word datatype / should use it?
  deriving(Show, Eq, Generic, Hashable, Real, Integral, Enum, Ord)

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


-- *These are just placeholders for now. We will need a more efficient implementation.
-- Both GCC and Clang provide checked add, mult, sub operations which we should use.

checkOp :: forall a . (Integral a, Bounded a) => (Integer -> Integer -> Integer) -> a -> a -> Maybe a
checkOp op x y = let res = op (toInteger x) (toInteger y)
                 in if res >= toInteger (minBound :: a) && res <= toInteger (maxBound :: a) then Just $ fromInteger res
                    else Nothing

-- TODO if same code for each numeric type, generalize using type variable
-- ===== Int64 =====

addInt64C :: Int64 -> Int64 -> Maybe Int64
addInt64C = checkOp (+)

subInt64C :: Int64 -> Int64 -> Maybe Int64
subInt64C = checkOp (-)

mulInt64C :: Int64 -> Int64 -> Maybe Int64
mulInt64C = checkOp (*)

-- This is only correct if using two's complement.
divInt64C :: Int64 -> Int64 -> Maybe Int64
divInt64C x y = if y /= 0 && (y /= -1 || x > minBound) then Just (x `div` y)
                else Nothing

modInt64C :: Int64 -> Int64 -> Maybe Int64
modInt64C x y = if y /= 0 then Just (x `mod` y)
               else Nothing

addWord64C :: Word64 -> Word64 -> Maybe Word64
addWord64C = checkOp (+)

subWord64C :: Word64 -> Word64 -> Maybe Word64
subWord64C = checkOp (-)

mulWord64C :: Word64 -> Word64 -> Maybe Word64
mulWord64C = checkOp (*)

divWord64C :: Word64 -> Word64 -> Maybe Word64
divWord64C x y = if y > 0 then Just (x `div` y) else Nothing

modWord64C :: Word64 -> Word64 -> Maybe Word64
modWord64C x y = if y /= 0 then Just (x `mod` y)
                 else Nothing

addInt64 :: Int64 -> Int64 -> Int64
addInt64 = (+)

subInt64 :: Int64 -> Int64 -> Int64
subInt64 = (-)

mulInt64 :: Int64 -> Int64 -> Int64
mulInt64 = (*)

-- This is only correct if using two's complement.
divInt64 :: Int64 -> Int64 -> Int64
divInt64 x y = if y /= 0 && (y /= -1 || x > minBound) then (x `div` y)
               else 0

modInt64 :: Int64 -> Int64 -> Int64
modInt64 x y = if y /= 0 then (x `mod` y)
               else 0

addWord64 :: Word64 -> Word64 -> Word64
addWord64 = (+)

subWord64 :: Word64 -> Word64 -> Word64
subWord64 = (-)

mulWord64 :: Word64 -> Word64 -> Word64
mulWord64 = (*)

divWord64 :: Word64 -> Word64 -> Word64
divWord64 x y = if y > 0 then (x `div` y) else 0

modWord64 :: Word64 -> Word64 -> Word64
modWord64 x y = if y /= 0 then (x `mod` y)
                else 0


-- ===== Int128 =====

addInt128C :: Int128 -> Int128 -> Maybe Int128
addInt128C = checkOp (+)

subInt128C :: Int128 -> Int128 -> Maybe Int128
subInt128C = checkOp (-)

mulInt128C :: Int128 -> Int128 -> Maybe Int128
mulInt128C = checkOp (*)

-- This is only correct if using two's complement.
divInt128C :: Int128 -> Int128 -> Maybe Int128
divInt128C x y = if y /= 0 && (y /= -1 || x > minBound) then Just (x `div` y)
                 else Nothing

modInt128C :: Int128 -> Int128 -> Maybe Int128
modInt128C x y = if y /= 0 then Just (x `mod` y)
                 else Nothing

addWord128C :: Word128 -> Word128 -> Maybe Word128
addWord128C = checkOp (+)

subWord128C :: Word128 -> Word128 -> Maybe Word128
subWord128C = checkOp (-)

mulWord128C :: Word128 -> Word128 -> Maybe Word128
mulWord128C = checkOp (*)

divWord128C :: Word128 -> Word128 -> Maybe Word128
divWord128C x y = if y > 0 then Just (x `div` y) else Nothing

modWord128C :: Word128 -> Word128 -> Maybe Word128
modWord128C x y = if y /= 0 then Just (x `mod` y)
                  else Nothing

addInt128 :: Int128 -> Int128 -> Int128
addInt128 = (+)

subInt128 :: Int128 -> Int128 -> Int128
subInt128 = (-)

mulInt128 :: Int128 -> Int128 -> Int128
mulInt128 = (*)

-- This is only correct if using two's complement.
divInt128 :: Int128 -> Int128 -> Int128
divInt128 x y = if y /= 0 && (y /= -1 || x > minBound) then (x `div` y)
                else 0

modInt128 :: Int128 -> Int128 -> Int128
modInt128 x y = if y /= 0 then (x `mod` y)
                else 0

addWord128 :: Word128 -> Word128 -> Word128
addWord128 = (+)

subWord128 :: Word128 -> Word128 -> Word128
subWord128 = (-)

mulWord128 :: Word128 -> Word128 -> Word128
mulWord128 = (*)

divWord128 :: Word128 -> Word128 -> Word128
divWord128 x y = if y > 0 then (x `div` y) else 0

modWord128 :: Word128 -> Word128 -> Word128
modWord128 x y = if y /= 0 then (x `mod` y)
                 else 0
