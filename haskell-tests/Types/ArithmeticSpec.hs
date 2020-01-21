{-# LANGUAGE ScopedTypeVariables #-}
module Types.ArithmeticSpec where

import Data.Word
import Data.Int

import Concordium.Types.Acorn.NumericTypes
import Types.NumericTypes()

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck as QC

import Data.Maybe(isJust, fromJust)

assoc :: (Eq a, Show a) => (a -> a -> a) -> a -> a -> a -> Property
assoc f x y z = f (f x y) z === f x (f y z)

commut :: (Eq a, Show a) => (t -> t -> a) -> t -> t -> Property
commut f x y = f x y === f y x

distribute ::
  (Eq t1, Show t1) =>
  (t2 -> t1 -> t1) -> (t1 -> t1 -> t1) -> t2 -> t1 -> t1 -> Property
distribute f g x y z = f x (g y z) === g (f x y) (f x z)

-- Check that a checked operations mostly fails given arguments from the provided generators
checkFail :: (Eq a, Show a) => (a -> a -> Maybe a) -> Gen a -> Gen a -> Property
checkFail f numGen1 numGen2 = QC.cover 95 True "do fail" $
                        (forAll numGen1
                          (\x -> forAll numGen2
                            (\y -> f x y === Nothing)))

-- Check that if checked operations succeed their result is the same as unchecked ones
compareChecked ::
  (Eq a, Show a) =>
  (t1 -> t2 -> Maybe a) -> (t1 -> t2 -> a) -> t1 -> t2 -> Property
compareChecked f g x y = let r1 = f x y in
                           QC.cover 95 (isJust r1) "Checked operation succeeds." $
                              isJust r1 ==>  fromJust r1 === g x y

-- Generate values that are not likely to overflow on multiplication
smallGenInt64 :: Gen Int64
smallGenInt64 = do x <- arbitrary :: Gen Int32
                   y <- arbitrary :: Gen Int8
                   return (fromIntegral x + fromIntegral y)

smallGenWord64 :: Gen Word64
smallGenWord64 = do x <- arbitrary :: Gen Word32
                    y <- arbitrary :: Gen Word8
                    return (fromIntegral x + fromIntegral y)

smallGenInt128 :: Gen Int128
smallGenInt128 = do x <- arbitrary :: Gen Int64
                    y <- arbitrary :: Gen Int32
                    return (fromIntegral x + fromIntegral y)

smallGenWord128 :: Gen Word128
smallGenWord128 = do x <- arbitrary :: Gen Word64
                     y <- arbitrary :: Gen Word32
                     return (fromIntegral x + fromIntegral y)

-- TODO for 256bit should probably use fromInteger and toInteger!

negNumGen :: (Num a, Eq a, Arbitrary a) => Gen a
negNumGen = do x <- arbitrary
               return $ if x == 0
                        then -1
                        else -(abs x) -- for signed types, the negative of all representable positive numbers is representable

nonNegNumGen :: (Num a, Eq a, Arbitrary a, Bounded a) => Gen a
nonNegNumGen = do x <- arbitrary
                  return $ if x == minBound -- for signed types, the absolute of all representable numbers except for minBound is representable
                           then 0
                           else abs x

-- Generates (absolutely) very small numbers
verySmallNumGen :: (Num a) => Gen a
verySmallNumGen = do x <- arbitrary :: Gen Int8
                     return $ fromIntegral x

-- Generates very small numbers >=0
verySmallNonNegNumGen :: (Num a) => Gen a
verySmallNonNegNumGen = do x <- arbitrary :: Gen Word8
                           return $ fromIntegral x

-- Create Gen for big numbers from a Gen from small numbers
makeBigNumGen :: forall a . (Integral a, Bounded a) => Gen a -> Gen a
makeBigNumGen smallNumGen = do
  x <- smallNumGen
  return $ fromInteger $ (toInteger (maxBound :: a)) - (abs $ toInteger x)

-- Like makeBigNumGen but to create big negative numbers
makeBigNegNumGen :: forall a . (Integral a, Bounded a) => Gen a -> Gen a
makeBigNegNumGen smallNumGen = do
  x <- smallNumGen
  return $ fromInteger $ (toInteger (minBound :: a)) + (abs $ toInteger x)


-- check that if checked operations succeed their result is the same as unchecked ones
compareChecked2 ::
  (Eq a, Show a) =>
  (t1 -> t2 -> t3 -> t4 -> a)
  -> (t1 -> t2 -> t3 -> t4 -> a)
  -> (t1 -> t2 -> Maybe t3)
  -> (t1 -> t2 -> Maybe t4)
  -> t1
  -> t2
  -> Property
compareChecked2 c1 c2 f g x y = let r1 = f x y
                                    r2 = g x y
                                in QC.cover 95 (isJust r1) "Checked operation succeeds." $
                                   (isJust r1 && isJust r2) ==> c1 x y (fromJust r1) (fromJust r2) === c2 x y (fromJust r1) (fromJust r2)


-- Specifications specific to signed numeric types
arithmeticSpecsInt :: forall a . (Bounded a, Integral a, Arbitrary a, Show a) => Gen a -> SpecWith ()
arithmeticSpecsInt smallNumGen =
  let bigNumGen = makeBigNumGen smallNumGen
      bigNegNumGen = makeBigNegNumGen smallNumGen
  in do
    describe "Int-specific corner cases regarding two's complement representation for unchecked operations" $ modifyMaxSuccess (const 50000) $ do
      specify "-maxBound" $ (0 :: a) - maxBound `shouldBe` -maxBound
      specify "2*maxBound" $ (2 :: a) * maxBound `shouldBe` -2
      specify "4*maxBound" $ (4 :: a) * maxBound `shouldBe` -4
      specify "minBound `divD` (-1)" $ (minBound :: a) `divD` (-1) `shouldBe` 0 -- unchecked operation should default to 0 on this overflow
      specify "abs -1" $ abs (-1 :: a) `shouldBe` 1
    describe "Int-specific failure of checked operations" $ modifyMaxSuccess (const 50000) $ do
      specify "-minBound" $ (0 :: a) `subC` minBound `shouldBe` Nothing
      specify "minBound `divC` (-1)" $ (minBound :: a) `divC` (-1) `shouldBe` Nothing -- unchecked operation should default to 0 on this exception
      specify "add overflow" $ (property $ checkFail addC bigNegNumGen bigNegNumGen)
      specify "mul overflow" $ (property $ checkFail mulC bigNegNumGen bigNumGen)
      specify "pow with negative exponent" $ (property $ checkFail powC arbitrary (negNumGen :: Gen a))
    describe "Int-specific defaulting of operations" $ modifyMaxSuccess (const 50000) $ do
      specify "pow with negative exponent" (forAll smallNumGen (\x -> forAll (negNumGen :: Gen a) (\y -> powD x y === 0)))


-- Specifications specific to unsigned numeric types
arithmeticSpecsWord :: forall a . (Bounded a, Integral a, Show a) => Gen a -> SpecWith ()
arithmeticSpecsWord smallNumGen =
  let bigNumGen = makeBigNumGen smallNumGen
  in do
    describe "Word-specific corner cases regarding two's complement representation for unchecked operations" $ modifyMaxSuccess (const 50000) $ do
      specify "-maxBound" $ (0 :: a) - maxBound `shouldBe` 1
      specify "3*maxBound (equation)" $ (3 :: a) * maxBound `shouldBe` minBound + maxBound - 2
    describe "Word-specific failure of checked operations" $ modifyMaxSuccess (const 50000) $ do
      specify "sub overflow" $ (property $ checkFail subC smallNumGen bigNumGen)

arithmeticSpecs :: forall a . (Bounded a, Integral a, Arbitrary a, Show a) => Gen a -> SpecWith ()
arithmeticSpecs smallNumGen =
  -- specify type for operations
  let add = (+) :: a -> a -> a
      addC' = addC :: a -> a -> Maybe a
      sub = (-) :: a -> a -> a
      mul = (*) :: a -> a -> a
      mulC' = mulC :: a -> a -> Maybe a
      divD' = divD :: a -> a -> a
      divC' = divC :: a -> a -> Maybe a
      modD' = modD :: a -> a -> a
      modC' = divC :: a -> a -> Maybe a
      powD' = powD :: a -> a -> a
      powC' = powC :: a -> a -> Maybe a
      bigNumGen = makeBigNumGen smallNumGen
  in do
    describe "General corner cases regarding two's complement representation for unchecked operations" $ modifyMaxSuccess (const 50000) $ do
      -- Corner case tests for Int and Word are based on the following rules which exist in two's complement representation:
      -- maxBound + 1 = minBound
      -- minBound - 1 = maxBound
      -- -minBound = minBound (like -0 = 0)
      specify "0-1" $ ((0 :: a) - 1) `shouldBe` (-1)
      specify "maxBound+1" $ (maxBound :: a) + 1 `shouldBe` minBound
      specify "minBound-1" $ (minBound :: a) - 1 `shouldBe` maxBound
      specify "-minBound" $ (0 :: a) - minBound `shouldBe` minBound
      specify "0*maxBound" $ (0 :: a) * maxBound `shouldBe` 0
      specify "1*maxBound" $ (1 :: a) * maxBound `shouldBe` maxBound
      specify "2*maxBound (equation)" $ (2 :: a) * maxBound `shouldBe` minBound + maxBound - 1
      specify "3*maxBound" $ (3 :: a) * maxBound `shouldBe` -2 + maxBound
      specify "4*maxBound (equation)" $ (4 :: a) * maxBound `shouldBe` minBound + maxBound - 3
      specify "5*maxBound" $ (5 :: a) * maxBound `shouldBe` -4 + maxBound
      specify "0*minBound" $ (0 :: a) * minBound `shouldBe` 0
      specify "1*minBound" $ (1 :: a) * minBound `shouldBe` minBound
      specify "2*minBound (equation)" $ (2 :: a) * minBound `shouldBe` maxBound + minBound + 1
      specify "2*minBound" $ (2 :: a) * minBound `shouldBe` 0
      specify "3*minBound" $ (3 :: a) * minBound `shouldBe` minBound
      specify "4*minBound" $ (4 :: a) * minBound `shouldBe` 0
      specify "5*minBound" $ (5 :: a) * minBound `shouldBe` minBound
      specify "1 `divD` 0" $ (1 :: a) `divD` (0) `shouldBe` 0 -- unchecked operation should default to 0 on this exception
      specify "minBound `divD` 0" $ (minBound :: a) `divD` (0) `shouldBe` 0 -- unchecked operation should default to 0 on this exception
      specify "1 `modD` 0" $ (1 :: a) `modD` (0) `shouldBe` 0 -- unchecked operation should default to 0 on this exception
      specify "minBound `modD` 0" $ (minBound :: a) `modD` (0) `shouldBe` 0 -- unchecked operation should default to 0 on this exception
      specify "abs 0" $ abs (0 :: a) `shouldBe` 0
      specify "abs 1" $ abs (1 :: a) `shouldBe` 1
      specify "abs maxBound" $ abs (maxBound :: a) `shouldBe` (maxBound :: a)
      specify "abs minBound" $ abs (minBound :: a) `shouldBe` (minBound :: a)
      specify "fromInteger 0" $ toInteger ((fromInteger :: Integer -> a) (0)) `shouldBe` ((0) :: Integer)
      specify "fromInteger 1" $ toInteger ((fromInteger :: Integer -> a) (1)) `shouldBe` ((1) :: Integer)
      specify "fromInteger maxBound" $ toInteger ((fromInteger :: Integer -> a) (1)) `shouldBe` ((1) :: Integer)
      specify "fromInteger maxBound+1" $ fromInteger ((toInteger (maxBound :: a)) + 1) `shouldBe` (minBound :: a)
      specify "fromInteger minBound-1" $ fromInteger ((toInteger (minBound :: a)) - 1) `shouldBe` (maxBound :: a)

    describe "Ring and commutativity properties" $ modifyMaxSuccess (const 50000) $ do
      specify "add associativity" (property $ assoc add)
      specify "mul associativity" (property $ assoc mul)
      specify "add/mul distributivity" (property $ distribute mul add)
      specify "add commutativity" (property $ commut add)
      specify "mul commutativity" (property $ commut mul)

    describe "Failure of checked operations" $ modifyMaxSuccess (const 50000) $ do
      specify "1 `divC` 0" $ (1 :: a) `divC` (0) `shouldBe` Nothing
      specify "minBound `divC` 0" $ (minBound :: a) `divC` (0) `shouldBe` Nothing
      specify "1 `modC` 0" $ (1 :: a) `modC` (0) `shouldBe` Nothing
      specify "minBound `modC` 0" $ (minBound :: a) `modC` (0) `shouldBe` Nothing
      specify "add overflow" $ (property $ checkFail addC' bigNumGen bigNumGen)
      specify "mul overflow" $ (property $ checkFail mulC' bigNumGen bigNumGen)
      specify "pow overflow" $ (property $ checkFail powC' bigNumGen (elements [2..7]))

    describe "Success of checked operations (must yield same result as unchecked)" $ modifyMaxSuccess (const 50000) $ do
      specify "compare checked add" (property $ compareChecked addC add)
      specify "compare checked sub" (property $ compareChecked subC sub)
      specify "compare checked mul" (forAll smallNumGen (\x -> forAll smallNumGen (compareChecked mulC mul x)))
      specify "compare checked div" (property $ compareChecked divC' divD')
      specify "compare checked mod" (property $ compareChecked modC' modD')
      specify "compare checked pow" (forAll smallNumGen (\x -> forAll (elements [0..10]) (compareChecked powC' powD' x)))

    describe "Div/mod relation" $ modifyMaxSuccess (const 50000) $ do
      specify "checked div/mod" (property $ compareChecked2 (\_ y q r -> q * y + r) (\x _ _ _ -> x) divC' modC) -- NOTE: compareChecked2 is for comparing checked vs. unchecked, but here it is just the checked operation
    describe "Representation conversion within same type" $ modifyMaxSuccess (const 50000) $ do
      specify "Involution on same type" $ forAll arbitrary (\x -> ((toIntegralNormalizing x) :: a) === x)

-- a should be an Int type, b a Word type of the same bit size
specCastIntWord :: forall a b . (Bounded a, Integral a, Show a,
                                 Bounded b, Integral b)
                       => Gen a -> Gen a -> Gen b -> SpecWith ()
specCastIntWord negNumGenA nonNegNumGenA _ = do
  describe "Int -> Word" $ modifyMaxSuccess (const 5000) $ do
    specify "minInt" $ toInteger (toIntegralNormalizing (minBound :: a) :: b) `shouldBe` -(toInteger (minBound :: a)) 
    specify "minInt'" $ toInteger (toIntegralNormalizing (minBound :: a) :: b) `shouldBe` toInteger (maxBound :: b) + toInteger (minBound :: a) + 1
    specify "minInt+1" $ toInteger (toIntegralNormalizing ((minBound :: a)+1) :: b) `shouldBe` toInteger (maxBound :: b) + toInteger (minBound :: a) + 2
    specify "-1" $ toInteger ((toIntegralNormalizing (-1 :: a)) :: b) `shouldBe` toInteger (maxBound :: b)
    specify "0" $ toInteger ((toIntegralNormalizing (0 :: a)) :: b) `shouldBe` toInteger (0 :: b)
    specify "1" $ toInteger ((toIntegralNormalizing (1 :: a)) :: b) `shouldBe` toInteger (1 :: b)
    specify "maxInt-1" $ toInteger (toIntegralNormalizing ((maxBound :: a)-1) :: b) `shouldBe` toInteger (maxBound :: a) - 1
    specify "maxInt" $ toInteger (toIntegralNormalizing (maxBound :: a) :: b) `shouldBe` toInteger (maxBound :: a)
    specify "Negative numbers" $ forAll negNumGenA (\x -> toInteger ((toIntegralNormalizing x) :: b) === (toInteger x) + (toInteger (maxBound :: b)) + 1)
    specify "Non-negative numbers" $ forAll nonNegNumGenA (\x -> toInteger ((toIntegralNormalizing x) :: b) === toInteger x)

-- a should be a Word type, b an Int type of the same bit size
specCastWordInt :: forall a b . (Bounded a, Integral a, Arbitrary a, Show a,
                                 Bounded b, Integral b,              Show b)
                       => Gen a -> Gen b -> SpecWith ()
specCastWordInt _ _ = do
  describe "Word -> Int" $ modifyMaxSuccess (const 5000) $ do
    let lowerGen = (suchThat (arbitrary :: Gen a) (\x -> toInteger x <  ((toInteger (maxBound :: a))+1) `div` 2))
    let upperGen = (suchThat (arbitrary :: Gen a) (\x -> toInteger x >= ((toInteger (maxBound :: a))+1) `div` 2))
    specify "minWord" $ (toIntegralNormalizing (minBound :: a) :: b) `shouldBe` (0 :: b)
    specify "minWord+1" $ (toIntegralNormalizing ((minBound :: a)+1) :: b) `shouldBe` (1 :: b)
    specify "maxInt-1" $ toInteger (toIntegralNormalizing (fromJust $ toIntegral ((maxBound :: b)-1) :: a) :: b) `shouldBe` toInteger (maxBound :: b) - 1
    specify "maxInt" $ toInteger (toIntegralNormalizing (maxBound :: b) :: b) `shouldBe` toInteger (maxBound :: b)
    specify "maxInt+1" $ toInteger (toIntegralNormalizing ((fromJust $ toIntegral (maxBound :: b) :: a)+1) :: b) `shouldBe` toInteger (minBound :: b)
    specify "maxInt+2" $ toInteger (toIntegralNormalizing ((fromJust $ toIntegral (maxBound :: b) :: a)+2) :: b) `shouldBe` toInteger (minBound :: b) + 1
    specify "maxWord-1" $ (toIntegralNormalizing ((maxBound :: a)-1) :: b) `shouldBe` (-2 :: b)
    specify "maxWord" $ (toIntegralNormalizing (maxBound :: a) :: b) `shouldBe` (-1 :: b)
    specify "Integer representable numbers" $ forAll lowerGen (\x -> toInteger ((toIntegralNormalizing x) :: b) === toInteger x)
    specify "Not Integer representable numbers" $ forAll upperGen (\x -> toInteger ((toIntegralNormalizing x) :: b) === (toInteger x) - (toInteger (maxBound :: a)) - 1)

specCastHomomorphic :: (Integral a, Arbitrary a, Show a, Integral b) => (a -> b) -> Spec
specCastHomomorphic f = do
  describe "Int128 -> Int64 is homomorphic" $ modifyMaxSuccess (const 5000) $ do
    specify "addition distributes" $ property $ \a b -> f (a + b) == f a + f b
    specify "multiplication distributes" $ property $ \a b -> f (a * b) == f a * f b
    specify "negation distributes" $ property $ \a -> f (-a) == - f a

tests :: Spec
tests = do
  describe "Numeric types" $ do
    describe "Int64" $ do
      specify "minBound toInteger" $ toInteger (minBound :: Int64) `shouldBe` (- 2^(63::Integer))
      specify "minBound fromInteger" $ (minBound :: Int64) `shouldBe` fromInteger (- 2^(63::Integer))
      specify "maxBound toInteger" $ toInteger (maxBound :: Int64) `shouldBe` (2^(63::Integer) - 1)
      specify "maxBound fromInteger" $ (maxBound :: Int64) `shouldBe` fromInteger (2^(63::Integer) - 1)
      arithmeticSpecsInt smallGenInt64
      arithmeticSpecs smallGenInt64
    describe "Word64" $ do
      specify "minBound toInteger" $ toInteger (minBound :: Word64) `shouldBe` (0 :: Integer)
      specify "minBound fromInteger" $ (minBound :: Word64) `shouldBe` fromInteger (0 :: Integer)
      specify "maxBound toInteger" $ toInteger (maxBound :: Word64) `shouldBe` (2^(64::Integer) - 1)
      specify "maxBound fromInteger" $ (maxBound :: Word64) `shouldBe` fromInteger (2^(64::Integer) - 1)
      arithmeticSpecsWord smallGenWord64
      arithmeticSpecs smallGenWord64
    describe "Int128" $ do
      specify "minBound toInteger" $ toInteger (minBound :: Int128) `shouldBe` (- 2^(127::Integer))
      specify "minBound fromInteger" $ (minBound :: Int128) `shouldBe` fromInteger (- 2^(127::Integer))
      specify "maxBound toInteger" $ toInteger (maxBound :: Int128) `shouldBe` (2^(127::Integer) - 1)
      specify "maxBound fromInteger" $ (maxBound :: Int128) `shouldBe` fromInteger (2^(127::Integer) - 1)
      arithmeticSpecsInt smallGenInt128
      arithmeticSpecs smallGenInt128
    describe "Word128" $ do
      specify "minBound toInteger" $ toInteger (minBound :: Word128) `shouldBe` (0 :: Integer)
      specify "minBound fromInteger" $ (minBound :: Word128) `shouldBe` fromInteger (0 :: Integer)
      specify "maxBound toInteger" $ toInteger (maxBound :: Word128) `shouldBe` (2^(128::Integer) - 1)
      specify "maxBound fromInteger" $ (maxBound :: Word128) `shouldBe` fromInteger (2^(128::Integer) - 1)
      arithmeticSpecsWord smallGenWord128
      arithmeticSpecs smallGenWord128
    describe "Conversion Int64/Word64" $ do
      specCastIntWord (negNumGen :: Gen Int64) (nonNegNumGen :: Gen Int64) (arbitrary :: Gen Word64)
      specCastWordInt (arbitrary :: Gen Word64) (arbitrary :: Gen Int64)
    describe "Conversion Int128/Word128" $ do
      specCastIntWord (negNumGen :: Gen Int128) (nonNegNumGen :: Gen Int128) (arbitrary :: Gen Word128)
      specCastWordInt (arbitrary :: Gen Word128) (arbitrary :: Gen Int128)
    specCastHomomorphic (toIntegralNormalizing :: Int128 -> Int64)
    specCastHomomorphic (toIntegralNormalizing :: Word128 -> Word64)
