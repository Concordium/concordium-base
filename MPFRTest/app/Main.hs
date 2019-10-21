{-|
Tests MPFR operations through hmpfr, randomized and in parallel. It is important to compile and run this with parallel execution enabled (see https://hspec.github.io/parallel-spec-execution.html).
HSpec might choose how many tests to actually run in parallel, so make sure that there is at least some parallelization, which, in combination with many numbers in memory, is the point of this test.
Note that depending on the randomness, the execution time of some tests can vary largely.
-}

{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeSynonymInstances #-}
module Main where

-- import qualified Data.Map.Strict as Map

import Control.Monad
import Control.Concurrent
import Control.Concurrent.Async
import Data.List
import qualified Data.Sequence as Seq
import Data.Sequence (Seq((:<|)), (|>), (<|))

import Data.Number.MPFR (MPFR)
import qualified Data.Number.MPFR as MPFR
import Data.Number.MPFR.Assignment as MPFR
import Data.Number.MPFR.Internal as MPFR.Internal
import Data.Number.MPFR.FFIhelper as MPFR.FFIhelper

import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck as QC

-- * Utilities

newtype MPFRUnaryOp = MPFRUnaryOp (MPFR.RoundMode -> MPFR.Precision -> MPFR -> MPFR)
newtype MPFRBinaryOp = MPFRBinaryOp (MPFR.RoundMode -> MPFR.Precision -> MPFR -> MPFR -> MPFR)
data MPFROp = MPFROpUnary MPFRUnaryOp
            | MPFROpBinary MPFRBinaryOp
  deriving Show

instance Show MPFRUnaryOp where
  show _ = "<MPFR unary operation>"

instance Show MPFRBinaryOp where
  show _ = "<MPFR binary operation>"

-- randomStatePointer :: MPFR.Internal.Ptr MPFR.FFIhelper.GmpRandState
-- randomStatePointer = MPFR.newRandomStatePointer

-- rand :: MPFR.Precision -> Gen MPFR
-- rand p = do
--   return $ MPFR.urandomb randomStatePointer p

-- randList :: MPFR.Precision -> Int -> Gen [MPFR]
-- randList p n = return $ replicate n $ MPFR.urandomb randomStatePointer p

-- | Generate an MPFR number from a random Int.
-- NOTE: MPFR.urandomb does not seem to work (results in the same number on repeated calls),
-- see https://github.com/michalkonecny/hmpfr/blob/master/demo/Demo.hs.
mpfrGen :: MPFR.Precision -> Gen MPFR
mpfrGen p = do
  i <- elements ([-1000..1000] :: [Int])
  return $! MPFR.fromInt MPFR.Near p i


-- NOTE: The choice of operations here might be important to tweak the tests. Some might be very expensive on some arguments, some might make the results quickly be infinity or zero.
mpfrUnaries :: [MPFRUnaryOp]
mpfrUnaries = map MPFRUnaryOp [ MPFR.sqrt, MPFR.sqr, MPFR.log, MPFR.exp -- These operations seem to be fast
                              -- , MPFR.sin, MPFR.cos, MPFR.tan -- These operations seem to me much slower than the test
                              -- , MPFR.sinh -- This can be very slow
                              ]

mpfrBinaries :: [MPFRBinaryOp]
mpfrBinaries = map MPFRBinaryOp [MPFR.add, MPFR.sub , MPFR.mul, MPFR.div
                                ]

mpfrOps :: [MPFROp]
mpfrOps = map MPFROpUnary mpfrUnaries ++ map MPFROpBinary mpfrBinaries

unaryAppGen :: MPFR.Precision -> Gen (MPFRUnaryOp, MPFR)
unaryAppGen p = do
  op <- elements mpfrUnaries
  x <- mpfrGen p
  return (op, x)

binaryAppGen :: MPFR.Precision -> Gen (MPFRBinaryOp, MPFR, MPFR)
binaryAppGen p = do
  op <- elements mpfrBinaries
  x <- mpfrGen p
  y <- mpfrGen p
  return (op, x, y)

runUnaryOp :: MPFR.Precision -> Property
runUnaryOp p = do
  forAll (unaryAppGen p) $ \(MPFRUnaryOp op, x) ->
    let !res = op MPFR.Near p x -- make sure the library call is made
    in res === res

runBinaryOp :: MPFR.Precision -> Property
runBinaryOp p = do
  forAll (binaryAppGen p) $ \(MPFRBinaryOp op, x, y) ->
    let !res = op MPFR.Near p x y -- make sure the library call is made
    in res === res
  -- forAll (binaryAppGen p) $ \(MPFRBinaryOp op, x, y) -> op MPFR.Near p x y === op MPFR.Near p x y
  -- forAll (rand p)
  --   (\x -> forAll (rand p)
  --     (\y -> let !res = op MPFR.Near p x y in res === res))
  -- y :: MPFR <- rand p
  -- let !res = op MPFR.Near p x y
  -- return $ property $ res == res

-- TODO maybe want to run just one operation
  -- with shuffle can at least permute list
  -- TODO make generator combining op and two parameters!


-- * Tests

-- p :: MPFR.Precision
-- p = 1000

-- ** Example computations

-- Compute e using Newton series up to n with MPFR precision p
-- e ~= sum_{k=0}^{n} (1/k!)
eNewton :: Int -> MPFR.Precision -> MPFR
eNewton n p =
  refine 1 1 (MPFR.one)
  where
    refine k fac e | k == n = e
                   | otherwise = let fac' = k*fac in
                       refine (k+1) fac' $ MPFR.add MPFR.Near p e (MPFR.divi MPFR.Near p MPFR.one fac')

-- ** Allocation tests (test for memory leaks)

-- | Sum up the given amount of random MPFR numbers with the given precision.
-- This can be used to detect memory leaks that would occur because of
-- the allocation of intermediate results.
simpleSum
  :: Int
  -> MPFR.Precision
  -> IO ()
simpleSum nNumbers p = do
  putStrLn $ "Running simpleSum with " ++ show nNumbers ++ " MPFR numbers..."
  !numbers <- take nNumbers <$> (generate $ infiniteListOf $ mpfrGen p)
  let sum = foldl' (MPFR.add MPFR.Near p) MPFR.zero numbers
  putStrLn $ "Sum: " ++ show sum
  let sum1 = foldl' (MPFR.add MPFR.Near p) MPFR.one numbers
  putStrLn $ "Sum+1: " ++ show sum1


-- ** Stress tests

-- *** Simple random test

-- | Run randomly chosen unary and binary MPFR operations on random arguments in parallel.
runRandomOps :: Int -> Int -> MPFR.Precision -> Spec
runRandomOps nParallel runs p = do
  describe "Random MPFR operations on random arguments" $ modifyMaxSuccess (const runs) $ do
    replicateM_ nParallel $ do
      specify "MPFR binary op" $ runBinaryOp p
      specify "MPFR unary op" $ runUnaryOp p

-- *** More sophisticated random test

-- | Apply the given operation to the first (or first/second and first/third) elements in the list and append the result(s) to the end of the list. The list maintains its length.
-- stepSuccessiveOp :: MPFR.Precision -> Seq MPFR -> MPFROp -> Seq MPFR
-- stepSuccessiveOp p lastResults op =
stepSuccessiveOp :: MPFR.Precision -> MPFROp -> Seq MPFR -> Seq MPFR
stepSuccessiveOp p op lastResults =
  case op of
    MPFROpUnary (MPFRUnaryOp unaryOp) ->
      let x:<|rest = lastResults
          !x' = unaryOp MPFR.Near p x in
        rest |>x'
    MPFROpBinary (MPFRBinaryOp binaryOp) ->
      let x:<|y:<|z:<|rest = lastResults
          !xy = binaryOp MPFR.Near p x y
          !xz = binaryOp MPFR.Near p x z in
        (z <| rest) |> xy |> xz

-- TODO might be interesting to see what results actual come out of this, maybe infinity...


runSuccessiveOps :: MPFR.Precision -> [MPFROp] -> Seq MPFR -> Seq MPFR
runSuccessiveOps p ops initialNumbers =
  foldr (stepSuccessiveOp p) initialNumbers ops

-- successiveOpInst :: MPFR.Precision -> Int -> Int -> Gen ([MPFROp], [MPFR])
-- successiveOpInst p nNumbers nOps = do
--   ops <- infiniteListOf $ elements mpfrOps
--   numbers <- randList p nNumbers
--   return (take nOps ops, numbers)

runSuccessiveRandomOps :: MPFR.Precision -> Int -> Int -> IO ()
runSuccessiveRandomOps p nNumbers nOps = do
  ops_ <- generate $ infiniteListOf $ elements mpfrOps
  let ops = take nOps ops_
  numbers_ <- generate $ infiniteListOf $ mpfrGen p
  let numbers = take nNumbers numbers_
  putStrLn $ "Running MPFR stress test with " ++ show (take 20 numbers) ++ " and more"
  putStrLn $ "Number of operations: " ++ show (length ops)
  putStrLn $ "Number of numbers kept in memory: " ++ show (length numbers)
  let !res = runSuccessiveOps p ops (Seq.fromList numbers)
  let nans :: Int = foldl' (\cnt m -> if MPFR.isNaN m then cnt+1 else cnt) 0 res
  let front20 = Seq.take 20 res
  let back20 = Seq.drop (nNumbers-20) res
  let back2000 = Seq.drop (nNumbers-2000) res
  let foldedres = foldl' (MPFR.add MPFR.Near p) MPFR.zero res
  putStrLn $ "Front 20 of result list: " ++ show front20
  putStrLn $ "Back  20 of result list: " ++ show back20
  -- putStrLn $ "Result list: " ++ show res
  -- putStrLn $ "Back2000 of result list: " ++ show back2000
  -- TODO The following two taking really long when the /operations/ are 10^6 instead of 10^5 (forever?) - why?
    -- But counting NaNs succeeded once
  putStrLn $ "NaNs: " ++ show nans ++ " (" ++ show ((fromIntegral nans :: Double)*100 / (fromIntegral nNumbers)) ++ "%)"
  putStrLn $ "Sum of all resulting numbers: " ++ show foldedres
  
-- | Apply the given number of randomly chosen MPFR operations to a list of arguments of the given length.
-- Unary operations are applied to the first element in the list, binary operations to the
-- first and second as well as first and third. The results are added to the end of the list.
-- This way, a list of MPFR numbers of the initial length is kept throughout the whole test.
-- The number of new MPFR allocations should be nUnaryOps+2*nBinaryOps
runSuccessiveRandomOpsParallel :: Int -> Int -> Int -> MPFR.Precision -> IO ()
runSuccessiveRandomOpsParallel nParallel nNumbers nOps p =
  replicateConcurrently_ nParallel $ do
    putStrLn $ "Random MPFR operations on random arguments and previous results, keeping "
               ++ show nNumbers ++ " MPFR numbers at all times"
    runSuccessiveRandomOps p nNumbers nOps -- keeping many MPFR numbers
  -- describe ("Random MPFR operations on random arguments and previous results, keeping " ++ show nNumbers ++ " MPFR numbers at all times") $ modifyMaxSuccess (const 1) $ do -- NOTE: only need one run on this level
  --   replicateM_ nParallel $ do
  --     specify "Run" $ runSuccessiveRandomOps p nNumbers nOps -- keeping many MPFR numbers


-- *** Testing MPFR operations on MPFRs and integers

-- | A deterministic stress test for MPFR producing a list of pairs of MPFR numbers and (very large) Integers.
-- The objective is to have many allocations of large numbers, MPFR and Integer, because this /might/ cause issues.
-- Each pair of numbers in the list is created from the previous pair by adding constants.
runMixedMPFRInteger'
  :: MPFR.Precision -- ^ The precision for the MPFR numbers but also roughly the amount of bits for the Integers.
  -> Int -- ^ The length of the list to produce. Computation time and memory consumption should scale linearly in this parameter.
  -> IO ()
runMixedMPFRInteger' p nNumbers = do
  let !res = foldl' step [(MPFR.one, 0 :: Integer)] [0..nNumbers]
  let (sumM, sumI) = foldl' (\(m,i) (m',i') -> (MPFR.add MPFR.Near p m m', i+i')) (MPFR.zero, intInitial) res -- TODO maybe this is not even creating res as a whole list (but there is increasing memory consumption)
  putStrLn $ "Sum of all MPFRs: " ++ show sumM ++ "\n"
  -- NOTE: to show all digits, need another conversion function, but the following does not show the exponent?
    -- (fst $ MPFR.mpfrToString MPFR.Near (fromIntegral p) 2 sumM)
    ++ "Sum of all Integers: " ++ show sumI
  where
    mpfrInc = MPFR.pi MPFR.Near p -- use an irrational constant
    intInitial = 2^p :: Integer -- make the integers consume roughly the same amount of bits as the MPFRs
    intMax = 2 * intInitial :: Integer
    intInc = max (2*intInitial `div` (fromIntegral nNumbers)) 1 :: Integer  -- step linearly through the whole range of value of same bit-length (within intInitial..2*intInitial)
    step ((m,i):res) _ =
      let m' = MPFR.add MPFR.Near p m mpfrInc
          i' = case i of
                 intMax -> intInitial -- make sure the memory size of the Integer does not increase much
                 _ -> i + intInc
      in
        (m',i'):(m,i):res


runMixedMPFRInteger
  :: Int -- ^ The number of threads to use
  -> Int -- ^ The length of the list to produce. Computation time and memory consumption should scale linearly in this parameter.
  -> MPFR.Precision -- ^ The precision for the MPFR numbers but also roughly the amount of bits for the Integers.
  -> Spec
runMixedMPFRInteger nParallel nNumbers p =
  replicateM_ nParallel $
  specify ("Parallel Integer and MPFR operations, keeping "
                                   ++ show nNumbers ++ " MPFR numbers and large Integers in memory (~" ++ showNumBits nNumbers p ++ " for MPFR, similar amount for Integer)") $
  runMixedMPFRInteger' p nNumbers -- keeping many MPFR numbers


showNumBits :: Int -> MPFR.Precision -> String
showNumBits nNumbers p =
  let totalBits = nNumbers * (fromIntegral p)
      order = logBase 10.0 (fromIntegral totalBits) in
    "10^" ++ show order ++ " bits"

--- * Test slection

-- TODO make use of level specifying complexity of tests
-- NOTE: the time specification are from MSI laptop if not otherwise noted
-- tests :: Word -> Spec
-- tests lvl = describe "MPFRTest" $ parallel $ do
  -- it "eNewton" $ eNewton 10 p1 `shouldBe` eNewton 10 p1
  -- it "eNewton" $ eNewton 20 p1 `shouldBe` eNewton 20 p1
  -- it "eNewton" $ eNewton 1000 p1 `shouldBe` eNewton 900 p1 -- This succeeds as the precision is not enough to catch the difference
  -- it "eNewton" $ eNewton 300 p2 `shouldBe` eNewton 600 p2
  -- it "eNewton" $ eNewton 300 p3 `shouldBe` eNewton 600 p3
  -- runRandomOps 8 100000 100
  -- successive parallel: nParallel nNumbers nOps precision
  -- runSuccessiveRandomOpsParallel 8 10000 100000 p1
  -- runSuccessiveRandomOpsParallel 8 n5 n5 p3
  -- runSuccessiveRandomOpsParallel 4 n6 500000 p3 -- This is fine
  -- runSuccessiveRandomOpsParallel 1 n5 109111 p2 -- This is fine
  -- runSuccessiveRandomOpsParallel 1 n5 199111 p2 -- This does not termiante at least for long; it even prints front and back of result list! (32s/sometimes very long) with sin/cos/tan and sinh; without any special functions ~1.2s, with sin/cos/tan: 15-18s
  -- runSuccessiveRandomOpsParallel 4 n6 n7 p2 -- With only +,-,*,/ in 36s (also with just +,-), even this works; also with sqr/sqrt (get mostly NaNs then, but still 34-36s), also with exp/log; but not on X1, here it fails after having quickly reached 95% memory usage
  -- runSuccessiveRandomOpsParallel 4 n6 n6 p2
  -- runSuccessiveRandomOpsParallel 1 n5 199988 p2 -- Even here get fron 20 quite quickly; but the front 20 are the oldest...
  -- runSuccessiveRandomOpsParallel 4 1000 10000 10 p1
  -- runMixedMPFRInteger 4 n6 p3 -- with n7 memory is going beond limits; on first tests, the RAM consumption by the test seems to equal the showNumBits amount

main :: IO ()
main = do
  let p1 = fromIntegral (10::Int) :: MPFR.Precision
  let p2 = fromIntegral (10::Int)^(2::Int) :: MPFR.Precision
  let p3 = fromIntegral (10::Int)^(3::Int) :: MPFR.Precision
  let p4 = fromIntegral (10::Int)^(4::Int) :: MPFR.Precision
  let n2 = (10::Int)^(2::Int)
  let n3 = (10::Int)^(3::Int)
  let n4 = (10::Int)^(4::Int)
  let n5 = (10::Int)^(5::Int)
  let n6 = (10::Int)^(6::Int)
  let n7 = (10::Int)^(7::Int)
  let n8 = (10::Int)^(8::Int)
  let n9 = (10::Int)^(9::Int)
  runSuccessiveRandomOpsParallel 4 n6 n5 p2
  simpleSum n5 p2
