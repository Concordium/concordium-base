{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeSynonymInstances #-}

-- |
--Tests MPFR operations through hmpfr, randomized and in parallel. It is important to compile and run this with parallel execution enabled (see https://hspec.github.io/parallel-spec-execution.html).
--HSpec might choose how many tests to actually run in parallel, so make sure that there is at least some parallelization, which, in combination with many numbers in memory, is the point of this test.
--Note that depending on the randomness, the execution time of some tests can vary largely.
module Main where

import Prelude hiding (sum)

import Control.Concurrent.Async
import Data.List hiding (sum)
import Data.Sequence (Seq ((:<|)), (<|), (|>))
import qualified Data.Sequence as Seq

import Data.Number.MPFR (MPFR)
import qualified Data.Number.MPFR as MPFR

import Test.QuickCheck as QC

-- * Utilities

newtype MPFRUnaryOp = MPFRUnaryOp (MPFR.RoundMode -> MPFR.Precision -> MPFR -> MPFR)
newtype MPFRBinaryOp = MPFRBinaryOp (MPFR.RoundMode -> MPFR.Precision -> MPFR -> MPFR -> MPFR)
data MPFROp
    = MPFROpUnary MPFRUnaryOp
    | MPFROpBinary MPFRBinaryOp
    deriving (Show)

instance Show MPFRUnaryOp where
    show _ = "<MPFR unary operation>"

instance Show MPFRBinaryOp where
    show _ = "<MPFR binary operation>"

-- | Generate an MPFR number from a random Int.
-- NOTE: MPFR.urandomb does not seem to work (results in the same number on repeated calls),
-- see https://github.com/michalkonecny/hmpfr/blob/master/demo/Demo.hs.
mpfrGen :: MPFR.Precision -> Gen MPFR
mpfrGen p = do
    i <- elements ([-1000 .. 1000] :: [Int])
    return $! MPFR.fromInt MPFR.Near p i

-- NOTE: The choice of operations here might be important to tweak the tests. Some might be very expensive on some arguments, some might make the results quickly be infinity or zero.
mpfrUnaries :: [MPFRUnaryOp]
mpfrUnaries =
    map
        MPFRUnaryOp
        [ MPFR.sqrt,
          MPFR.sqr,
          MPFR.log,
          MPFR.exp -- These operations seem to be fast
          -- , MPFR.sin, MPFR.cos, MPFR.tan -- These operations seem to me much slower than the test
          -- , MPFR.sinh -- This can be very slow
        ]

mpfrBinaries :: [MPFRBinaryOp]
mpfrBinaries =
    map
        MPFRBinaryOp
        [ MPFR.add,
          MPFR.sub,
          MPFR.mul,
          MPFR.div
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

-- * Tests

-- ** Example computations

-- Compute e using Newton series up to n with MPFR precision p
-- e ~= sum_{k=0}^{n} (1/k!)
eNewton :: Int -> MPFR.Precision -> MPFR
eNewton n p =
    refine 1 1 (MPFR.one)
  where
    refine k fac e
        | k == n = e
        | otherwise =
            let fac' = k * fac
            in  refine (k + 1) fac' $ MPFR.add MPFR.Near p e (MPFR.divi MPFR.Near p MPFR.one fac')

-- ** Allocation tests (test for memory leaks)

-- | Sum up the given amount of random MPFR numbers with the given precision.
-- This can be used to detect memory leaks that would occur because of
-- the allocation of intermediate results.
simpleSum ::
    Int ->
    MPFR.Precision ->
    IO ()
simpleSum nNumbers p = do
    putStrLn $ "Running simpleSum with " ++ show nNumbers ++ " " ++ show (fromIntegral p :: Int) ++ "-bit MPFR numbers..."
    numbers <- take nNumbers <$> (generate $ infiniteListOf $ mpfrGen p)
    let sum = foldl' (MPFR.add MPFR.Near p) MPFR.zero numbers
    putStrLn $ "Sum: " ++ show sum

-- | Like 'simpleSum' but sum up the numbers twice (the second sum starting with the previous sum)
-- to make the numbers stay in memory.
simpleSumRepeated ::
    Int ->
    MPFR.Precision ->
    IO ()
simpleSumRepeated nNumbers p = do
    putStrLn $ "Running simpleSumRepeated with " ++ show nNumbers ++ " " ++ show (fromIntegral p :: Int) ++ "-bit MPFR numbers..."
    !numbers <- take nNumbers <$> (generate $ infiniteListOf $ mpfrGen p)
    let sum = foldl' (MPFR.add MPFR.Near p) MPFR.zero numbers
    putStrLn $ "Sum: " ++ show sum
    let sum2 = foldl' (MPFR.add MPFR.Near p) sum numbers
    putStrLn $ "2*Sum: " ++ show sum2

-- ** Stress tests

-- *** More sophisticated random test

-- | Apply the given operation to the first (or first/second and first/third) elements in the list and append the result(s) to the end of the list. The list maintains its length.
-- stepSuccessiveOp :: MPFR.Precision -> Seq MPFR -> MPFROp -> Seq MPFR
-- stepSuccessiveOp p lastResults op =
stepSuccessiveOp :: MPFR.Precision -> MPFROp -> Seq MPFR -> Seq MPFR
stepSuccessiveOp p op lastResults =
    case op of
        MPFROpUnary (MPFRUnaryOp unaryOp) ->
            let x :<| rest = lastResults
                !x' = unaryOp MPFR.Near p x
            in  rest |> x'
        MPFROpBinary (MPFRBinaryOp binaryOp) ->
            let x :<| y :<| z :<| rest = lastResults
                !xy = binaryOp MPFR.Near p x y
                !xz = binaryOp MPFR.Near p x z
            in  (z <| rest) |> xy |> xz

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
    let nans :: Int = foldl' (\cnt m -> if MPFR.isNaN m then cnt + 1 else cnt) 0 res
    let front20 = Seq.take 20 res
    let back20 = Seq.drop (nNumbers - 20) res
    -- let back2000 = Seq.drop (nNumbers-2000) res
    let foldedres = foldl' (MPFR.add MPFR.Near p) MPFR.zero res
    putStrLn $ "Front 20 of result sequence: " ++ show front20
    putStrLn $ "Back  20 of result sequence: " ++ show back20
    -- putStrLn $ "Result sequence: " ++ show res
    -- putStrLn $ "Back2000 of result sequence: " ++ show back2000
    putStrLn $ "NaNs: " ++ show nans ++ " (" ++ show ((fromIntegral nans :: Double) * 100 / (fromIntegral nNumbers)) ++ "%)"
    putStrLn $ "Sum of all resulting numbers: " ++ show foldedres

-- | Apply the given number of randomly chosen MPFR operations to a sequence of MPFR numbers of the given length.
-- Unary operations are applied to the first element in the sequence, binary operations to the
-- first and second as well as first and third. The results are added to the end of the sequence.
-- This way, a sequence of MPFR numbers of the initial length is kept throughout the whole test.
-- The number of new MPFR allocations should be nUnaryOps+2*nBinaryOps
runSuccessiveRandomOpsParallel ::
    -- | The number of threads to use
    Int ->
    -- | The length of the sequence to produce.
    Int ->
    -- | The number of operations to run on the sequence.
    Int ->
    -- | The precision for the MPFR numbers but also roughly the amount of bits for the Integers.
    MPFR.Precision ->
    IO ()
runSuccessiveRandomOpsParallel nParallel nNumbers nOps p =
    replicateConcurrently_ nParallel $ do
        putStrLn $
            "Random MPFR operations on random arguments and previous results, keeping "
                ++ show nNumbers
                ++ " MPFR numbers at all times"
                ++ ", amounting to ~"
                ++ showNumBits nNumbers p
                ++ " in memory"
        runSuccessiveRandomOps p nNumbers nOps -- keeping many MPFR numbers

-- *** Testing MPFR operations on MPFRs and integers

-- | A deterministic stress test for MPFR producing a list of pairs of MPFR numbers and (very large) Integers.
-- The objective is to have many allocations of large numbers, MPFR and Integer, because this /might/ cause issues.
-- Each pair of numbers in the list is created from the previous pair by adding constants.
runMixedMPFRInteger ::
    -- | The precision for the MPFR numbers but also roughly the amount of bits for the Integers.
    MPFR.Precision ->
    -- | The length of the list to produce. Computation time and memory consumption should scale linearly in this parameter.
    Int ->
    IO ()
runMixedMPFRInteger p nNumbers = do
    -- NOTE This does not seem to keep all numbers in memory at the same time (even though
    -- there is increasing and significant memory usage over time) but that is okay
    -- as we just want the allocations (which must happen).
    let !res = foldl' step [(MPFR.one, 0 :: Integer)] [0 .. nNumbers]
    let (sumM, sumI) = foldl' (\(m, i) (m', i') -> (MPFR.add MPFR.Near p m m', i + i')) (MPFR.zero, intInitial) res
    putStrLn $
        "Sum of all MPFRs: "
            ++ show sumM
            ++ "\n"
            -- NOTE: to show all digits, need another conversion function, but the following does not show the exponent?
            -- (fst $ MPFR.mpfrToString MPFR.Near (fromIntegral p) 2 sumM)
            ++ "Sum of all Integers: "
            ++ show sumI
  where
    mpfrInc = MPFR.pi MPFR.Near p -- use an irrational constant
    intInitial = 2 ^ p :: Integer -- make the integers consume roughly the same amount of bits as the MPFR limbs (not counting overhead)
    intMax = 2 * intInitial :: Integer
    intInc = max (2 * intInitial `div` (fromIntegral nNumbers)) 1 :: Integer -- step linearly through the whole range of value of same bit-length (within intInitial..2*intInitial)
    step ((m, i) : res) _ =
        let m' = MPFR.add MPFR.Near p m mpfrInc
            -- make sure the memory size of the Integer does not increase much
            i' = if i == intMax then intInitial else i + intInc
        in  (m', i') : (m, i) : res
    step [] _ = error "Implementation error."

runMixedMPFRIntegerParallel ::
    -- | The number of threads to use
    Int ->
    -- | The length of the list to produce. Computation time and memory consumption should scale linearly in this parameter.
    Int ->
    -- | The precision for the MPFR numbers but also roughly the amount of bits for the Integers.
    MPFR.Precision ->
    IO ()
runMixedMPFRIntegerParallel nParallel nNumbers p =
    replicateConcurrently_ nParallel $ do
        putStrLn $
            "Parallel Integer and MPFR operations, keeping "
                ++ show nNumbers
                ++ " MPFR numbers and large Integers in memory (~"
                ++ showNumBits nNumbers p
                ++ " for MPFR numbers)"
        runMixedMPFRInteger p nNumbers -- keeping many MPFR numbers

-- NOTE: This is just a very rough estimate on how many bits hmpfr uses to represent the given amount of numbers.
-- Source: https://hackage.haskell.org/package/hmpfr-0.4.4/docs/src/Data-Number-MPFR-FFIhelper.html,
-- https://hackage.haskell.org/package/hmpfr-0.4.4/docs/Data-Number-MPFR-FFIhelper.html#t:MPFR
calcNumBits :: Int -> MPFR.Precision -> Int
calcNumBits nNumbers p =
    -- TODO Complete/correct by looking at hmpfr code
    let fixedPerNumber :: Int =
            -- Haskell MPFR data structure
            32 -- sign
                + 64 -- precision
                + 64 -- exponent
                + 64 -- pointer to the limbs
        bitsPerLimb :: Int =
            64 -- the actual limb bits
            -- TODO not sure whether this is the actual number of limbs
        nLimbs :: Int =
            (fromIntegral p) `div` 64
                + (if (fromIntegral p :: Int) `mod` 64 > 0 then 1 else 0)
    in  nNumbers * (fixedPerNumber + nLimbs * bitsPerLimb)

showNumBits :: Int -> MPFR.Precision -> String
showNumBits nNumbers p =
    let totalBits = calcNumBits nNumbers p
        order :: Double = logBase 10.0 (fromIntegral totalBits)
    in  "10^" ++ show order ++ " bits"

--- * Test slection

main :: IO ()
main = do
    -- let p1 = fromIntegral (10::Int) :: MPFR.Precision
    let p2 = fromIntegral (10 :: Int) ^ (2 :: Int) :: MPFR.Precision
    let p3 = fromIntegral (10 :: Int) ^ (3 :: Int) :: MPFR.Precision
    let p4 = fromIntegral (10 :: Int) ^ (4 :: Int) :: MPFR.Precision
    let p5 = fromIntegral (10 :: Int) ^ (5 :: Int) :: MPFR.Precision
    -- let n2 = (10::Int)^(2::Int)
    -- let n3 = (10::Int)^(3::Int)
    -- let n4 = (10::Int)^(4::Int)
    let n5 = (10 :: Int) ^ (5 :: Int)
    let n6 = (10 :: Int) ^ (6 :: Int)
    let n7 = (10 :: Int) ^ (7 :: Int)
    -- let n8 = (10::Int)^(8::Int)
    -- let n9 = (10::Int)^(9::Int)

    -- successive parallel: nParallel nNumbers nOps precision
    runSuccessiveRandomOpsParallel 4 n5 n6 p2
    runSuccessiveRandomOpsParallel 4 n6 n5 p2
    runSuccessiveRandomOpsParallel 4 n6 n6 p2
    runMixedMPFRIntegerParallel 4 n5 p3
    runMixedMPFRIntegerParallel 4 n5 p4
    runMixedMPFRIntegerParallel 4 n5 p5
    runMixedMPFRIntegerParallel 4 n6 p2
    simpleSum n5 p2
    simpleSum n6 p2
    simpleSum n7 p2
    simpleSum n5 p3
    simpleSum n6 p3
    simpleSumRepeated n5 p2
    simpleSumRepeated n6 p2
    simpleSumRepeated n5 p3
    simpleSumRepeated n6 p3
