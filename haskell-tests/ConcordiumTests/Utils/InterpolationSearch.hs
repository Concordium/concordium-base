{-# LANGUAGE MultiWayIf #-}

module ConcordiumTests.Utils.InterpolationSearch where

import Control.Monad.Trans.State.Strict
import Data.Functor.Identity
import Test.Hspec
import Test.QuickCheck

import Concordium.Utils.InterpolationSearch
import Control.Monad.Trans
import Data.Word

-- | A list used for unit tests of the interpolation search.
inputList :: [(Int, String)]
inputList =
    [ (1, "a"),
      (1, "b"),
      (1, "c"),
      (2, "d"),
      (3, "e"),
      (3, "f"),
      (5, "g"),
      (6, "h"),
      (6, "i"),
      (6, "j")
    ]

-- | Run 'interpolationSearchFirstM' on a subsection of 'inputList'.
runListTest ::
    -- | Search key
    Int ->
    -- | Low index
    Int ->
    -- | High index
    Int ->
    Maybe (Int, String)
runListTest key low high = runIdentity $ interpolationSearchFirstM lu key (low, inputList !! low) (high, inputList !! high)
  where
    lu i
        | i <= low = error "Index below lower bound"
        | i >= high = error "Index above upper bound"
        | otherwise = pure (inputList !! i)

-- | Test cases running 'interpolationSearchFirstM' on 'inputList' with different target keys.
listTests :: Spec
listTests = do
    let fullListTest key = runListTest key 0 (length inputList - 1)
    it "key 0" $ fullListTest 0 `shouldBe` Nothing
    it "key 1" $ fullListTest 1 `shouldBe` Just (0, "a")
    it "key 2" $ fullListTest 2 `shouldBe` Just (3, "d")
    it "key 3" $ fullListTest 3 `shouldBe` Just (4, "e")
    it "key 4" $ fullListTest 4 `shouldBe` Nothing
    it "key 5" $ fullListTest 5 `shouldBe` Just (6, "g")
    it "key 6" $ fullListTest 6 `shouldBe` Just (7, "h")
    it "key 7" $ fullListTest 7 `shouldBe` Nothing

-- | State used in 'generalSearchTest'. This tracks the interval in which the target can be found
--  (if it is present).
data InterpolationState' index key value = InterpolationState
    { targetKey :: key,
      lowIndex :: index,
      lowKey :: key,
      lowValue :: value,
      highIndex :: index,
      highKey :: key,
      highValue :: value
    }
    deriving (Show)

-- The choice of sizes for 'TestIndex' and 'TestKey' are made to give reasonable coverage
-- of different cases in 'generalSearchTest'. If the space of keys is too large, then many
-- cases will be "not found". If the space of indexes is too large (with respect to the keys),
-- then many cases will be "found".
type TestIndex = Word16
type TestKey = Word8
type TestVal = String

type InterpolationState = InterpolationState' TestIndex TestKey TestVal

-- | Test 'interpolationSearchFirstM' by generating the input array on demand.
--  This progressively tracks the interval of the array in which the result may be found (if
--  present). Each successive query is expected to be within the interval, and the interval is
--  updated accordingly. When the search is complete, the interval must have been sufficiently
--  narrowed to fully determine the result.
generalSearchTest :: Property
generalSearchTest = forAll startState doTest
  where
    -- The start state defines the interval and target for the search.
    startState :: Gen InterpolationState
    startState = do
        lowIndex <- arbitrary
        lowKey <- arbitrary
        lowValue <- arbitrary
        highIndex <- chooseBoundedIntegral (lowIndex, maxBound)
        if highIndex /= lowIndex
            then do
                -- The interval is not trivial.
                highKey <- chooseBoundedIntegral (lowKey, maxBound)
                highValue <- arbitrary
                targetKey <-
                    frequency
                        [ (1, chooseBoundedIntegral (minBound, lowKey)),
                          (1, chooseBoundedIntegral (highKey, maxBound)),
                          (18, chooseBoundedIntegral (lowKey, highKey))
                        ]
                return InterpolationState{..}
            else do
                -- The interval is trivial
                let highKey = lowKey
                let highValue = lowValue
                targetKey <-
                    frequency
                        [ (1, chooseBoundedIntegral (minBound, lowKey)),
                          (1, chooseBoundedIntegral (highKey, maxBound)),
                          (18, chooseBoundedIntegral (lowKey, highKey))
                        ]
                return InterpolationState{..}
    -- The lookup function checks that the index is inside the search interval and
    -- returns a key between the endpoints and an arbitrary value.
    -- The search interval is then redefined by updating the low or high endpoint to
    -- the supplied index, so that it contains the target.
    lu :: TestIndex -> StateT InterpolationState Gen (TestKey, TestVal)
    lu ix = do
        st@InterpolationState{..} <- get
        if
            | ix <= lowIndex -> error "Look-up below low index"
            | ix >= highIndex -> error "Look-up above high index"
            | targetKey < lowKey || targetKey > highKey -> error "Target out of lookup range"
            | otherwise -> do
                newKey <- lift $ chooseBoundedIntegral (lowKey, highKey)
                newValue <- lift arbitrary
                put $!
                    if newKey < targetKey
                        then st{lowIndex = ix, lowKey = newKey, lowValue = newValue}
                        else st{highIndex = ix, highKey = newKey, highValue = newValue}
                return (newKey, newValue)
    -- Run the search and check that the result is consistent with the final search interval.
    doTest st = do
        (res, endSt) <-
            runStateT
                ( interpolationSearchFirstM
                    lu
                    (targetKey st)
                    (lowIndex st, (lowKey st, lowValue st))
                    (highIndex st, (highKey st, highValue st))
                )
                st
        return $ counterexample ("End state: " ++ show endSt ++ " => " ++ show res) $ case res of
            Nothing ->
                label "Not found" $
                    label
                        "Outside bound"
                        (targetKey endSt < lowKey endSt || targetKey endSt > highKey endSt)
                        .||. label
                            "In empty range"
                            ( (lowIndex endSt + 1 === highIndex endSt)
                                .&. (lowKey endSt < targetKey endSt)
                                .&. (targetKey endSt < highKey endSt)
                            )
            Just (resIndex, resVal) ->
                label "Found" $
                    label
                        "Lowest key"
                        ( (lowKey st === targetKey st)
                            .&. (resIndex === lowIndex st)
                            .&. (resVal === lowValue st)
                        )
                        .||. label
                            "Non-trivial"
                            ( (lowIndex endSt + 1 === highIndex endSt)
                                .&. (lowKey endSt < highKey endSt)
                                .&. (resIndex === highIndex endSt)
                                .&. (resVal === highValue endSt)
                                .&. (targetKey endSt === highKey endSt)
                            )

tests :: Spec
tests = describe "interpolationSearchFirstM" $ do
    it "arbitrary test" $ withMaxSuccess 10000 generalSearchTest
    describe "list unit tests" listTests
