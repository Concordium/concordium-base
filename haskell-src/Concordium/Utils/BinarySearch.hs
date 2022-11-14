-- |This module implements binary search on vectors.
module Concordium.Utils.BinarySearch where

import qualified Data.Vector as Vec

-- |Perform a binary search on a sorted vector, returning the index and the value, if found.
-- The first argument is a function that maps a value to its search key.
-- The elements of the vector must be sorted in ascending order with respect to the key, with no
-- duplicate keys.
binarySearchI :: (Ord k) => (a -> k) -> Vec.Vector a -> k -> Maybe (Int, a)
binarySearchI valToKey vec key = search 0 (Vec.length vec - 1)
  where
    search lowIndex highIndex = case compare lowIndex highIndex of
        LT ->
            let midIndex = lowIndex + (highIndex - lowIndex) `div` 2
                midVal = vec Vec.! midIndex
            in  case compare key (valToKey midVal) of
                    LT -> search lowIndex (midIndex - 1)
                    EQ -> Just (midIndex, midVal)
                    GT -> search (midIndex + 1) highIndex
        EQ ->
            let val = vec Vec.! lowIndex
            in  if key == valToKey val
                    then Just (lowIndex, val)
                    else Nothing
        GT -> Nothing

-- |Perform a binary search on a sorted vector, returning the value, if found.
-- The first argument is a function that maps a value to its search key.
-- The elements of the vector must be sorted in ascending order with respect to the key, with no
-- duplicate keys.
binarySearch :: (Ord k) => (a -> k) -> Vec.Vector a -> k -> Maybe a
binarySearch valToKey vec key = snd <$> binarySearchI valToKey vec key

-- |Perform a binary search on a sorted vector, returning the index and the value, if found.
-- The first argument is a function that resolves an entry in a monad.
-- Resolving entries should be idempotent, and there should be no requirements on which
-- entries are resolved, how often and in which order.
-- The second argument is a function that maps a value to its search key.
-- The elements of the vector must be sorted in ascending order with respect to the key, with no
-- duplicate keys.
binarySearchIM ::
    (Ord k, Monad m) =>
    (b -> m a) ->
    (a -> k) ->
    Vec.Vector b ->
    k ->
    m (Maybe (Int, a))
binarySearchIM resolve valToKey vec key = search 0 (Vec.length vec - 1)
  where
    search lowIndex highIndex = case compare lowIndex highIndex of
        LT -> do
            let midIndex = lowIndex + (highIndex - lowIndex) `div` 2
            midVal <- resolve $ vec Vec.! midIndex
            case compare key (valToKey midVal) of
                LT -> search lowIndex (midIndex - 1)
                EQ -> return $ Just (midIndex, midVal)
                GT -> search (midIndex + 1) highIndex
        EQ -> do
            val <- resolve $ vec Vec.! lowIndex
            return $!
                if key == valToKey val
                    then Just (lowIndex, val)
                    else Nothing
        GT -> return Nothing
