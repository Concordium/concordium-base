module Concordium.Utils.InterpolationSearch where

-- |Perform a (linear) interpolation search to find the first instance of the search key in
-- the given bounds. This is more efficient than a binary search when the keys are approximately
-- linearly distributed with respect to the indices.
--
-- PRECONDITIONS: For some @key :: index -> key@ and @val :: index -> value@
--   * The lookup function @lookupIx i@ returns @(key i, val i)@ for @lowIx <= i <= highIx@.
--   * @lowKey = key lowIx@ and @lowVal = val lowIx@.
--   * @highKey = key highIx@ and @highVal = val highIx@.
--   * For @lowIx <= i < highIx@, @key i <= key (i+1)@ (monotonicity).
--   * @lowIx <= highIx@.
--
-- POSTCONDITION:
--   * If the return value is @Just (i, v)@ then @lowIx <= i <= highIx@, @v = val i@,
--     @target = key i@, and for all @lowKey <= j < i@, @key j < target@.
--   * If the return value is @Nothing@ then there is no @i@ with @lowIx <= i <= highIx@ and
--     @target = key i@.
--
-- @lookupIx@ will only be invoked for indexes @lowIx < i < highIx@.
interpolationSearchFirstM ::
    (Monad m, Integral key, Integral index) =>
    -- |Function to look up the key and value at a specific index.
    (index -> m (key, value)) ->
    -- |Key to search for @target@.
    key ->
    -- |Lower bound of the search range @(lowIx, (lowKey, lowVal))@.
    (index, (key, value)) ->
    -- |Upper bound of the search range @(highIx, (highKey, highVal))@.
    (index, (key, value)) ->
    m (Maybe (index, value))
{-# INLINE interpolationSearchFirstM #-}
interpolationSearchFirstM lookupIx target low@(lowIx, (lowKey, lowVal)) high@(_, (highKey, _))
    | target < lowKey = return Nothing
    | target == lowKey = return $ Just (lowIx, lowVal)
    | target > highKey = return Nothing
    | otherwise =
        -- lowKey < target <= highKey
        search low high
  where
    -- Compute a new index @lIx < newIx < hIx@.
    -- Preconditions:
    --   * lIx + 1 < hIx
    --   * lKey < target <= hKey
    interpolate lIx lKey hIx hKey =
        lIx
            + fromInteger
                ( (toInteger (hIx - lIx) * (2 * toInteger (target - lKey) - 1))
                    `div` (2 * toInteger (hKey - lKey))
                )
    -- Do interpolation search between the lower and upper bounds.
    -- Preconditions:
    --   * @l = (lIx, (key lIx, val lIx))@, @h = (hIx, (key hIx, val hIx))@.
    --   * @key lIx < target <= key hIx@.
    --   * @lIx < hIx@ (this follows from the previous conditions by monotonicity of @key@).
    search l@(lIx, (lKey, _)) h@(hIx, (hKey, hVal))
        | lIx + 1 == hIx =
            if hKey == target
                then return $ Just (hIx, hVal)
                else return Nothing
        | otherwise = do
            let newIx = interpolate lIx lKey hIx hKey
            (newKey, newVal) <- lookupIx newIx
            if newKey < target
                then search (newIx, (newKey, newVal)) h
                else search l (newIx, (newKey, newVal))
