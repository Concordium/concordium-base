{-# LANGUAGE BangPatterns #-}
-- |Utility functions for serialization.
module Concordium.Utils.Serialization where

import Control.Monad
import qualified Data.ByteString as BS
import qualified Data.Map as Map
import Data.Serialize
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Word

-- * Length

-- |Put a length as a 64-bit (unsigned) integer.
putLength :: Putter Int
putLength = putWord64be . fromIntegral

-- |Get a length as a 64-bit (unsigned) integer.
getLength :: Get Int
getLength = do
    l <- fromIntegral <$> getWord64be
    if l < 0 then
        fail "Length must be non-negative (as a 64-bit signed value)"
    else
        return l

-- * ByteString

-- |Put a 'BS.ByteString' preceded by its length as a 64-bit (unsigned) integer.
putByteStringLen :: Putter BS.ByteString
putByteStringLen bs = putLength (BS.length bs) >> putByteString bs

-- |Get a 'BS.ByteString' preceded by its length as a 64-bit (unsigned) integer.
getByteStringLen :: Get BS.ByteString
getByteStringLen = do
    len <- getLength
    getByteString len

-- * Unicode string

-- |Put a 'T.Text' as UTF-8 encoded, preceded by its length in bytes as a 64-bit (unsigned) integer.
putUtf8 :: Putter T.Text
putUtf8 = putByteStringLen . TE.encodeUtf8

-- |Get a 'T.Text' UTF-8 encoded, preceded by its length in bytes as a 64-bit (unsigned) integer.
getUtf8 :: Get T.Text
getUtf8 = do
    bs <- getByteStringLen
    case TE.decodeUtf8' bs of
        Left e -> fail (show e)
        Right r -> return r

-- * Containers

-- |Put a 'Set.Set' by first putting the size, then putting the elements in ascending order.
putSafeSetOf
    :: Putter Word64
    -- ^How to put the size
    -> Putter a
    -- ^How to put a value
    -> Putter (Set.Set a)
putSafeSetOf pSize pVal s = pSize (fromIntegral (Set.size s)) >> mapM_ pVal (Set.toAscList s)

-- |Get a 'Set.Set', but enforce that the elements are ordered and distinct.
getSafeSetOf :: (Ord a) => Get a -> Get (Set.Set a)
getSafeSetOf g = do
        sz <- getWord64be
        getSafeSizedSetOf sz g

-- |Get a 'Set.Set' of specified size, but enforce that the elements are ordered and distinct.
getSafeSizedSetOf :: (Ord a, Integral s) => s -> Get a -> Get (Set.Set a)
getSafeSizedSetOf sz0 getter
        | sz0 <= 0 = return Set.empty
        | otherwise = do
            !f <- getter
            go f [f] (sz0 - 1)
    where
        go p l sz
            | sz <= 0 = return $ Set.fromDistinctDescList l
            | otherwise = do
                !v <- getter
                if p < v then
                    go v (v:l) (sz - 1)
                else
                    fail "elements not in ascending order"

-- |Put a 'Map.Map' by first putting the size and then putting the key-value pairs in
-- ascending order of keys.
putSafeMapOf
    :: Putter Word64
    -- ^How to put the size
    -> Putter k
    -- ^How to put a key
    -> Putter v
    -- ^How to put a value
    -> Putter (Map.Map k v)
putSafeMapOf putSize putKey putVal m = do
    putSize (fromIntegral (Map.size m))
    forM_ (Map.toAscList m) $ \(k, v) -> putKey k >> putVal v

-- |Get a 'Map.Map' of specified size, enforcing that the keys are ordered and distinct.
getSafeSizedMapOf :: (Ord k, Integral s) => s -> Get k -> Get v -> Get (Map.Map k v)
getSafeSizedMapOf sz0 getKey getVal
        | sz0 <= 0 = return Map.empty
        | otherwise = do
            !k <- getKey
            !v <- getVal
            go k [(k,v)] (sz0 - 1)
    where
        go pk l sz
            | sz <= 0 = return $ Map.fromDistinctDescList l
            | otherwise = do
                !k <- getKey
                if pk < k then do
                    !v <- getVal
                    go k ((k, v):l) (sz - 1)
                else
                    fail "keys not in ascending order"

-- |Get a 'Map.Map', enforcing that the keys are ordered and distinct.
getSafeMapOf :: (Ord k) => Get k -> Get v -> Get (Map.Map k v)
getSafeMapOf getKey getVal = do
        sz <- getWord64be
        getSafeSizedMapOf sz getKey getVal

-- * Utility

-- |Run a getter, but also return the 'ByteString' that was parsed.
-- FIXME: using 'remaining' may not be robust with respect to 'runGetPartial'.
--        However, the current approach is a work-around for the fact that
--        'lookAhead' updates 'bytesRead'.
getWithBytes :: Get a -> Get (a, BS.ByteString)
getWithBytes g = do
        (v, size) <- lookAhead $ do
            startRemain <- remaining
            v <- g
            endRemain <- remaining
            return (v, startRemain - endRemain)
        bytes <- label ("getting " ++ show size ++ " bytes") $ getByteString size
        return (v, bytes)