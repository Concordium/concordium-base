{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DerivingVia #-}

-- |Utility functions for serialization.
module Concordium.Utils.Serialization where

import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as BSS
import qualified Data.Map as Map
import Data.Serialize
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

-- * Length

-- |Put a length as a 64-bit (unsigned) integer.
putLength :: Putter Int
{-# INLINE putLength #-}
putLength = putWord64be . fromIntegral

-- |Get a length as a 64-bit (unsigned) integer.
getLength :: Get Int
getLength = do
    l <- fromIntegral <$> getWord64be
    if l < 0
        then fail "Length must be non-negative (as a 64-bit signed value)"
        else return l

-- * ByteString

-- |Put a 'BS.ByteString' preceded by its length as a 64-bit (unsigned) integer.
putByteStringLen :: Putter BS.ByteString
putByteStringLen bs = putLength (BS.length bs) >> putByteString bs

-- |Put a 'LBS.ByteString' preceded by its length as a 64-bit (unsigned) integer.
putLazyByteStringLen :: Putter LBS.ByteString
putLazyByteStringLen bs = putLength (fromIntegral (LBS.length bs)) >> putLazyByteString bs

-- |Get a 'BS.ByteString' preceded by its length as a 64-bit (unsigned) integer.
getByteStringLen :: Get BS.ByteString
getByteStringLen = do
    len <- getLength
    getByteString len

-- |Get a 'LBS.ByteString' preceded by its length as a 64-bit (unsigned) integer.
-- This creates a copy of the underlying bytes.
getLazyByteStringLen :: Get LBS.ByteString
getLazyByteStringLen = do
    len <- getLength
    getLazyByteString (fromIntegral len)

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

-- |Put a list of elements by first putting the size using 'putLength', then
-- putting the elements from head to tail.
putListOf ::
    -- |How to put a value
    Putter a ->
    Putter [a]
putListOf pVal xs = putLength (length xs) <> mapM_ pVal xs

-- |Get a list of elements. Dual to 'putListOf'.
getListOf ::
    -- |How to get a value.
    Get a ->
    Get [a]
getListOf gVal = do
    sz <- getLength
    replicateM sz gVal

-- |Put a 'Set.Set' by first putting the size, then putting the elements in ascending order.
putSafeSetOf ::
    -- |How to put a value
    Putter a ->
    Putter (Set.Set a)
putSafeSetOf pVal s = putLength (Set.size s) >> mapM_ pVal (Set.toAscList s)

-- |Get a 'Set.Set', but enforce that the elements are ordered and distinct.
getSafeSetOf :: (Ord a) => Get a -> Get (Set.Set a)
getSafeSetOf g = do
    sz <- getLength
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
            if p < v
                then go v (v : l) (sz - 1)
                else fail "elements not in ascending order"

-- |Put a 'Map.Map' by putting the key-value pairs in
-- ascending order of keys.
putSafeSizedMapOf ::
    -- |How to put a key
    Putter k ->
    -- |How to put a value
    Putter v ->
    Putter (Map.Map k v)
putSafeSizedMapOf putKey putVal m =
    forM_ (Map.toAscList m) $ \(k, v) -> putKey k >> putVal v

-- |Put a 'Map.Map' by first putting the size and then putting the key-value pairs in
-- ascending order of keys.
putSafeMapOf ::
    -- |How to put a key
    Putter k ->
    -- |How to put a value
    Putter v ->
    Putter (Map.Map k v)
putSafeMapOf putKey putVal m = do
    putLength (Map.size m)
    putSafeSizedMapOf putKey putVal m

-- |Get a 'Map.Map' of specified size, enforcing that the keys are ordered and distinct.
getSafeSizedMapOf :: (Ord k, Integral s) => s -> Get k -> Get v -> Get (Map.Map k v)
getSafeSizedMapOf sz0 getKey getVal
    | sz0 <= 0 = return Map.empty
    | otherwise = do
        !k <- getKey
        !v <- getVal
        go k [(k, v)] (sz0 - 1)
  where
    go pk l sz
        | sz <= 0 = return $ Map.fromDistinctDescList l
        | otherwise = do
            !k <- getKey
            if pk < k
                then do
                    !v <- getVal
                    go k ((k, v) : l) (sz - 1)
                else fail "keys not in ascending order"

-- |Get a 'Map.Map', enforcing that the keys are ordered and distinct.
getSafeMapOf :: (Ord k) => Get k -> Get v -> Get (Map.Map k v)
getSafeMapOf getKey getVal = do
    sz <- getLength
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

-- |Get a bytestring with length serialized as big-endian 4 bytes.
getByteStringWord32 :: Get ByteString
getByteStringWord32 = do
    len <- fromIntegral <$> getWord32be
    getByteString len

-- |Put a bytestring with length serialized as big-endian 4 bytes.
-- This function assumes the string length fits into 4 bytes.
putByteStringWord32 :: Putter ByteString
putByteStringWord32 bs =
    let len = fromIntegral (BS.length bs)
    in  putWord32be len <> putByteString bs

-- |Get a bytestring with length serialized as big-endian 2 bytes.
getByteStringWord16 :: Get ByteString
getByteStringWord16 = do
    len <- fromIntegral <$> getWord16be
    getByteString len

-- |Put a bytestring with length serialized as big-endian 2 bytes.
-- This function assumes the string length fits into 2 bytes.
putByteStringWord16 :: Putter ByteString
putByteStringWord16 bs =
    let len = fromIntegral (BS.length bs)
    in  putWord16be len <> putByteString bs

-- |Get a bytestring with length serialized as big-endian 4 bytes.
getShortByteStringWord32 :: Get ShortByteString
getShortByteStringWord32 = do
    len <- fromIntegral <$> getWord32be
    getShortByteString len

-- |Put a bytestring with length serialized as big-endian 4 bytes.
-- This function assumes the string length fits into 4 bytes.
putShortByteStringWord32 :: Putter ShortByteString
putShortByteStringWord32 bs =
    let len = fromIntegral (BSS.length bs)
    in  putWord32be len <> putShortByteString bs

-- |Get a bytestring with length serialized as big-endian 2 bytes.
getShortByteStringWord16 :: Get ShortByteString
getShortByteStringWord16 = do
    len <- fromIntegral <$> getWord16be
    getShortByteString len

-- |Put a bytestring with length serialized as big-endian 2 bytes.
-- This function assumes the string length fits into 2 bytes.
putShortByteStringWord16 :: Putter ShortByteString
putShortByteStringWord16 bs =
    let len = fromIntegral (BSS.length bs)
    in  putWord16be len <> putShortByteString bs

-- |Serialize a Maybe value
-- Just v is serialized with a word8 tag 1 followed by the serialization of the value
-- Nothing is seralized with a word8 tag 0.
putMaybe :: Putter a -> Putter (Maybe a)
putMaybe p (Just v) = do
    putWord8 1
    p v
putMaybe _ Nothing = putWord8 0

-- |Deserialize a Maybe value
-- Expects a leading 0 or 1 word8, 1 signaling Just and 0 signaling Nothing.
-- NB: This method is stricter than the Serialize instance method in that it only allows
-- tags 0 and 1, whereas the Serialize.get method allows any non-zero tag for Just.
getMaybe :: Get a -> Get (Maybe a)
getMaybe g =
    getWord8
        >>= \case
            0 -> return Nothing
            1 -> Just <$> g
            n -> fail $ "encountered invalid tag when deserializing a Maybe '" ++ show n ++ "'"

-- |Serialize False as a single 0 byte, True as a 1 byte.
putBool :: Putter Bool
putBool False = putWord8 0
putBool True = putWord8 1

-- |Read a byte, trying to interpret it as a bool strictly.
-- 0 is False, 1 is True, everything else is invalid
getBool :: Get Bool
getBool =
    getWord8 >>= \case
        0 -> return False
        1 -> return True
        n -> fail $ "Unrecognized boolean value: " ++ show n
