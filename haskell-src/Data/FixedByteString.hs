{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -Wno-redundant-constraints #-}

module Data.FixedByteString where

import Control.Monad
import Control.Monad.ST.Strict
import Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Short as BSS
import qualified Data.ByteString.Short.Internal as BSS
import Data.Data (Data, Typeable)
import Data.Primitive.ByteArray
import Data.Primitive.Types
import Data.Word
import Foreign.Marshal
import Foreign.Ptr
import Foreign.Storable
import System.IO.Unsafe

import Control.Monad.Primitive (touch)

class FixedLength a where
    -- |Returns the length (in bytes) of a @FixedByteString a@.
    -- The argument must not be evaluated.
    fixedLength :: a -> Int

-- |A fixed-length byte string.  The length of the byte string
-- is determined by the type parameter @a@, which should be an
-- instance of 'FixedLength', as @fixedLength (undefined :: a)@.
newtype FixedByteString a = FixedByteString ByteArray
    deriving (Data, Typeable)

-- |NB: We need to be very careful with compiler optimizations here.
-- The issue is that newPinnedByteArray does not depend on f as the argument (only on f)
-- and so if we have two create f1 create f2 with the same type argument a the compiler
-- could concievably lift the newPinnedByteArray len out and thus only allocate the one
-- array which would be __very bad__.
-- For this reason this function should not be inlined.
-- Analogous reasoning applies do functions below that do the same copying.
{-# INLINE create #-}
create :: forall a. FixedLength a => (Ptr Word8 -> IO ()) -> IO (FixedByteString a)
create f = snd <$> createWith f

{-# NOINLINE createWith #-}
createWith :: forall a b. FixedLength a => (Ptr Word8 -> IO b) -> IO (b, FixedByteString a)
createWith f = do
    mbarr <- newPinnedByteArray len
    let !mutable = mutableByteArrayContents mbarr
    r <- f mutable
    touch mbarr -- DO NOT REMOVE. GHC does strange things if you do leading to weird errors
    -- The issue probably that the dependency between mbarr and ptr is lost
    -- and so the optimizer sometimes seems to move the copy before the foreign
    -- call is done, leading to corrupt data.
    barr <- newByteArray len
    copyMutableByteArray barr 0 mbarr 0 len
    fbarr <- unsafeFreezeByteArray barr
    return (r, FixedByteString fbarr)
  where
    len = fixedLength (undefined :: a)

unsafeCreate :: FixedLength a => (Ptr Word8 -> IO ()) -> FixedByteString a
unsafeCreate = unsafePerformIO . create

-- |Create a 'FixedByteString' from a list of bytes.  If the list is too short,
-- the remaining bytes are filled with @0@.  If it is too long, only the first
-- @fixedLength (undefined :: a)@ bytes are used.
pack :: forall a. FixedLength a => [Word8] -> FixedByteString a
pack = FixedByteString . byteArrayFromListN limit . pad
  where
    limit = fixedLength (undefined :: a)
    pad xs = take limit $ xs ++ repeat 0

-- |Convert a 'FixedByteString' to a list of bytes.
unpack :: forall a. FixedLength a => FixedByteString a -> [Word8]
unpack (FixedByteString fbs) = foldrByteArray (:) [] fbs

-- |Create a 'FixedByteString' from a list of bytes in reverse order.
-- If the list is too short, the remaining bytes are filled with @0@.
-- If it is too long, only the first @fixedLength (undefined :: a)@
-- bytes are used.
fromReversedBytes :: forall a. FixedLength a => [Word8] -> FixedByteString a
fromReversedBytes = unsafeCreate . fill (limit - 1)
  where
    limit = fixedLength (undefined :: a)
    fill n l ptr = when (n >= 0) $
        case l of
            [] -> do
                fillBytes ptr 0x00 (n + 1)
            (b : bs) -> do
                pokeByteOff ptr n b
                fill (n - 1) bs ptr

-- |Convert a 'FixedByteString' to a list of bytes in reverse order.
toReversedBytes :: forall a. (FixedLength a) => FixedByteString a -> [Word8]
toReversedBytes (FixedByteString fbs) = toB (len - 1)
  where
    len = fixedLength (undefined :: a)
    toB n
        | n < 0 = []
        | otherwise = getB n : toB (n - 1)
    getB n = indexByteArray fbs n

getByte :: forall a. (FixedLength a) => FixedByteString a -> Int -> Word8
getByte (FixedByteString fbs) n
    | n < 0 = error $ "getByte: cannot get a negative index (" ++ show n ++ ")"
    | n >= (fixedLength (undefined :: a)) = error $ "getByte: index (" ++ show n ++ ") out of bounds"
    | otherwise = indexByteArray fbs n

instance FixedLength a => Storable (FixedByteString a) where
    sizeOf _ = fixedLength (undefined :: a)
    alignment _ = 1
    peek ptr = create (\p' -> copyBytes p' (castPtr ptr) (fixedLength (undefined :: a)))
    poke ptr (FixedByteString fbs) = copyByteArrayToAddr (castPtr ptr) fbs 0 (fixedLength (undefined :: a))

-- |Convert an 'Integer' to a 'FixedByteString'.  The encoding is big endian and modulo @2 ^ (8 * fixedLength undefined)@.
encodeInteger :: forall a. FixedLength a => Integer -> FixedByteString a
encodeInteger z0 = unsafeCreate (initBytes z0 (fixedLength (undefined :: a) - 1))
  where
    initBytes z off ptr
        | off >= 0 = do
            pokeByteOff ptr off (fromInteger z :: Word8)
            initBytes (shiftR z 8) (off - 1) ptr
        | otherwise = return ()

-- |Convert a 'FixedByteString' to an unsigned 'Integer' with big endian encoding.
decodeIntegerUnsigned :: forall a. FixedLength a => FixedByteString a -> Integer
decodeIntegerUnsigned fbs = foldl (\acc v -> acc `shiftL` 8 .|. toInteger (v :: Word8)) 0 (unpack fbs)

-- |Convert a 'FixedByteString' to a signed 'Integer' with big endian encoding.
decodeIntegerSigned :: forall a. (FixedLength a) => FixedByteString a -> Integer
decodeIntegerSigned (FixedByteString fbs) = doDecode 0 0 fbs
  where
    len = fixedLength (undefined :: a)
    doDecode i v ptr
        | i >= len = v
        | i == 0 =
            let (b :: Word8) = indexByteArray ptr i
            in  if testBit b 8
                    then doDecode 1 (shiftL (-1) 8 .|. toInteger b) ptr
                    else doDecode 1 (toInteger b) ptr
        | otherwise =
            let (b :: Word8) = indexByteArray ptr i
            in  doDecode (i + 1) (shiftL v 8 .|. toInteger b) ptr

instance (FixedLength a) => Eq (FixedByteString a) where
    FixedByteString p1 == FixedByteString p2 = p1 == p2
    {-# INLINE (==) #-}

-- |NB: In our use case this is lexicographic ordering for the current (0.6.4) version of the library. However
-- it is dependant on what the underlying library does and must be monitored closely
-- between major version changes.
instance (FixedLength a) => Ord (FixedByteString a) where
    compare (FixedByteString f1) (FixedByteString f2) = compare f1 f2
    {-# INLINE compare #-}

mapBytes :: forall a. (FixedLength a) => (Word8 -> Word8) -> FixedByteString a -> FixedByteString a
mapBytes f (FixedByteString fbs) = runST comp
  where
    comp :: forall s. ST s (FixedByteString a)
    comp = do
        barr <- newByteArray len
        mapM_ (\i -> writeByteArray barr i (f (indexByteArray fbs i))) [0 .. len - 1]
        FixedByteString <$> unsafeFreezeByteArray barr
    len = fixedLength (undefined :: a)

zipWithBytes :: forall a. (FixedLength a) => (Word8 -> Word8 -> Word8) -> FixedByteString a -> FixedByteString a -> FixedByteString a
zipWithBytes f (FixedByteString fbs1) (FixedByteString fbs2) = runST comp
  where
    comp :: forall s. ST s (FixedByteString a)
    comp = do
        barr <- newByteArray len
        mapM_ (\i -> writeByteArray barr i (f (indexByteArray fbs1 i) (indexByteArray fbs2 i))) [0 .. len - 1]
        FixedByteString <$> unsafeFreezeByteArray barr
    len = fixedLength (undefined :: a)

constantFixedByteString :: forall a. FixedLength a => Word8 -> FixedByteString a
constantFixedByteString c = runST comp
  where
    comp :: forall s. ST s (FixedByteString a)
    comp = do
        barr <- newByteArray len
        fillByteArray barr 0 len c
        FixedByteString <$> unsafeFreezeByteArray barr
    len = fixedLength (undefined :: a)

instance (FixedLength a) => Bounded (FixedByteString a) where
    minBound = constantFixedByteString 0x00
    maxBound = constantFixedByteString 0xff

instance (FixedLength a) => Enum (FixedByteString a) where
    succ fbs = if overflow then error "succ: overflow" else pack newBytes
      where
        doSucc b (True, l) = (b == 0xff, (b + 1) : l)
        doSucc b (False, l) = (False, b : l)
        (overflow, newBytes) = foldr doSucc (True, []) (unpack fbs)
    pred fbs = if underflow then error "pred: underflow" else pack newBytes
      where
        doPred b (True, l) = (b == 0x00, (b - 1) : l)
        doPred b (False, l) = (False, b : l)
        (underflow, newBytes) = foldr doPred (True, []) (unpack fbs)
    toEnum = encodeInteger . toInteger
    fromEnum = fromInteger . decodeIntegerSigned

instance (FixedLength a) => Bits (FixedByteString a) where
    (.&.) = zipWithBytes (.&.)
    (.|.) = zipWithBytes (.|.)
    xor = zipWithBytes xor
    complement = mapBytes complement
    shiftL fbs n =
        fromReversedBytes $
            (take (n `div` 8) (repeat 0)) ++ fst (foldr (\b (r, carry) -> ((shiftL b (n `mod` 8) .|. carry) : r, shiftR b (8 - (n `mod` 8)))) ([], 0) (toReversedBytes fbs))

    -- We treat FixedByteStrings as unsigned, meaning shiftR does not do sign extension
    shiftR fbs n =
        pack $
            (take (n `div` 8) (repeat 0)) ++ fst (foldr (\b (r, carry) -> ((shiftR b (n `mod` 8) .|. carry) : r, shiftL b (8 - (n `mod` 8)))) ([], 0) (unpack fbs))
    rotateL fbs n0 = shiftL fbs n .|. shiftR fbs (bitLen - n)
      where
        bitLen = (8 * fixedLength (undefined :: a))
        n = n0 `mod` bitLen
    rotateR fbs n0 = shiftR fbs n .|. shiftL fbs (bitLen - n)
      where
        bitLen = (8 * fixedLength (undefined :: a))
        n = n0 `mod` bitLen
    isSigned _ = False
    bitSize _ = 8 * fixedLength (undefined :: a)
    bitSizeMaybe _ = Just (8 * fixedLength (undefined :: a))
    popCount fbs = sum (popCount <$> unpack fbs)
    testBit fbs n
        | n >= 8 * fixedLength (undefined :: a) = False
        | otherwise = testBit (getByte fbs ((n `div` 8) `mod` (fixedLength (undefined :: a)))) (n `mod` 8)
    bit = fromReversedBytes . bitBytes
      where
        bitBytes n
            | n < 0 = []
            | n < 8 = [bit n]
            | otherwise = 0 : bitBytes (n - 8)

-- |Convert to a short 'BS.ByteString'.  The 'ByteString' will share the underlying
-- pointer of the 'FixedByteString'.
toShortByteString :: forall a. FixedLength a => FixedByteString a -> BSS.ShortByteString
toShortByteString (FixedByteString (ByteArray ptr)) = BSS.SBS ptr
{-# INLINE toShortByteString #-}

{-# INLINE toByteString #-}
toByteString :: forall a. FixedLength a => FixedByteString a -> BS.ByteString
toByteString = BSS.fromShort . toShortByteString

-- |Copy a 'BSS.ByteString' into a 'FixedByteString'.  If the 'ByteString' is too short,
-- the later bytes will be filled with @0@; if it is too long, only the first bytes
-- will be copied.
{-# INLINE fromShortByteString #-}
fromShortByteString :: forall a. (FixedLength a) => BSS.ShortByteString -> FixedByteString a
fromShortByteString (BSS.SBS bs')
    -- If the string is already the correct length (the common case when
    -- deserializing) then we do nothing.
    | sizeofByteArray bs == len = FixedByteString bs
    | otherwise = runST comp
  where
    {-# INLINE comp #-}
    comp :: forall s. ST s (FixedByteString a)
    comp = do
        barr <- newByteArray len
        fillByteArray barr 0 len 0
        copyByteArray barr 0 bs 0 (min len (sizeofByteArray bs))
        FixedByteString <$> unsafeFreezeByteArray barr
    len = fixedLength (undefined :: a)
    bs = ByteArray bs'

{-# INLINE fromByteString #-}
fromByteString :: forall a. (FixedLength a) => BS.ByteString -> FixedByteString a
fromByteString = fromShortByteString . BSS.toShort

-- -- |Use the FixedByteString as a pointer.
-- withPtr :: FixedByteString s -> (Ptr Word8 -> IO a) -> IO a
-- withPtr (FixedByteString p) = withForeignPtr p

-- |Access the pointer encapsulated by a 'FixedByteString'.
-- If the IO action writes to the pointer the changes will not be reflected back.
{-# NOINLINE withPtrReadOnly #-}
withPtrReadOnly :: forall s a. FixedLength s => FixedByteString s -> (Ptr Word8 -> IO a) -> IO a
withPtrReadOnly (FixedByteString ba) f = allocaBytes size $ \ptr -> do
    copyByteArrayToAddr ptr ba 0 size
    f ptr
  where
    size = fixedLength (undefined :: s)

-- |Access the pointer encapsulated by a 'FixedByteString' via a pure function.
{-# NOINLINE withPtrReadOnlyST #-}
withPtrReadOnlyST :: forall s a. FixedLength s => FixedByteString s -> (forall state. Ptr Word8 -> ST state a) -> a
withPtrReadOnlyST (FixedByteString ba) f = runST comp
  where
    comp :: forall state. ST state a
    comp = do
        mba <- newPinnedByteArray size
        copyByteArray mba 0 ba 0 size
        let !mutable = mutableByteArrayContents mba
        r <- f mutable
        touch mba
        return r
    size = fixedLength (undefined :: s)

-- |Read the first 8 bytes as a Word64 in __host__ endian. This will lead to
-- problems if the size of the fixed bytestring is not at least 8 bytes, hence
-- this function is unsafe.
{-# INLINE unsafeReadWord64 #-}
unsafeReadWord64 :: FixedLength s => FixedByteString s -> Word64
unsafeReadWord64 (FixedByteString fbs) = indexByteArray fbs 0

-- |Read a primitive value from the byte string at the given offset. __The
-- offset is given in elements of type a rather than in bytes.__ This function
-- does no bounds checking and its behaviour is undefined if an attempt is made
-- to read past the end of the byte array.
{-# INLINE unsafeIndexByteArray #-}
unsafeIndexByteArray ::
    forall a s.
    (Prim a, FixedLength s) =>
    FixedByteString s ->
    -- | Offset in elements of the type @a@. Must be non-negative.
    Int ->
    a
unsafeIndexByteArray (FixedByteString fbs) = indexByteArray fbs

-- |Compare two fixed byte strings. This function's behaviour is undefined if
-- the offset and length do not satisfy the precondition mentioned below, hence
-- it is marked unsafe.
unsafeCompareFixedByteStrings ::
    FixedLength s =>
    -- |Start of the subsection (offset). Must be @<= fixedLength _@
    Int ->
    -- |Length of the slice in bytes. Offset + length must be @<= fixedLength _@ and length must be non-negative.
    Int ->
    FixedByteString s ->
    FixedByteString s ->
    Ordering
unsafeCompareFixedByteStrings offset len (FixedByteString fbs1) (FixedByteString fbs2) = compareByteArrays fbs1 offset fbs2 offset len
{-# INLINE unsafeCompareFixedByteStrings #-}

-- |Read the first 8 bytes as a Word64 in __big__ endian.  If there are fewer
-- than 8 bytes, these will be used as the low-order bytes (i.e. we pad with 0s on
-- the left).
readWord64be :: FixedLength s => FixedByteString s -> Word64
readWord64be = foldl (\acc v -> acc `shiftL` 8 .|. fromIntegral (v :: Word8)) 0 . take 8 . unpack
