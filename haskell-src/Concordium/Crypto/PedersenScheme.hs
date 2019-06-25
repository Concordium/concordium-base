{-# LANGUAGE DeriveGeneric, GeneralizedNewtypeDeriving, ForeignFunctionInterface , TypeFamilies, FlexibleContexts, FlexibleInstances  #-}
-- |This module provides a prototype implementation of 
-- Pedersen Scheme
-- on the curve BLS12-381 
module Concordium.Crypto.PedersenScheme
 where

import           Concordium.Crypto.ByteStringHelpers
import           Data.Word
import           System.IO.Unsafe
import           Foreign.Ptr
import           Data.Serialize
import           Data.ByteString.Internal (create) 
import qualified Data.ByteString  as B
import           Data.ByteString (ByteString, empty) 
import qualified Data.FixedByteString as FBS
import           Data.FixedByteString (FixedByteString)
import           Foreign.C.Types

-- input [n:Word32] number of values
-- input [key_bytes:: Ptr Word8] a byte array to fill with key bytes
foreign import ccall "pedersen_commitment_key" rs_commitment_key :: Word32 -> Ptr Word8 -> IO ()
--input: number of vlaues ,  key bytes, values, commitment, randomness
foreign import ccall "pedersen_commit" rs_commit :: Word32 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 ->IO CInt 
--input:: number of values, key bytes, values, commitment, randomness 
foreign import ccall "pedersen_open" rs_open :: Word32 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 ->  IO CInt 
--input:: [n] number of values, values bytes of size (n * field element seize)
foreign import ccall "pedersen_random_values" rs_rand_values :: Word32 -> Ptr Word8 -> IO ()

groupElementSize :: Int
groupElementSize = 48

fieldElementSize :: Int  
fieldElementSize = 32  

randomnessSize :: Int
randomnessSize = fieldElementSize

data ValueSize
instance FBS.FixedLength ValueSize where
    fixedLength _ = fieldElementSize


data RandomnessSize
instance FBS.FixedLength RandomnessSize  where
    fixedLength _ =  randomnessSize

data CommitmentSize
instance FBS.FixedLength CommitmentSize  where
    fixedLength _ = groupElementSize



-- |Commitment key public .  unknown size
data CommitmentKey = CommitmentKey (ByteString) Int
    deriving (Eq)
instance Serialize CommitmentKey where
    put (CommitmentKey key n) = put (key,n)
    get = do (b,n) <- get 
             return $ CommitmentKey b n 
instance Show CommitmentKey where
    show (CommitmentKey key _) = byteStringToHex  key

data Value = Value (FixedByteString ValueSize)
    deriving(Eq)
instance Serialize Value where
    put (Value v) = putByteString $ FBS.toByteString v
    get = Value . FBS.fromByteString <$> getByteString (FBS.fixedLength (undefined::ValueSize))
type Values = [Value]
    

data Randomness = Randomness (FixedByteString RandomnessSize)
    deriving (Eq)
instance Serialize Randomness where
    put (Randomness c) = putByteString $ FBS.toByteString c
    get = Randomness. FBS.fromByteString <$> getByteString (FBS.fixedLength (undefined::RandomnessSize))

data Commitment = Commitment (FixedByteString CommitmentSize)
    deriving (Eq)
instance Serialize Commitment where
    put (Commitment c) = putByteString $ FBS.toByteString c
    get = Commitment . FBS.fromByteString <$> getByteString (FBS.fixedLength (undefined::CommitmentSize))
instance Show Commitment where
    show (Commitment c) = byteStringToHex $ FBS.toByteString c

-- generates a new commitment key 
-- input [n] the number of values to commit
-- output [IO ck]  a commitment key
newCommitmentKey :: Int -> IO CommitmentKey
newCommitmentKey n = 
    do bytes <- create bytesSize $ \ck -> rs_commitment_key (fromIntegral n) ck 
       return $ CommitmentKey bytes n 
    where bytesSize = (n+1) * groupElementSize

    
--input: key bytes, values, commitment, randomness
-- commiting to Values [v] with CommitmentKey [ck]
-- it's the caller responsibility to ensure that the key has the proper size
commit :: CommitmentKey -> Values -> IO (Commitment, Randomness)
commit (CommitmentKey ck n) vs = do commitment <- FBS.mallocFixedByteString 
                                    randomness <- FBS.mallocFixedByteString 
                                    suc <- withByteStringPtr ck $ \ckPtr ->
                                             withByteStringPtr valuesBytes $ \valuesPtr ->
                                              FBS.withPtr commitment $ \commitmentPtr ->
                                                FBS.withPtr randomness $ \randomnessPtr ->
                                                  rs_commit (fromIntegral n) ckPtr valuesPtr commitmentPtr randomnessPtr
                                    return (Commitment commitment, Randomness randomness)
    where
        valuesBytes = B.concat $ map (\(Value v) -> FBS.toByteString v) vs



--opening a commitment 
open :: CommitmentKey -> Randomness -> Values -> Commitment -> Bool
open (CommitmentKey ck n) (Randomness r) vs (Commitment c) = unsafePerformIO $
    do suc <- withByteStringPtr ck $ \ckPtr ->
                withByteStringPtr valuesBytes $ \valuesPtr -> 
                    FBS.withPtr c $ \cPtr -> 
                        FBS.withPtr r $ \rPtr -> 
                            rs_open (fromIntegral n) ckPtr valuesPtr cPtr rPtr
       putStrLn(show suc)
       case suc of
            1 -> return True  
            _ -> return False
         where
             valuesBytes = B.concat $ map (\(Value v) -> FBS.toByteString v) vs



-- rand values for testing
-- note that the order of values is the reverse of that generated by rust
-- it shouldn't matter
randValues:: Int -> IO Values
randValues n = do b <- bytes
                  return $  map (Value . FBS.fromByteString) (f b [])
          where
              bytes = create (n * fieldElementSize) $ \vs -> rs_rand_values (fromIntegral n) vs 
              f b xs | b==empty =  xs
                     | otherwise = let (h, t) = B.splitAt (FBS.fixedLength (undefined::ValueSize)) b in 
                                     f t (h:xs)

test :: Int -> IO Bool
test n = do ck <- newCommitmentKey n
            vs <- randValues n
            (c, r) <- commit ck vs
            ck' <- newCommitmentKey n
            return $ open ck r vs c

