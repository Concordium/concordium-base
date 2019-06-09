{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE TemplateHaskell #-}
{-| This module provides a framework for deriving interfaces to pedersen
    commitment schemes, parametrized by different base curves.

    The following assumptions are made.

      * Group elements have fixed, predetermined size.
      * Field elements have fixed, predetermined size.

    As a consequence the size of values which can be commited is fixed size
    predetermined up front.
-}
module Concordium.Crypto.PedersenScheme.TH where

import           Concordium.Crypto.ByteStringHelpers
import           Data.Word
import           System.IO.Unsafe
import           Foreign.Ptr
import           Data.Serialize
import qualified Data.Serialize.Put as Put
import qualified Data.Serialize.Get as Get
import           Data.ByteString.Internal (create) 
import qualified Data.ByteString  as B
import           Data.ByteString (ByteString, empty) 
import qualified Data.FixedByteString as FBS
import           Data.FixedByteString (FixedByteString)
import           Foreign.C.Types

import Language.Haskell.TH

-- |Parameters used to generate the commitment scheme.
data InternalParameters = InternalParameters {
  genCommitmentKeyName :: Name,
  commitName :: Name,
  openName :: Name,
  randomValuesName :: Name,
  parameters :: Parameters
  } deriving(Show)

mkForeignImports :: InternalParameters -> Q [Dec]
mkForeignImports InternalParameters{parameters=Parameters{..},..} = do
  -- Generate commitment key
  -- input [n:Word32] number of values
  -- input [key_bytes:: Ptr Word8] a byte array to fill with key bytes
  genCommitImport <- forImpD cCall unsafe cGenCommitmentKeyName genCommitmentKeyName [t|Word32 -> Ptr Word8 -> IO ()|]
  --input: number of vlaues ,  key bytes, values, commitment, randomness
  commitImport <- forImpD cCall unsafe cCommitName commitName [t| Word32 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 ->IO CInt|]
  --input:: number of values, key bytes, values, commitment, randomness 
  openImport <- forImpD cCall unsafe cOpenName openName [t| Word32 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO CInt|]
  --input:: [n] number of values, values bytes of size (n * field element seize)
  randomValuesImport <- forImpD cCall unsafe cRandomValuesName randomValuesName [t|Word32 -> Ptr Word8 -> IO ()|]
  return [genCommitImport,commitImport,openImport,randomValuesImport]

mkDataTysAndTerms :: InternalParameters -> Q [Dec]
mkDataTysAndTerms InternalParameters{parameters=Parameters{..},..} =
  [d|
     data OpenResult =
       InvalidCommitmentKey
       | InvalidValues
       | InvalidRandomness
       | InvalidCommitment
       | Reject
       | OK
       deriving(Eq, Show)
     
     data CommitResult =
       CommitInvalidCommitmentKey
       | CommitInvalidValues
       | CommitSuccess !Commitment !Randomness
       deriving(Eq, Show)

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


     -- Commitment key. Public and preteremined in some way at chain genesis.
     -- The second parameter is the number of commited values this commitment key
     -- corresponds to.
     -- TODO: Can we not derive this parameter from the length of the bytestring and parameters?
     data CommitmentKey = CommitmentKey !ByteString !Int
         deriving (Eq)

     instance Serialize CommitmentKey where
         put (CommitmentKey key n) = put key <> Put.putInt32be (fromIntegral n)
         get = do b <- get
                  n <- Get.getInt32be 
                  return $ CommitmentKey b (fromIntegral n)

     instance Show CommitmentKey where
         show (CommitmentKey key n) = "(" ++ show n ++ ", " ++ byteStringToHex key ++ ")"
     
     newtype Value = Value (FixedByteString ValueSize)
         deriving(Eq)

     instance Show Value where
       show (Value v) = byteStringToHex (FBS.toByteString v)

     instance Serialize Value where
         put (Value v) = putByteString $ FBS.toByteString v
         get = Value . FBS.fromByteString <$> getByteString (FBS.fixedLength (undefined::ValueSize))

     type Values = [Value]

     newtype Randomness = Randomness (FixedByteString RandomnessSize)
         deriving (Eq)

     instance Show Randomness where
       show (Randomness r) = byteStringToHex (FBS.toByteString r)

     instance Serialize Randomness where
         put (Randomness c) = putByteString $ FBS.toByteString c
         get = Randomness. FBS.fromByteString <$> getByteString (FBS.fixedLength (undefined::RandomnessSize))


     newtype Commitment = Commitment (FixedByteString CommitmentSize)
         deriving (Eq)
     instance Serialize Commitment where
         put (Commitment c) = putByteString $ FBS.toByteString c
         get = Commitment . FBS.fromByteString <$> getByteString (FBS.fixedLength (undefined::CommitmentSize))
     instance Show Commitment where
         show (Commitment c) = byteStringToHex $ FBS.toByteString c

     -- Generates a new commitment key for the given number of values to commit.
     newCommitmentKey :: Int -> IO CommitmentKey
     newCommitmentKey n = 
         do bytes <- create bytesSize $ \ck -> $(varE genCommitmentKeyName) (fromIntegral n) ck 
            return $ CommitmentKey bytes n 
         where bytesSize = (n+1) * groupElementSize

     --input: key bytes, values, commitment, randomness
     -- commiting to Values [v] with CommitmentKey [ck]
     -- it's the caller responsibility to ensure that the key has the proper size
     commit :: CommitmentKey -> Values -> IO CommitResult
     commit (CommitmentKey ck n) vs = do 
         commitment <- FBS.mallocFixedByteString 
         randomness <- FBS.mallocFixedByteString 
         suc <- withByteStringPtr ck $ \ckPtr ->
                  withByteStringPtr valuesBytes $ \valuesPtr ->
                   FBS.withPtr commitment $ \commitmentPtr ->
                     FBS.withPtr randomness $ \randomnessPtr ->
                       $(varE commitName) (fromIntegral n) ckPtr valuesPtr commitmentPtr randomnessPtr
         case suc of
           x | x == -1 -> return CommitInvalidCommitmentKey
             | x == -2 -> return CommitInvalidValues
             | x == 1 -> return $! CommitSuccess (Commitment commitment) (Randomness randomness)
           _ -> error "commit: Unknown return code."
       where
           valuesBytes = B.concat $ map (\(Value v) -> FBS.toByteString v) vs

     --opening a commitment 
     open :: CommitmentKey -> Randomness -> Values -> Commitment -> OpenResult
     open (CommitmentKey ck n) (Randomness r) vs (Commitment c) = unsafePerformIO $
         do suc <- withByteStringPtr ck $ \ckPtr ->
                     withByteStringPtr valuesBytes $ \valuesPtr -> 
                         FBS.withPtr c $ \cPtr -> 
                             FBS.withPtr r $ \rPtr -> 
                                 $(varE openName) (fromIntegral n) ckPtr valuesPtr cPtr rPtr
            case suc of
                 x | x == 1 -> return OK
                   | x == 0 -> return Reject
                   | x == -1 -> return InvalidCommitmentKey
                   | x == -2 -> return InvalidValues
                   | x == -3 -> return InvalidRandomness
                   | x == -4 -> return InvalidCommitment
                 _ -> error "open: Unexpected return value."
              where
                  valuesBytes = B.concat $ map (\(Value v) -> FBS.toByteString v) vs

     -- Produce the given number of valid values.
     -- note that the order of values is the reverse of that generated by rust
     -- it shouldn't matter
     randomValues:: Int -> IO Values
     randomValues n = do
         b <- bytes
         return $ map (Value . FBS.fromByteString) (f b [])
               where
                   bytes = create (n * fieldElementSize) $ \vs -> $(varE randomValuesName) (fromIntegral n) vs 
                   f b xs | b==empty =  xs
                          | otherwise = let (h, t) = B.splitAt (FBS.fixedLength (undefined::ValueSize)) b in 
                                          f t (h:xs)
  |]

-- |Parameters used to generate the commitment scheme.
data Parameters = Parameters  {
  -- |Name of the c function to generate the commitment key, given as a string.
  cGenCommitmentKeyName :: String,
  -- |Name of the c function to commit to a given list of values.
  cCommitName :: String,
  -- |Name of the c function to check whether the given commitment does indeed
  -- correspond to the values given.
  cOpenName :: String,
  -- |A c function to generate random values, e.g., to use for testing.
  cRandomValuesName :: String,

  -- |Size of group elements in bytes.
  groupElementSize :: Int,
  -- |Size of field elements in bytes.
  fieldElementSize :: Int
  } deriving(Show)

-- |TODO: Documentation ...
mkPedersenScheme :: Parameters -> Q [Dec]
mkPedersenScheme parameters@Parameters{..} = 
  let genCommitmentKeyName = mkName cGenCommitmentKeyName
      commitName = mkName cCommitName
      openName = mkName cOpenName
      randomValuesName = mkName cRandomValuesName
      iparams = InternalParameters{..}
  in do
    foreignImports <- mkForeignImports iparams
    tysandterms <- mkDataTysAndTerms iparams
    return $ foreignImports ++ tysandterms
