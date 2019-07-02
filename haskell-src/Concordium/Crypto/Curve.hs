{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies #-}
module Concordium.Crypto.Curve where

import Foreign.ForeignPtr
import Foreign.Ptr
import Foreign.C.Types
import Data.Serialize

import Concordium.Crypto.ByteStringHelpers
import Concordium.Crypto.FFIHelpers

import Data.Word

import Data.Proxy

import Control.Monad

data family GroupElement a
type family FieldElement a -- fields are shared by different groups

class (Serialize (GroupElement a),
       Serialize (FieldElement a),
       Show (GroupElement a),
       Show (FieldElement a)) => Curve a where

  groupElementSize :: Proxy a -> Int
  fieldElementSize :: Proxy a -> Int

  generateGroupElem :: IO (GroupElement a)
  generateFieldElem :: Proxy a -> IO (FieldElement a)

  generateGroupElements :: Int -> IO [GroupElement a]
  generateGroupElements n = replicateM n generateGroupElem

  generateFieldElements :: Proxy a -> Int -> IO [FieldElement a]
  generateFieldElements p n = replicateM n (generateFieldElem p)

  withGroupElement :: GroupElement a -> (Ptr (GroupElement a) -> IO b) -> IO b
  withFieldElement :: Proxy a -> FieldElement a -> (Ptr (FieldElement a) -> IO b) -> IO b

  groupElementFromPtr :: Ptr (GroupElement a) -> IO (GroupElement a)

data G1

data instance GroupElement G1 = G1 (ForeignPtr (GroupElement G1))

newtype BLS12_381_Field = BLS12_381_Field (ForeignPtr BLS12_381_Field)

type instance FieldElement G1 = BLS12_381_Field

foreign import ccall unsafe "&bls_free_g1" freeG1Elem :: FunPtr (Ptr (GroupElement G1) -> IO ())
foreign import ccall unsafe "&bls_free_scalar" freeFieldElem :: FunPtr (Ptr BLS12_381_Field -> IO ())

foreign import ccall unsafe "bls_to_bytes_g1" toBytesG1 :: Ptr (GroupElement G1) -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "bls_from_bytes_g1" fromBytesG1 :: Ptr Word8 -> CSize -> IO (Ptr (GroupElement G1))
foreign import ccall unsafe "bls_generate_g1" generateG1 :: IO (Ptr (GroupElement G1))

foreign import ccall unsafe "bls_to_bytes_scalar" toBytesField :: Ptr BLS12_381_Field -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "bls_from_bytes_scalar" fromBytesField :: Ptr Word8 -> CSize -> IO (Ptr BLS12_381_Field)
foreign import ccall unsafe "bls_generate_scalar" generateScalar :: IO (Ptr BLS12_381_Field)

g1ElemLength :: Int
g1ElemLength = 48

scalarLength :: Int
scalarLength = 32

instance Serialize (GroupElement G1) where
  get = do
    bs <- getByteString g1ElemLength
    case fromBytesHelper freeG1Elem fromBytesG1 bs of
      Nothing -> fail "Cannot decode cipher."
      Just x -> return $ G1 x

  put (G1 e) = putByteString . toBytesHelper toBytesG1 $ e

instance Serialize BLS12_381_Field where
  get = do
    bs <- getByteString scalarLength
    case fromBytesHelper freeFieldElem fromBytesField bs of
      Nothing -> fail "Cannot decode cipher."
      Just x -> return $ BLS12_381_Field x

  put (BLS12_381_Field e) = putByteString . toBytesHelper toBytesField $ e

instance Show (GroupElement G1) where
  show = byteStringToHex . encode

instance Show BLS12_381_Field where
  show = byteStringToHex . encode

instance Curve G1 where
  groupElementSize _ = g1ElemLength
  fieldElementSize _ = scalarLength

  generateGroupElem = G1 <$> (newForeignPtr freeG1Elem =<< generateG1)
  generateFieldElem _ = BLS12_381_Field <$> (newForeignPtr freeFieldElem =<< generateScalar)

  withGroupElement (G1 fp) = withForeignPtr fp
  withFieldElement _ (BLS12_381_Field fp) = withForeignPtr fp

  groupElementFromPtr p = G1 <$> newForeignPtr freeG1Elem p
