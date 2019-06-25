{-# LANGUAGE GeneralizedNewtypeDeriving, ForeignFunctionInterface #-}
-- | This module is a prototype implementantion of  pseudo  random function.
-- dodis-yampolskiy

module Concordium.Crypto.PRF(
    PrfKey,
    newPrfKey,
    PrfObj(..),
    prf,
    test
) where

import           Concordium.Crypto.ByteStringHelpers
import qualified Data.FixedByteString       as FBS
import           Foreign.Ptr
import           Data.Word
import           System.IO.Unsafe
import           Data.Serialize
import           Foreign.C.Types
import           Data.IORef


foreign import ccall "prf_key" rs_prf_key :: Ptr Word8 -> IO()
foreign import ccall "prf" rs_prf :: Ptr Word8 -> Ptr Word8 -> Word8 -> IO CInt

-- |The size of a PRF  key in bytes (32).
prfKeySize :: Int
prfKeySize = 32

data PrfKeySize
instance FBS.FixedLength PrfKeySize where
    fixedLength _ = prfKeySize

-- |A VRF  key. 32 bytes.
data PrfKey = PrfKey (FBS.FixedByteString PrfKeySize)
    deriving (Eq)

instance Serialize PrfKey where
    put (PrfKey key) = putByteString $ FBS.toByteString key
    get = PrfKey . FBS.fromByteString <$> getByteString prfKeySize
instance Show PrfKey where
    show (PrfKey key) = byteStringToHex $ FBS.toByteString key


-- |The size of a PRF Object in bytes (48).
prfObjSize :: Int
prfObjSize = 48 

data PrfObjSize
instance FBS.FixedLength PrfObjSize where
    fixedLength _ = prfObjSize

-- |A PRF object. 48 bytes.
newtype PrfObj = PrfObj (FBS.FixedByteString PrfObjSize)
    deriving (Eq)

instance Serialize PrfObj where
    put (PrfObj p) = putByteString $ FBS.toByteString p
    get = PrfObj . FBS.fromByteString <$> getByteString prfObjSize

instance Show PrfObj where
    show (PrfObj p) = byteStringToHex $ FBS.toByteString p



newPrfKey :: IO PrfKey
newPrfKey =  
    do sk <- FBS.create $ \priv -> rs_prf_key priv 
       return (PrfKey sk)

                                 

test :: IO () 
test = do sks <- mapM (\ _ -> newPrfKey) [1 :: Int]
          let ms = map f sks 
          let rs = zip sks ms  in
              mapM_ g rs
   where f sk = map (prf sk) [3,3,3]
         g (sk, prfs) = do _ <- putStrLn ("SK :+++" ++  show sk ++  "+++:") 
                           putStrLn(show prfs)


-- |Generate a PRF object.

prf :: PrfKey -> Word8-> PrfObj
prf (PrfKey sk) n = PrfObj $ unsafeDupablePerformIO  $ 
                        do suc <- newIORef(0::Int) 
                           p  <- FBS.create $ \prfp -> 
                            do pc <- FBS.withPtr sk $ \sk' -> 
                                       rs_prf prfp  sk' n 
                               if (pc == 1) then writeIORef suc 1  
                               else  writeIORef suc 0  
                           suc' <- readIORef suc
                           case suc' of
                             1 -> return p
                             _ -> error "PRF failed"

