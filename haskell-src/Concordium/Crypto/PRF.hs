{-# LANGUAGE GeneralizedNewtypeDeriving, ForeignFunctionInterface #-}
-- | This module is a prototype implementantion of  pseudo  random function.
-- dodis-yampolskiy

module Concordium.Crypto.PRF(
    PrivateKey,
    newPrivKey,
    PrfObj,
    prf,
    test
) where

import           Concordium.Crypto.ByteStringHelpers
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as B
import qualified Data.FixedByteString       as FBS
import           Foreign.Ptr
import           Data.Word
import           System.IO.Unsafe
import           Data.Serialize
import           Foreign.C.Types
import           Data.IORef
import           Concordium.Crypto.SHA256
import           System.Random
import           Test.QuickCheck (Arbitrary(..))


foreign import ccall "prf_key" rs_priv_key :: Ptr Word8 -> IO()
foreign import ccall "prf" rs_prf :: Ptr Word8 -> Ptr Word8 -> Word8 -> IO CInt

-- |The size of a PRF  key in bytes (32).
privateKeySize :: Int
privateKeySize = 32

data PrivateKeySize
instance FBS.FixedLength PrivateKeySize where
    fixedLength _ = privateKeySize

-- |A VRF private key. 32 bytes.
data PrivateKey = PrivateKey (FBS.FixedByteString PrivateKeySize)
    deriving (Eq)
instance Serialize PrivateKey where
    put (PrivateKey key) = putByteString $ FBS.toByteString key
    get = PrivateKey . FBS.fromByteString <$> getByteString privateKeySize
instance Show PrivateKey where
    show (PrivateKey key) = byteStringToHex $ FBS.toByteString key


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



newPrivKey :: IO PrivateKey
newPrivKey =  
    do sk <- FBS.create $ \priv -> rs_priv_key priv 
       return (PrivateKey sk)

                                 

test :: IO () 
test = do sks <- mapM (\ _ -> newPrivKey) [1]
          let ms = map f sks 
          let rs = zip sks ms  in
              mapM_ g rs
   where f sk = map (prf sk) [3,3,3]
         g (sk, prfs) = do _ <- putStrLn ("SK :+++" ++  show sk ++  "+++:") 
                           putStrLn(show prfs)


-- |Generate a PRF object.

prf :: PrivateKey -> Word8-> PrfObj
prf (PrivateKey sk) n = PrfObj $ unsafeDupablePerformIO  $ 
                        do suc <- newIORef(0::Int) 
                           p  <- FBS.create $ \prf -> 
                            do pc <- FBS.withPtr sk $ \sk' -> 
                                       rs_prf prf  sk' n 
                               if (pc == 1) then writeIORef suc 1  
                               else  writeIORef suc 0  
                           suc' <- readIORef suc
                           case suc' of
                             1 -> return p
                             0 -> error "PRF failed"

