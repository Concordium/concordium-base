{-# LANGUAGE GeneralizedNewtypeDeriving, ForeignFunctionInterface #-}
-- |This module provides a prototype implementation of 
-- ECDSA scheme of Curve Ed25519 
--  IRTF RFC 8032
module Concordium.Crypto.Signature(
    SignKey,
    VerifyKey,
    KeyPair(..),
    Signature,
    test,
    randomKeyPair,
    newKeyPair,
    sign,
    verify
   --emptySignature
) where

import           Concordium.Crypto.ByteStringHelpers
import           Text.Printf
import           Data.IORef
import           Data.ByteString.Internal   (create, toForeignPtr)
import           Data.Word
import           System.IO.Unsafe
import           Foreign.Ptr
import           Foreign.ForeignPtr
import qualified Concordium.Crypto.SHA256 as Hash
import qualified Data.ByteString.Lazy as L
import           Data.Serialize
import qualified Data.ByteString  as B
import           Data.ByteString (ByteString) 
import           Data.ByteString.Builder
import           Data.Word
import           System.Random
import           Foreign.Marshal.Array
import           Foreign.Marshal.Alloc
import           Foreign.C.Types

foreign import ccall "ec_vrf_ed25519-sha256.h priv_key" c_priv_key :: Ptr Word8 -> IO CInt
foreign import ccall "ed25519.h ed25519_publickey" c_public_key :: Ptr Word8 -> Ptr Word8 -> IO () 
foreign import ccall "ed25519.h ed25519_sign" c_sign :: Ptr Word8 -> Word32 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO () 
foreign import ccall "ed25519.h ed25519_sign_open" c_verify :: Ptr Word8 -> Word32 -> Ptr Word8 -> Ptr Word8 -> IO CInt 


privKeyToHex :: SignKey -> String
privKeyToHex (SignKey sk) = byteStringToHex sk

pubKeyToHex :: VerifyKey -> String
pubKeyToHex (VerifyKey pk) = byteStringToHex pk

-- |Signature private key.  32 bytes
data SignKey = SignKey ByteString
    deriving (Eq)
instance Serialize SignKey where
    put (SignKey key) = putByteString key
    get = SignKey <$> getByteString 32
instance Show SignKey where
    show (SignKey sk) = byteStringToHex sk


-- |Signature public (verification) key. 32 bytes
data VerifyKey = VerifyKey ByteString
    deriving (Eq, Ord)
instance Serialize VerifyKey where
    put (VerifyKey key) = putByteString key
    get = VerifyKey <$> getByteString 32
instance Show VerifyKey where
    show (VerifyKey vk) = byteStringToHex vk

-- |Signature. 64 bytes
newtype Signature = Signature ByteString
    deriving (Eq)

instance Serialize Signature where
    put (Signature sig) = putByteString sig
    get = Signature <$> getByteString 64
instance Show Signature where
    show (Signature sig) = byteStringToHex sig

data KeyPair = KeyPair {
    signKey :: SignKey,
    verifyKey :: VerifyKey
} deriving (Eq, Show)
instance Serialize KeyPair where
    put (KeyPair sk vk) = put sk >> put vk
    get = do
        sk <- get
        vk <- get
        return $ KeyPair sk vk

newPrivKey :: IO SignKey
newPrivKey =
     do suc <- newIORef (0::Int)
        sk <- create 32 $ \priv ->
            do rc <-  c_priv_key priv
               case rc of
                    1 ->  do writeIORef suc 1
                    _ ->  do writeIORef suc 0
        suc' <- readIORef suc
        case suc' of
            1 -> return (SignKey sk)
            _ -> error "Private key generation failed"

pubKey :: SignKey -> IO VerifyKey
pubKey (SignKey sk) = do pk <- create 32 $ \pub -> 
                                 withByteStringPtr sk $ \y -> c_public_key y pub
                         return (VerifyKey pk)

randomKeyPair :: RandomGen g => g -> (KeyPair, g)
randomKeyPair gen = (key, gen')
        where
            (gen0, gen') = split gen
            privKey = SignKey $ B.pack $ take 32 $ randoms gen0
            key = KeyPair privKey (unsafePerformIO $ pubKey privKey)


newKeyPair :: IO KeyPair
newKeyPair = do sk <- newPrivKey
                pk <- pubKey sk
                return (KeyPair sk pk)

sign :: KeyPair -> ByteString -> Signature
sign (KeyPair (SignKey sk) (VerifyKey pk)) m = Signature $ unsafeDupablePerformIO $ 
    create 64 $ \sig ->
       withByteStringPtr m $ \m' -> 
          withByteStringPtr pk $ \pk' ->
             withByteStringPtr sk $ \sk' ->
                c_sign m' mlen sk' pk' sig 
   where
       mlen = fromIntegral $ B.length m


verify :: VerifyKey -> ByteString -> Signature -> Bool
verify (VerifyKey pk) m (Signature sig) =  suc > -1
   where
       mlen = fromIntegral $ B.length m
       suc  = unsafeDupablePerformIO $ 
           withByteStringPtr m $ \m'->
                 withByteStringPtr pk $ \pk'->
                    withByteStringPtr sig $ \sig' ->
                       c_verify m' mlen pk' sig'



test :: IO ()
test = do kp@(KeyPair sk pk) <- newKeyPair
          putStrLn ("SK: " ++ privKeyToHex sk)
          putStrLn ("PK: " ++ pubKeyToHex pk)
          putStrLn("MESSAGE:")
          alpha <- B.getLine
          let sig@(Signature b) = sign kp alpha
              suc = verify pk alpha sig
           in
              putStrLn ("signature: " ++ byteStringToHex b) >>
              putStrLn ("Good?: " ++ if suc then "YES" else "NO")
