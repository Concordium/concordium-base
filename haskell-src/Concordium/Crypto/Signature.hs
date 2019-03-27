{-# LANGUAGE DeriveGeneric, GeneralizedNewtypeDeriving, ForeignFunctionInterface , TypeFamilies  #-}
-- |This module provides a dummy signature scheme for
-- prototyping purposes.  It provides NO SECURITY and
-- obviously should be replaced with a real implementation.
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
import           GHC.Generics
import           System.Random
import           Foreign.Marshal.Array
import           Foreign.Marshal.Alloc
import           Foreign.C.Types
import           Concordium.Crypto.SignatureScheme (SignatureScheme)
import qualified Concordium.Crypto.SignatureScheme as S 

foreign import ccall "ec_vrf_ed25519-sha256.h priv_key" c_priv_key :: Ptr Word8 -> IO CInt
foreign import ccall "ed25519.h ed25519_publickey" c_public_key :: Ptr Word8 -> Ptr Word8 -> IO () 
foreign import ccall "ed25519.h ed25519_sign" c_sign :: Ptr Word8 -> Word32 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO () 
foreign import ccall "ed25519.h ed25519_sign_open" c_verify :: Ptr Word8 -> Word32 -> Ptr Word8 -> Ptr Word8 -> IO CInt 


privKeyToHex :: SignKey -> String
privKeyToHex (SignKey sk) = byteStringToHex sk

pubKeyToHex :: VerifyKey -> String
pubKeyToHex (VerifyKey pk) = byteStringToHex pk


data SignKey = SignKey ByteString
    deriving (Eq, Generic)
instance Serialize SignKey where

data VerifyKey = VerifyKey ByteString
    deriving (Eq, Ord, Generic)
instance Serialize VerifyKey where

newtype Signature = Signature Hash.Hash
    deriving (Eq, Generic, Serialize, Show)

data KeyPair = KeyPair {
    signKey :: SignKey,
    verifyKey :: VerifyKey
} deriving (Eq, Generic)
instance Serialize KeyPair

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
sign (KeyPair (SignKey sk) (VerifyKey pk)) m = Signature $ Hash.Hash $ unsafeDupablePerformIO $ 
    create 64 $ \sig ->
       withByteStringPtr m $ \m' -> 
          withByteStringPtr pk $ \pk' ->
             withByteStringPtr sk $ \sk' ->
                c_sign m' mlen sk' pk' sig 
   where
       mlen = fromIntegral $ B.length m


verify :: VerifyKey -> ByteString -> Signature -> Bool
verify (VerifyKey pk) m (Signature (Hash.Hash sig)) =  suc > -1
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
          let sig@(Signature (Hash.Hash b)) = sign kp alpha
              suc = verify pk alpha sig
           in
              putStrLn ("signature: " ++ byteStringToHex b) >>
              putStrLn ("Good?: " ++ if suc then "YES" else "NO")



data Ed25519
instance SignatureScheme Ed25519 where
    data VerifyKey Ed25519    = Ed25519_PK ByteString
    data SignKey Ed25519      = Ed25519_SK ByteString
    data Signature Ed25519    = Ed25519_Sig ByteString
    generatePrivateKey        = unsafePerformIO $ do (SignKey x) <- newPrivKey
                                                     return (Ed25519_SK x)
    publicKey (Ed25519_SK x) = unsafePerformIO $ do (VerifyKey y) <- pubKey (SignKey x)
                                                    return (Ed25519_PK y)
    sign (Ed25519_SK x) (Ed25519_PK y) b = Ed25519_Sig b
    verify (Ed25519_PK x) b s = True
