{-# LANGUAGE DeriveGeneric, GeneralizedNewtypeDeriving, ForeignFunctionInterface , TypeFamilies, FlexibleContexts, FlexibleInstances  #-}
-- |This module provides a prototype implementation of 
-- EDDSA scheme of Curve Ed25519 
--  IRTF RFC 8032
module Concordium.Crypto.Ed25519Signature 
    where

import           Concordium.Crypto.ByteStringHelpers
import qualified Concordium.Crypto.SignatureScheme as SCH
import           Concordium.Crypto.SignatureScheme (Signature(..), SignKey(..), VerifyKey(..), SchemeId(..), KeyPair(..))
import           Data.IORef
import           Data.Word
import           System.IO.Unsafe
import           Foreign.Ptr
import           Data.Serialize
import qualified Data.ByteString  as B
import           Data.ByteString (ByteString) 
import           Data.ByteString.Internal
import           Foreign.C.Types
import           Test.QuickCheck (Arbitrary(..))
import           System.Random


foreign import ccall "eddsa_priv_key" c_priv_key :: Ptr Word8 -> IO CInt
foreign import ccall "eddsa_pub_key" c_public_key :: Ptr Word8 -> Ptr Word8 -> IO ()
foreign import ccall "eddsa_sign" c_sign :: Ptr Word8 -> Word32 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> IO ()
foreign import ccall "eddsa_verify" c_verify :: Ptr Word8 -> Word32 -> Ptr Word8 -> Ptr Word8 -> IO CInt


signKeySize :: Int
signKeySize = 32
verifyKeySize :: Int
verifyKeySize = 32
signatureSize :: Int
signatureSize = 64



newPrivKey :: IO SignKey
newPrivKey =
     do suc <- newIORef (0::Int)
        sk <- create signKeySize $ \priv ->
            do rc <-  c_priv_key priv
               case rc of
                    1 ->  do writeIORef suc 1
                    _ ->  do writeIORef suc 0
        suc' <- readIORef suc
        case suc' of
            1 -> return (SignKey sk)
            _ -> error "Private key generation failed"

pubKey :: SignKey -> IO VerifyKey
pubKey (SignKey sk) = do pk <- create verifyKeySize $ \pub -> 
                                 withByteStringPtr sk $ \y -> c_public_key y pub
                         return (VerifyKey pk)


newKeyPair :: IO KeyPair
newKeyPair = do sk <- newPrivKey
                pk <- pubKey sk
                return (KeyPair sk pk)

sign :: KeyPair -> ByteString -> Signature
sign (KeyPair (SignKey sk) (VerifyKey pk)) m = Signature $ unsafePerformIO $ create signatureSize $ \sig ->
       withByteStringPtr m $ \m' -> 
          withByteStringPtr pk $ \pk' ->
             withByteStringPtr sk $ \sk' ->
                c_sign m' mlen sk' pk' sig 
   where
       mlen = fromIntegral $ B.length m


verify :: VerifyKey -> ByteString -> Signature -> Bool
verify (VerifyKey pk) m (Signature sig) =  suc > 0
   where
       mlen = fromIntegral $ B.length m
       suc  = unsafeDupablePerformIO $ 
           withByteStringPtr m $ \m'->
                 withByteStringPtr pk $ \pk'->
                    withByteStringPtr sig $ \sig' ->
                       c_verify m' mlen pk' sig'



test :: IO ()
test = do kp@(KeyPair sk pk) <- newKeyPair
          putStrLn ("SK: " ++ show sk)
          putStrLn ("PK: " ++ show pk)
          putStrLn("MESSAGE:")
          alpha <- B.getLine
          let sig = sign kp alpha
              suc = verify pk alpha sig
           in
              putStrLn ("signature: " ++ show sig) >>
              putStrLn ("Good?: " ++ if suc then "YES" else "NO")




ed25519 :: SCH.SignatureScheme
ed25519 = SCH.SigScheme { SCH.schemeId = Ed25519,
                          SCH.sign = sign,
                          SCH.verify = verify,
                          SCH.newPrivateKey =  newPrivKey,
                          SCH.publicKey = unsafePerformIO . pubKey
                        }





instance Arbitrary SCH.KeyPair where
          arbitrary = fst . randomKeyPair . mkStdGen <$> arbitrary

randomKeyPair :: RandomGen g => g -> (SCH.KeyPair, g)
randomKeyPair gen = (key, gen')
        where
            (gen0, gen') = split gen
            privKey = SCH.SignKey $ B.pack $ take signKeySize $ randoms gen0
            key = SCH.KeyPair privKey (SCH.publicKey ed25519 privKey)







