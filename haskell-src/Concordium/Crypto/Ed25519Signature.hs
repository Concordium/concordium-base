{-# LANGUAGE DeriveGeneric, GeneralizedNewtypeDeriving, ForeignFunctionInterface , TypeFamilies, FlexibleContexts, FlexibleInstances  #-}
-- |This module provides a prototype implementation of 
-- EDDSA scheme of Curve Ed25519 
--  IRTF RFC 8032
module Concordium.Crypto.Ed25519Signature 
    where

import           Concordium.Crypto.ByteStringHelpers
import qualified Concordium.Crypto.SignatureScheme as SCH
import           Concordium.Crypto.SignatureScheme (Signature(..), SignKey(..), VerifyKey(..), SchemeId(..), KeyPair(..))
import           Data.Word
import           System.IO.Unsafe
import           Foreign.Ptr
import qualified Data.ByteString.Unsafe as BS
import qualified Data.ByteString.Short as BSS
import           Data.ByteString (ByteString) 
import           Foreign.C.Types
import           Test.QuickCheck (Gen, Arbitrary(..))
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
     do (suc, sk) <- withAllocatedShortByteString signKeySize $ c_priv_key
        case suc of
            1 -> return (SignKey sk)
            _ -> error "Private key generation failed"

pubKey :: SignKey -> IO VerifyKey
pubKey (SignKey sk) = do ((), pk) <- withAllocatedShortByteString verifyKeySize $
                             \pub -> withByteStringPtr sk $ \sk' -> c_public_key sk' pub
                         return (VerifyKey pk)

newKeyPair :: IO KeyPair
newKeyPair = do sk <- newPrivKey
                pk <- pubKey sk
                return (KeyPair sk pk)

sign :: KeyPair -> ByteString -> Signature
sign (KeyPair (SignKey sk) (VerifyKey pk)) m =
  Signature $ unsafeDupablePerformIO $ do
    ((), sig) <- withAllocatedShortByteString signatureSize $ \sig ->
      BS.unsafeUseAsCStringLen m $ \(m', mlen) -> 
      withByteStringPtr pk $ \pk' ->
      withByteStringPtr sk $ \sk' ->
      c_sign (castPtr m') (fromIntegral mlen) sk' pk' sig
    return sig

verify :: VerifyKey -> ByteString -> Signature -> Bool
verify (VerifyKey pk) m (Signature sig) =  suc > 0
   where
       suc = unsafeDupablePerformIO $ 
         BS.unsafeUseAsCStringLen m $ \(m', mlen) -> 
         withByteStringPtr pk $ \pk'->
         withByteStringPtr sig $ \sig' ->
         c_verify (castPtr m') (fromIntegral mlen) pk' sig'

ed25519 :: SCH.SignatureScheme
ed25519 = SCH.SigScheme { SCH.schemeId = Ed25519,
                          SCH.sign = sign,
                          SCH.verify = verify,
                          SCH.newPrivateKey =  newPrivKey,
                          SCH.publicKey = unsafePerformIO . pubKey
                        }

genKeyPair :: Gen KeyPair
genKeyPair = fst . randomKeyPair . mkStdGen <$> arbitrary

randomKeyPair :: RandomGen g => g -> (SCH.KeyPair, g)
randomKeyPair gen = (key, gen')
        where
            (gen0, gen') = split gen
            privKey = SCH.SignKey $ BSS.pack $ take signKeySize $ randoms gen0
            key = SCH.KeyPair privKey (SCH.publicKey ed25519 privKey)







