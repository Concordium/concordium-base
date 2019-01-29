{-# LANGUAGE DeriveGeneric, GeneralizedNewtypeDeriving, ForeignFunctionInterface #-}
{- | This module implements a dummy verifiable random function.
     The implementation is intended to immitate the behaviour of
     a real implementation, but does not provide any security.
-}
module Concordium.Crypto.Haskell.VRF(
    PublicKey,
    PrivateKey,
    newPrivKey,
    pubKey,
    KeyPair(..),
    Hash,
    Proof,
    newKeyPair,
    --hash,
    prove,
    proofToHash,
    verify,
    verifyKey,
    hashToDouble,
    hashToInt,
) where
import           Data.String.Builder
import           Data.ByteString.Builder
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as B
import qualified Data.ByteString.Lazy       as L
import           Data.ByteString.Internal   (create, toForeignPtr)
import           Foreign.Ptr
import           Foreign.ForeignPtr
import           Data.Word
import           System.IO.Unsafe
import           Control.Monad
import           Foreign.Marshal.Array
import           Foreign.Marshal.Alloc
import           Data.Serialize
import           Foreign.C.Types
import           Data.IORef
import           GHC.Generics
import           Data.Maybe
import           Numeric
import           Text.Printf
import           Concordium.Crypto.Haskell.SHA256
foreign import ccall "priv_key" c_priv_key :: Ptr Word8 -> IO CInt
foreign import ccall "public_key" c_public_key :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall "keyPair" c_key_pair :: Ptr Word8 -> Ptr Word8 -> IO () 
foreign import ccall "ecvrf_prove" c_prove :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Word32-> IO () 
foreign import ccall "ecvrf_proof_to_hash" c_proof_to_hash :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall "ecvrf_verify_key" c_verify_key :: Ptr Word8 -> IO CInt
foreign import ccall "ecvrf_verify" c_verify :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Word32-> IO CInt
--import Data.ByteString as BS
--import Data.ByteString.Builder
--import Data.Word
--import System.Random


wordToHex :: Word8 -> [Char]
wordToHex x = printf "%.2x" x 

              
byteStringToHex :: ByteString -> String
byteStringToHex b= concatMap wordToHex ls
    where
        ls = B.unpack b

privKeyToHex :: PrivateKey -> String
privKeyToHex (PrivateKey sk) = byteStringToHex sk

pubKeyToHex :: PublicKey -> String
pubKeyToHex (PublicKey pk) = byteStringToHex pk

withByteStringPtr :: ByteString -> (Ptr Word8 -> IO a) -> IO a
withByteStringPtr b f =  withForeignPtr fptr $ \ptr -> f (ptr `plusPtr` off)
    where (fptr, off, _) = toForeignPtr b

    {-
newKeyPair :: IO (PrivateKey, PublicKey)
newKeyPair = do maybeSk <- newPrivKey 
                case maybeSk of
                  Nothing -> return Nothing
                  Just sk -> do maybePk <- pubKey sk
                                case maybePk of 
                                  Nothing -> return Nothing
                                  Just pk -> do _ <- putStrLn(privKeyToHex sk)
                                                _ <- putStrLn(pubKeyToHex pk) 
                                                return (Just (sk,  pk))

-}

newKeyPair :: IO (PrivateKey, PublicKey)
newKeyPair = do sk <- newPrivKey 
                pk <- pubKey sk
                _  <- putStrLn ("SK: " ++ privKeyToHex sk)
                _  <- putStrLn ("PK: " ++ pubKeyToHex pk)
                return (sk, pk)

newPrivKey :: IO PrivateKey
newPrivKey = 
    do suc <- newIORef (0::Int)
       sk <- create 32 $ \priv -> 
           do rc <-  c_priv_key priv 
              case rc of
                   1 ->  do writeIORef suc 1 
                   0 ->  do writeIORef suc 0 
       suc' <- readIORef suc
       case suc' of
           0 -> error "Private key generation failed"
           1 -> return (PrivateKey sk)

pubKey :: PrivateKey -> IO PublicKey
pubKey (PrivateKey sk) = do suc <- newIORef (0::Int)
                            pk  <- create 32 $ \pub -> 
                                 do pc <- withByteStringPtr sk $ \y -> c_public_key pub y
                                    if (pc == 1) 
                                       then writeIORef suc 1
                                       else writeIORef suc 0
                            suc' <- readIORef suc
                            case suc' of 
                                  0 -> error "Public key generation failed"
                                  1 -> return (PublicKey pk)
                                 

data PublicKey = PublicKey ByteString
    deriving (Eq, Ord, Generic)
instance Serialize PublicKey where

data PrivateKey = PrivateKey ByteString
    deriving (Eq, Generic)

instance Serialize PrivateKey where


newtype Proof = Proof Hash
    deriving (Eq, Generic, Serialize, Show)

data KeyPair = KeyPair {
    privateKey :: PrivateKey,
    publicKey :: PublicKey
}


test :: IO () 
test = do (sk,pk) <- newKeyPair
          _ <- putStrLn("MESSAGE:") 
          alpha <- B.getLine 
          let prf@(Proof (Hash b)) = prove pk sk alpha  
              valid = verify pk alpha prf 
              h@(Hash h') = proofToHash prf 
           in
              putStrLn ("Proof: " ++ byteStringToHex b) >>
              putStrLn ("PK IS " ++ if verifyKey pk then "OK" else "BAD") >>
              putStrLn ("Verification: " ++ if valid then "VALID" else "INVALID") >>
              putStrLn ("Proof hash: " ++ byteStringToHex h')


prove :: PublicKey -> PrivateKey -> ByteString -> Proof
prove (PublicKey pk) (PrivateKey sk) b = Proof $ Hash $ unsafeDupablePerformIO $
                                        create 80 $ \pi -> 
                                           withByteStringPtr pk $ \pk' -> 
                                               withByteStringPtr sk $ \sk' -> 
                                                   withByteStringPtr b $ \b' -> 
                                                       c_prove pi pk' sk' b' (fromIntegral $ B.length b)

verify :: PublicKey -> ByteString -> Proof -> Bool
verify (PublicKey pk) alpha (Proof (Hash pi)) = cIntToBool $ unsafeDupablePerformIO $ 
                                                withByteStringPtr pk $ \pk' ->
                                                   withByteStringPtr pi $ \pi' ->
                                                     withByteStringPtr alpha $ \alpha'->
                                                       c_verify pk' pi' alpha' (fromIntegral $ B.length alpha)
              where
                  cIntToBool x = (fromIntegral x) > 0
                                                           
                                                   


proofToHash :: Proof -> Hash
proofToHash (Proof (Hash p)) =  Hash $ unsafeDupablePerformIO $ 
    create 32 $ \x -> 
        withByteStringPtr p $ \p' -> c_proof_to_hash x p' >> return()

verifyKey :: PublicKey -> Bool
verifyKey (PublicKey pk) = fromIntegral x > 0 
            where
               x = unsafeDupablePerformIO $  withByteStringPtr pk $ \pk' -> c_verify_key pk'

-- |Convert a 'Hash' into a 'Double' value in the range [0,1].
-- This implementation takes the first 64-bit word (big-endian) and uses it
-- as the significand, with an exponent of -64.  Since the precision of a
-- 'Double' is only 53 bits, there is inevitably some loss.  This also means
-- that the outcome 1 is not possible.
hashToDouble :: Hash -> Double
hashToDouble (Hash  h) = case runGet getWord64be h of
    Left e -> error e
    Right w -> encodeFloat (toInteger w) (-64)


hashToInt :: Hash -> Int
hashToInt (Hash h) = case runGet getInt64be h of
    Left e -> error e
    Right i -> fromIntegral i



