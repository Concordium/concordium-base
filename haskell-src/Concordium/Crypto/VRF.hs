{-# LANGUAGE DeriveGeneric, GeneralizedNewtypeDeriving, ForeignFunctionInterface #-}
-- | This module is a prototype implementantion of  verifiable random function.
-- draft-irtf-cfrg-vrf-01


module Concordium.Crypto.VRF(
    PublicKey,
    PrivateKey,
    newPrivKey,
    pubKey,
    KeyPair(..),
    Hash,
    Proof,
    randomKeyPair,
    newKeyPair,
    prove,
    proofToHash,
    verify,
    verifyKey,
    hashToDouble,
    hashToInt,
    test
) where

import           Concordium.Crypto.ByteStringHelpers
import           Data.String.Builder
import           Data.ByteString.Builder
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as B
import qualified Data.ByteString.Lazy       as L
import           Data.ByteString.Internal   (create, toForeignPtr)
import qualified Data.FixedByteString       as FBS
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
import           Concordium.Crypto.SHA256
import           System.Random


foreign import ccall "ec_vrf_priv_key" c_priv_key :: Ptr Word8 -> IO CInt
foreign import ccall "ec_vrf_pub_key" c_public_key :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall "ec_vrf_prove" c_prove :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Word32-> IO ()
foreign import ccall "ec_vrf_proof_to_hash" c_proof_to_hash :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall "ec_vrf_verify_key" c_verify_key :: Ptr Word8 -> IO CInt
foreign import ccall "ec_vrf_verify" c_verify :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Word32-> IO CInt

-- |The size of a VRF public key in bytes (32).
publicKeySize :: Int
publicKeySize = 32

data PublicKeySize
instance FBS.FixedLength PublicKeySize where
    fixedLength _ = publicKeySize

-- |A VRF public key. 32 bytes.
data PublicKey = PublicKey (FBS.FixedByteString PublicKeySize)
    deriving (Eq, Ord)
instance Serialize PublicKey where
    put (PublicKey key) = putByteString $ FBS.toByteString key
    get = PublicKey . FBS.fromByteString <$> getByteString (publicKeySize)
instance Show PublicKey where
    show (PublicKey key) = byteStringToHex $ FBS.toByteString key

-- |The size of a VRF private key in bytes (32).
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


-- |The size of a VRF proof in bytes (80).
proofSize :: Int
proofSize = 80

data ProofSize
instance FBS.FixedLength ProofSize where
    fixedLength _ = proofSize

-- |A VRF proof. 80 bytes.
newtype Proof = Proof (FBS.FixedByteString ProofSize)
    deriving (Eq)

instance Serialize Proof where
    put (Proof p) = putByteString $ FBS.toByteString p
    get = Proof . FBS.fromByteString <$> getByteString proofSize

instance Show Proof where
    show (Proof p) = byteStringToHex $ FBS.toByteString p

-- |A VRF key pair.
data KeyPair = KeyPair {
    privateKey :: PrivateKey,
    publicKey :: PublicKey
} deriving (Eq, Show)

instance Serialize KeyPair where
    put (KeyPair priv pub) = put priv >> put pub
    get = do
        priv <- get
        pub <- get
        return $ KeyPair priv pub

-- |Generate a key pair using a given random generator.
-- Useful for generating deterministic pseudo-random keys.
randomKeyPair :: RandomGen g => g -> (KeyPair, g)
randomKeyPair gen = (key, gen')
        where
            (gen0, gen') = split gen
            privKey = PrivateKey $ FBS.pack $ randoms gen0
            key = KeyPair privKey (unsafePerformIO $ pubKey privKey)

-- |Generate a new key pair using the system random number generator.
newKeyPair :: IO KeyPair
newKeyPair = do sk <- newPrivKey 
                pk <- pubKey sk
                return (KeyPair sk pk)

newPrivKey :: IO PrivateKey
newPrivKey = 
    do suc <- newIORef (0::Int)
       sk <- FBS.create $ \priv -> 
           do rc <-  c_priv_key priv 
              case rc of
                   1 ->  do writeIORef suc 1 
                   _ ->  do writeIORef suc 0 
       suc' <- readIORef suc
       case suc' of
           0 -> error "Private key generation failed"
           _ -> return (PrivateKey sk)

pubKey :: PrivateKey -> IO PublicKey
pubKey (PrivateKey sk) = do suc <- newIORef (0::Int)
                            pk  <- FBS.create $ \pub -> 
                                 do pc <- FBS.withPtr sk $ \y -> c_public_key pub y
                                    if (pc == 1) 
                                       then writeIORef suc 1
                                       else writeIORef suc 0
                            suc' <- readIORef suc
                            case suc' of 
                                  1 -> return (PublicKey pk)
                                  _ -> error "Public key generation failed"
                                 

test :: IO () 
test = do kp@(KeyPair sk pk) <- newKeyPair
          _ <- putStrLn("SK: " ++ show sk)
          _ <- putStrLn("PK: " ++ show pk)
          _ <- putStrLn("MESSAGE:") 
          alpha <- B.getLine 
          let prf = prove kp alpha  
              valid = verify pk alpha prf 
              h' = proofToHash prf 
           in
              putStrLn ("Proof: " ++ show prf) >>
              putStrLn ("PK IS " ++ if verifyKey pk then "OK" else "BAD") >>
              putStrLn ("Verification: " ++ if valid then "VALID" else "INVALID") >>
              putStrLn ("Proof hash: " ++ show h')

-- |Generate a VRF proof.
prove :: KeyPair -> ByteString -> Proof
prove (KeyPair (PrivateKey sk) (PublicKey pk)) b = Proof $
                                        FBS.unsafeCreate $ \prf -> 
                                           FBS.withPtr pk $ \pk' -> 
                                               FBS.withPtr sk $ \sk' -> 
                                                   withByteStringPtr b $ \b' -> 
                                                       c_prove prf pk' sk' b' (fromIntegral $ B.length b)

-- |Verify a VRF proof.
verify :: PublicKey -> ByteString -> Proof -> Bool
verify (PublicKey pk) alpha (Proof prf) = cIntToBool $ unsafeDupablePerformIO $ 
                                                FBS.withPtr pk $ \pk' ->
                                                   FBS.withPtr prf $ \pi' ->
                                                     withByteStringPtr alpha $ \alpha'->
                                                       c_verify pk' pi' alpha' (fromIntegral $ B.length alpha)
              where
                  cIntToBool x =  x > 0
                                                           
-- |Generate a 256-bit hash from a VRF proof.
proofToHash :: Proof -> Hash
proofToHash (Proof p) =  Hash $ FBS.unsafeCreate $ \x -> 
        FBS.withPtr p $ \p' -> c_proof_to_hash x p' >> return()

-- |Verify a VRF public key.
verifyKey :: PublicKey -> Bool
verifyKey (PublicKey pk) =  x > 0 
            where
               x = unsafeDupablePerformIO $ FBS.withPtr pk $ \pk' -> c_verify_key pk'
