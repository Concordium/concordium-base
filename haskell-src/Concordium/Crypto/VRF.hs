{-# LANGUAGE GeneralizedNewtypeDeriving, ForeignFunctionInterface, DerivingVia #-}
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
import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as B
import qualified Data.ByteString.Unsafe as B
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
import Data.Int

foreign import ccall "ec_vrf_priv_key" rs_priv_key :: Ptr Word8 -> IO CInt
foreign import ccall "ec_vrf_pub_key" rs_public_key :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall "ec_vrf_prove" rs_prove :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Word32-> IO Int32
foreign import ccall "ec_vrf_proof_to_hash" rs_proof_to_hash :: Ptr Word8 -> Ptr Word8 -> IO CInt
foreign import ccall "ec_vrf_verify_key" rs_verify_key :: Ptr Word8 -> CInt
foreign import ccall "ec_vrf_verify" rs_verify :: Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Word32-> IO CInt

-- |The size of a VRF public key in bytes (32).
publicKeySize :: Int
publicKeySize = 32

data PublicKeySize
instance FBS.FixedLength PublicKeySize where
    fixedLength _ = publicKeySize

-- |A VRF public key. 32 bytes.
newtype PublicKey = PublicKey (FBS.FixedByteString PublicKeySize)
    deriving (Eq, Ord)
    deriving Show via FBSHex PublicKeySize
    deriving Serialize via FBSHex PublicKeySize

-- |The size of a VRF private key in bytes (32).
privateKeySize :: Int
privateKeySize = 32

data PrivateKeySize
instance FBS.FixedLength PrivateKeySize where
    fixedLength _ = privateKeySize

-- |A VRF private key. 32 bytes.
newtype PrivateKey = PrivateKey (FBS.FixedByteString PrivateKeySize)
    deriving (Eq)
    deriving Show via (FBSHex PrivateKeySize)
    deriving Serialize via (FBSHex PrivateKeySize)

-- |The size of a VRF proof in bytes (80).
proofSize :: Int
proofSize = 80

data ProofSize
instance FBS.FixedLength ProofSize where
    fixedLength _ = proofSize

-- |A VRF proof. 80 bytes.
newtype Proof = Proof (FBS.FixedByteString ProofSize)
    deriving (Eq, Ord)
    deriving Show via (FBSHex ProofSize)
    deriving Serialize via (FBSHex ProofSize)

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
            key = KeyPair privKey (pubKey privKey)

instance Arbitrary KeyPair where
    arbitrary = fst . randomKeyPair . mkStdGen <$> arbitrary


-- |Generate a new key pair using the system random number generator.
newKeyPair :: IO KeyPair
newKeyPair = do sk <- newPrivKey 
                return (KeyPair sk (pubKey sk))

newPrivKey :: IO PrivateKey
newPrivKey = 
    do suc <- newIORef (0::Int)
       sk <- FBS.create $ \priv -> 
           do rc <-  rs_priv_key priv 
              case rc of
                   1 ->  do writeIORef suc 1 
                   _ ->  do writeIORef suc 0 
       suc' <- readIORef suc
       case suc' of
           0 -> error "Private key generation failed"
           _ -> return (PrivateKey sk)

-- |FIXME: This function should not error. It should fail gracefully by returning
-- Maybe or Either.
pubKey :: PrivateKey -> PublicKey
pubKey (PrivateKey sk) = PublicKey $! FBS.unsafeCreate $ \pub -> do
                            pc <- FBS.withPtrReadOnly sk $ \y -> rs_public_key pub y
                            if (pc == 1) then
                               return ()
                            else 
                              error "Public key generation failed"


test :: IO () 
test = do kp@(KeyPair sk pk) <- newKeyPair
          _ <- putStrLn("SK: " ++ show sk)
          _ <- putStrLn("PK: " ++ show pk)
          _ <- putStrLn("MESSAGE:") 
          alpha <- B.getLine
          prf <- prove kp alpha
          let valid = verify pk alpha prf 
              h' = proofToHash prf 
           in
              putStrLn ("Proof: " ++ show prf) >>
              putStrLn ("PK IS " ++ if verifyKey pk then "OK" else "BAD") >>
              putStrLn ("Verification: " ++ if valid then "VALID" else "INVALID") >>
              putStrLn ("Proof hash: " ++ show h')

-- |Generate a VRF proof.
prove :: KeyPair -> ByteString -> IO Proof
prove (KeyPair (PrivateKey sk) (PublicKey pk)) b = Proof <$>
                                        (FBS.create $ \prf -> 
                                           FBS.withPtrReadOnly pk $ \pk' -> 
                                               FBS.withPtrReadOnly sk $ \sk' -> 
                                                   B.unsafeUseAsCStringLen b $ \(b', blen) -> do
                                                       r <- rs_prove prf pk' sk' (castPtr b') (fromIntegral $ blen)
                                                       if r == 1 then return () else (error $ "Could not prove: " ++ show r))

-- |Verify a VRF proof.
verify :: PublicKey -> ByteString -> Proof -> Bool
verify (PublicKey pk) alpha (Proof prf) = cIntToBool $! unsafeDupablePerformIO $
                                                FBS.withPtrReadOnly pk $ \pk' ->
                                                   FBS.withPtrReadOnly prf $ \pi' ->
                                                     B.unsafeUseAsCStringLen alpha $ \(alpha', alphalen)->
                                                       rs_verify pk' pi' (castPtr alpha') (fromIntegral $ alphalen)
              where
                  cIntToBool x = x > 0

-- |FIXME: This function is unsafe. It will cause a runtime exception in foreign
-- code if the proof is not valid (not a point on the curve). Either the function
-- should be marked as such or should return an option.
-- |Generate a 256-bit hash from a VRF proof.
proofToHash :: Proof -> Hash
proofToHash (Proof p) =  Hash (FBS.unsafeCreate $ \x ->
                                  FBS.withPtrReadOnly p $ \p' -> rs_proof_to_hash x p' >> return())

-- |Verify a VRF public key.
verifyKey :: PublicKey -> Bool
verifyKey (PublicKey pk) =  x > 0 
            where
               x = FBS.withPtrReadOnlyST pk (return . rs_verify_key)
