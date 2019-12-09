{-# LANGUAGE GeneralizedNewtypeDeriving, ForeignFunctionInterface,
             DerivingVia, RecordWildCards, OverloadedStrings #-}
-- | This module is a prototype implementantion of  verifiable random function.
-- draft-irtf-cfrg-vrf-01


module Concordium.Crypto.VRF(
    PublicKey,
    SecretKey,
    newPrivKey,
    pubKey,
    withPublicKey,
    withSecretKey,
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
import           Concordium.Crypto.SHA256
import           System.Random
import           Test.QuickCheck (Arbitrary(..))
import qualified Data.Aeson as AE
import Data.Int
import Foreign.ForeignPtr
import Concordium.Crypto.FFIHelpers

newtype PublicKey = PublicKey (ForeignPtr PublicKey)
newtype SecretKey = SecretKey (ForeignPtr SecretKey)
newtype Proof = Proof (ForeignPtr Proof)

foreign import ccall unsafe "&ec_vrf_proof_free" freeProof :: FunPtr (Ptr Proof -> IO ())
foreign import ccall unsafe "&ec_vrf_public_key_free" freePublicKey :: FunPtr (Ptr PublicKey -> IO ())
foreign import ccall unsafe "&ec_vrf_secret_key_free" freeSecretKey :: FunPtr (Ptr SecretKey -> IO ())
foreign import ccall unsafe "ec_vrf_proof_to_bytes" toBytesProof :: Ptr Proof -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "ec_vrf_public_key_to_bytes" toBytesPublicKey :: Ptr PublicKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "ec_vrf_secret_key_to_bytes" toBytesSecretKey :: Ptr SecretKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "ec_vrf_proof_from_bytes" fromBytesProof :: Ptr Word8 -> CSize -> IO (Ptr Proof)
foreign import ccall unsafe "ec_vrf_public_key_from_bytes" fromBytesPublicKey :: Ptr Word8 -> CSize -> IO (Ptr PublicKey)
foreign import ccall unsafe "ec_vrf_secret_key_from_bytes" fromBytesSecretKey :: Ptr Word8 -> CSize -> IO (Ptr SecretKey)
foreign import ccall unsafe "ec_vrf_priv_key" generateSecretKey :: IO (Ptr SecretKey)

foreign import ccall unsafe "ec_vrf_proof_eq" proofEq :: Ptr Proof -> Ptr Proof -> IO Word8
foreign import ccall unsafe "ec_vrf_public_key_eq" publicKeyEq :: Ptr PublicKey -> Ptr PublicKey -> IO Word8
foreign import ccall unsafe "ec_vrf_secret_key_eq" secretKeyEq :: Ptr SecretKey -> Ptr SecretKey -> IO Word8

foreign import ccall unsafe "ec_vrf_proof_cmp" proofOrd :: Ptr Proof -> Ptr Proof -> IO Int32
foreign import ccall unsafe "ec_vrf_public_key_cmp" publicKeyOrd :: Ptr PublicKey -> Ptr PublicKey -> IO Int32

foreign import ccall "ec_vrf_pub_key" rs_public_key :: Ptr SecretKey -> IO (Ptr PublicKey)
foreign import ccall "ec_vrf_prove" rs_prove :: Ptr PublicKey -> Ptr SecretKey -> Ptr Word8 -> CSize -> IO (Ptr Proof)
foreign import ccall "ec_vrf_proof_to_hash" rs_proof_to_hash :: Ptr Word8 -> Ptr Proof -> IO ()
foreign import ccall "ec_vrf_verify_key" rs_verify_key :: Ptr PublicKey -> IO Bool
foreign import ccall "ec_vrf_verify" rs_verify :: Ptr PublicKey -> Ptr Proof -> Ptr Word8 -> CSize -> IO Int32

withProof :: Proof -> (Ptr Proof -> IO b) -> IO b
withProof (Proof fp) = withForeignPtr fp

withPublicKey :: PublicKey -> (Ptr PublicKey -> IO b) -> IO b
withPublicKey (PublicKey fp) = withForeignPtr fp

withSecretKey :: SecretKey -> (Ptr SecretKey -> IO b) -> IO b
withSecretKey (SecretKey fp) = withForeignPtr fp

publicKeySize :: Int
publicKeySize = 32

secretKeySize :: Int
secretKeySize = 32

proofSize :: Int
proofSize = 80

instance Serialize Proof where
  get = do
    bs <- getByteString proofSize
    case fromBytesHelper freeProof fromBytesProof bs of
      Nothing -> fail "Cannot decode proof."
      Just x -> return $ Proof x

  put (Proof p) =
    let bs = toBytesHelper toBytesProof p
    in putByteString bs

instance AE.FromJSON Proof where
  parseJSON = AE.withText "VRF.Proof" deserializeBase16

instance AE.ToJSON Proof where
  toJSON v = AE.String (serializeBase16 v)

instance Eq Proof where
  Proof p1 == Proof p2 = eqHelper p1 p2 proofEq

instance Ord Proof where
  compare p1 p2 = unsafeDupablePerformIO $! 
    withProof p1 $ \p1Ptr ->
      withProof p2 $ \p2Ptr -> do
        r <- proofOrd p1Ptr p2Ptr
        case r of
          0 -> return EQ
          1 -> return GT
          -1 -> return LT
          _ -> error "Should not happen. FFI import breaks precondition."

instance Show Proof where
  show = byteStringToHex . encode

instance Serialize PublicKey where
  get = do
    bs <- getByteString publicKeySize
    case fromBytesHelper freePublicKey fromBytesPublicKey bs of
      Nothing -> fail "Cannot decode public key."
      Just x -> return $ PublicKey x

  put (PublicKey p) =
    let bs = toBytesHelper toBytesPublicKey p
    in putByteString bs

instance AE.FromJSON PublicKey where
  parseJSON = AE.withText "VRF.PublicKey" deserializeBase16

instance AE.ToJSON PublicKey where
  toJSON v = AE.String (serializeBase16 v)

instance Eq PublicKey where
  PublicKey p1 == PublicKey p2 = eqHelper p1 p2 publicKeyEq

instance Ord PublicKey where
  compare p1 p2 = unsafeDupablePerformIO $! 
    withPublicKey p1 $ \p1Ptr ->
      withPublicKey p2 $ \p2Ptr -> do
        r <- publicKeyOrd p1Ptr p2Ptr
        case r of
          0 -> return EQ
          1 -> return GT
          -1 -> return LT
          _ -> error "Should not happen. FFI import breaks precondition."

instance Show PublicKey where
  show = byteStringToHex . encode

instance Serialize SecretKey where
  get = do
    bs <- getByteString secretKeySize
    case fromBytesHelper freeSecretKey fromBytesSecretKey bs of
      Nothing -> fail "Cannot decode secret key."
      Just x -> return $ SecretKey x

  put (SecretKey p) =
    let bs = toBytesHelper toBytesSecretKey p
    in putByteString bs

instance AE.FromJSON SecretKey where
  parseJSON = AE.withText "VRF.SecretKey" deserializeBase16

instance AE.ToJSON SecretKey where
  toJSON v = AE.String (serializeBase16 v)

instance Show SecretKey where
  show = byteStringToHex . encode

instance Eq SecretKey where
  SecretKey p1 == SecretKey p2 = eqHelper p1 p2 secretKeyEq

-- |A VRF key pair.
data KeyPair = KeyPair {
    privateKey :: !SecretKey,
    publicKey :: !PublicKey
} deriving (Eq, Show)

instance Serialize KeyPair where
    put (KeyPair priv pub) = put priv <> put pub
    get = KeyPair <$> get <*> get

instance AE.FromJSON KeyPair where
    parseJSON = AE.withObject "Baker block signature key" $ \obj -> do
      privateKey <- obj AE..: "electionPrivateKey"
      publicKey <- obj AE..: "electionVerifyKey"
      return KeyPair{..}

-- |Generate a key pair using a given random generator.
-- Useful for generating deterministic pseudo-random keys.
randomKeyPair :: RandomGen g => g -> (KeyPair, g)
randomKeyPair gen = (key, gen')
        where
            (gen0, gen') = split gen
            secretKeyBytes = B.pack . take secretKeySize $ randoms gen0
            secretKey =
              case decode secretKeyBytes of
                Left err -> error $ "Should not happen since any 32 bytes are a valid secret key: " ++ err
                Right sk -> sk
            key = KeyPair secretKey (pubKey secretKey)

instance Arbitrary KeyPair where
    arbitrary = fst . randomKeyPair . mkStdGen <$> arbitrary

-- |Generate a new key pair using the system random number generator.
newKeyPair :: IO KeyPair
newKeyPair = do sk <- newPrivKey 
                return (KeyPair sk (pubKey sk))

newPrivKey :: IO SecretKey
newPrivKey = 
    do ptr <- generateSecretKey
       SecretKey <$> newForeignPtr freeSecretKey ptr

pubKey :: SecretKey -> PublicKey
pubKey sk = unsafeDupablePerformIO $!
    withSecretKey sk $
      \skPtr -> do
        pkPtr <- rs_public_key skPtr
        PublicKey <$> newForeignPtr freePublicKey pkPtr

-- |Generate a VRF proof.
prove :: KeyPair -> ByteString -> IO Proof
prove (KeyPair sk pk) b = do
  withPublicKey pk $ \pkPtr ->
    withSecretKey sk $ \skPtr ->
      -- this use of unsafe is fine because the called function checks
      -- the length before dereferencing the data pointer of the payload
      B.unsafeUseAsCStringLen b $ \(bPtr, blen) -> do
        res <- rs_prove pkPtr skPtr (castPtr bPtr) (fromIntegral blen)
        Proof <$> newForeignPtr freeProof res

-- |Verify a VRF proof.
verify :: PublicKey -> ByteString -> Proof -> Bool
verify pk alpha prf = unsafeDupablePerformIO $!
  withPublicKey pk $ \pkPtr ->
    withProof prf $ \prfPtr ->
      -- this use of unsafe is fine because the called function
      -- checks length first before dereferencing the data pointer
      B.unsafeUseAsCStringLen alpha $ \(alphaPtr, alphaLen) -> do
        res <- rs_verify pkPtr prfPtr (castPtr alphaPtr) (fromIntegral alphaLen)
        return $! res == 1

-- |Generate a 256-bit hash from a VRF proof.
proofToHash :: Proof -> Hash
proofToHash prf =  Hash (FBS.unsafeCreate $ \x ->
                            withProof prf $ \prfPtr -> rs_proof_to_hash x prfPtr)

-- |Verify a VRF public key.
-- NB: This is redundant if only functions in this module are used to construct
-- public keys. Deserialization makes sure that the public key is always valid,
-- and given a valid secret key the derived public key is always valid as well.
{-# DEPRECATED verifyKey "This is no longer needed. Only valid keys can be constructed." #-}
verifyKey :: PublicKey -> Bool
verifyKey pk = unsafeDupablePerformIO $!
    withPublicKey pk rs_verify_key
