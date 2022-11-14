{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}

-- | This module is a prototype implementantion of  verifiable random function.
-- draft-irtf-cfrg-vrf-07
module Concordium.Crypto.VRF (
    PublicKey,
    SecretKey,
    newPrivKey,
    pubKey,
    withPublicKey,
    withSecretKey,
    KeyPair (..),
    Hash,
    Proof,
    randomKeyPair,
    newKeyPair,
    prove,
    proofToHash,
    withProof,
    verify,
    verifyKey,
    hashToDouble,
    hashToInt,
    publicKeySize,
) where

import Concordium.Crypto.ByteStringHelpers
import Concordium.Crypto.FFIHelpers
import Control.DeepSeq
import Control.Monad
import qualified Data.Aeson as AE
import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as B
import Data.Data (Data, Typeable)
import qualified Data.FixedByteString as FBS
import Data.Int
import Data.Serialize
import Data.Word
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Ptr
import GHC.Generics
import System.IO.Unsafe
import System.Random
import Test.QuickCheck (Arbitrary (..))

newtype PublicKey = PublicKey (ForeignPtr PublicKey)
newtype SecretKey = SecretKey (ForeignPtr SecretKey)
newtype Proof = Proof (ForeignPtr Proof)

instance NFData PublicKey where
    rnf x = rwhnf x

instance NFData SecretKey where
    rnf x = rwhnf x

foreign import ccall unsafe "&ecvrf_proof_free" freeProof :: FunPtr (Ptr Proof -> IO ())
foreign import ccall unsafe "&ecvrf_public_key_free" freePublicKey :: FunPtr (Ptr PublicKey -> IO ())
foreign import ccall unsafe "&ecvrf_secret_key_free" freeSecretKey :: FunPtr (Ptr SecretKey -> IO ())
foreign import ccall unsafe "ecvrf_proof_to_bytes" toBytesProof :: Ptr Proof -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "ecvrf_public_key_to_bytes" toBytesPublicKey :: Ptr PublicKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "ecvrf_secret_key_to_bytes" toBytesSecretKey :: Ptr SecretKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "ecvrf_proof_from_bytes" fromBytesProof :: Ptr Word8 -> CSize -> IO (Ptr Proof)
foreign import ccall unsafe "ecvrf_public_key_from_bytes" fromBytesPublicKey :: Ptr Word8 -> CSize -> IO (Ptr PublicKey)
foreign import ccall unsafe "ecvrf_secret_key_from_bytes" fromBytesSecretKey :: Ptr Word8 -> CSize -> IO (Ptr SecretKey)
foreign import ccall unsafe "ecvrf_priv_key" generateSecretKey :: IO (Ptr SecretKey)

foreign import ccall unsafe "ecvrf_proof_eq" proofEq :: Ptr Proof -> Ptr Proof -> IO Word8
foreign import ccall unsafe "ecvrf_public_key_eq" publicKeyEq :: Ptr PublicKey -> Ptr PublicKey -> IO Word8
foreign import ccall unsafe "ecvrf_secret_key_eq" secretKeyEq :: Ptr SecretKey -> Ptr SecretKey -> IO Word8

foreign import ccall unsafe "ecvrf_proof_cmp" proofOrd :: Ptr Proof -> Ptr Proof -> IO Int32
foreign import ccall unsafe "ecvrf_public_key_cmp" publicKeyOrd :: Ptr PublicKey -> Ptr PublicKey -> IO Int32

foreign import ccall "ecvrf_pub_key" rs_public_key :: Ptr SecretKey -> IO (Ptr PublicKey)
foreign import ccall "ecvrf_prove" rs_prove :: Ptr PublicKey -> Ptr SecretKey -> Ptr Word8 -> CSize -> IO (Ptr Proof)
foreign import ccall "ecvrf_proof_to_hash" rs_proof_to_hash :: Ptr Word8 -> Ptr Proof -> IO ()
foreign import ccall "ecvrf_verify_key" rs_verify_key :: Ptr PublicKey -> IO Bool
foreign import ccall "ecvrf_verify" rs_verify :: Ptr PublicKey -> Ptr Proof -> Ptr Word8 -> CSize -> IO Int32

-- |As a wrapper over `withForeignPtr` this allows temporary access
-- to the underlying `ForeignPtr` inside a `Proof`. The internally
-- exposed pointer must not be used outside of the call to the
-- provided function.
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
        in  putByteString bs

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
        in  putByteString bs

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
        in  putByteString bs

instance AE.FromJSON SecretKey where
    parseJSON = AE.withText "VRF.SecretKey" deserializeBase16

instance AE.ToJSON SecretKey where
    toJSON v = AE.String (serializeBase16 v)

instance Show SecretKey where
    show = byteStringToHex . encode

instance Eq SecretKey where
    SecretKey p1 == SecretKey p2 = eqHelper p1 p2 secretKeyEq

-- |A VRF key pair.
data KeyPair = KeyPair
    { privateKey :: !SecretKey,
      publicKey :: !PublicKey
    }
    deriving (Eq, Show, Generic)

instance NFData KeyPair

instance Serialize KeyPair where
    put (KeyPair priv pub) = put priv <> put pub
    get = do
        privateKey <- get
        publicKey <- get
        when (publicKey /= pubKey privateKey) $ fail "Private key does not correspond to the public key."
        return KeyPair{..}

instance AE.FromJSON KeyPair where
    parseJSON = AE.withObject "Baker block signature key" $ \obj -> do
        privateKey <- obj AE..: "electionPrivateKey"
        publicKey <- obj AE..: "electionVerifyKey"
        when (publicKey /= pubKey privateKey) $ fail "Private key does not correspond to the public key."
        return KeyPair{..}

-- |A SHA512 hash.  64 bytes.
digestSize :: Int
digestSize = 64

data DigestSize
    deriving (Typeable, Data)

instance FBS.FixedLength DigestSize where
    fixedLength _ = digestSize

newtype Hash = Hash (FBS.FixedByteString DigestSize)
    deriving (Eq, Ord, Bits, Bounded, Enum, Typeable, Data)
    deriving (Serialize) via FBSHex DigestSize
    deriving (Show) via FBSHex DigestSize
    deriving (AE.ToJSON, AE.FromJSON, AE.FromJSONKey, AE.ToJSONKey) via FBSHex DigestSize

-- |Convert a 'Hash' into a 'Double' value in the range [0,1].
-- This implementation takes the first 64-bit word (big-endian) and uses it
-- as the significand, with an exponent of -64.  Since the precision of a
-- 'Double' is only 53 bits, there is inevitably some loss.  This also means
-- that the outcome 1 is not possible.
hashToDouble :: Hash -> Double
hashToDouble (Hash h) =
    let w = FBS.readWord64be h
    in  encodeFloat (toInteger w) (-64)

-- |Convert a 'Hash' to an 'Int'.
hashToInt :: Hash -> Int
hashToInt (Hash h) = fromIntegral . FBS.readWord64be $ h

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
newKeyPair = do
    sk <- newPrivKey
    return (KeyPair sk (pubKey sk))

newPrivKey :: IO SecretKey
newPrivKey =
    do
        ptr <- generateSecretKey
        SecretKey <$> newForeignPtr freeSecretKey ptr

pubKey :: SecretKey -> PublicKey
pubKey sk = unsafePerformIO $!
    withSecretKey sk $
        \skPtr -> do
            pkPtr <- rs_public_key skPtr
            PublicKey <$> newForeignPtr freePublicKey pkPtr

-- |Generate a VRF proof.
prove :: KeyPair -> ByteString -> Proof
prove (KeyPair sk pk) b = unsafePerformIO $!
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
proofToHash prf =
    Hash
        ( FBS.unsafeCreate $ \x ->
            withProof prf $ \prfPtr -> rs_proof_to_hash x prfPtr
        )

-- |Verify a VRF public key.
-- NB: This is redundant if only functions in this module are used to construct
-- public keys. Deserialization makes sure that the public key is always valid,
-- and given a valid secret key the derived public key is always valid as well.
{-# DEPRECATED verifyKey "This is no longer needed. Only valid keys can be constructed." #-}
verifyKey :: PublicKey -> Bool
verifyKey pk =
    unsafeDupablePerformIO $!
        withPublicKey pk rs_verify_key
