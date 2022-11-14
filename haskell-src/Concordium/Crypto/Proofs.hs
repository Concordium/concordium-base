{-# LANGUAGE DerivingVia #-}

module Concordium.Crypto.Proofs (
    Dlog25519Proof,
    checkDlog25519ProofSig,
    checkDlog25519ProofVRF,
    checkDlog25519ProofBlock,
    randomProof,
    proveDlog25519KP,
    proveDlog25519VRF,
    proveDlog25519Block,
    dlogProofSize,
)
where

import Data.Serialize
import Foreign.C.Types
import Foreign.Ptr

import Concordium.Crypto.ByteStringHelpers
import Data.FixedByteString

import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BS
import Data.Int
import Data.Word

import System.IO.Unsafe
import System.Random

import Control.DeepSeq

import qualified Concordium.Crypto.BlockSignature as BlockSig
import qualified Concordium.Crypto.SignatureScheme as Sig
import qualified Concordium.Crypto.VRF as VRF
import qualified Data.Aeson as AE

data Dlog25519ProofLength

dlogProofSize :: Int
dlogProofSize = 64

instance FixedLength Dlog25519ProofLength where
    fixedLength _ = dlogProofSize

instance NFData Dlog25519Proof where
    rnf x = rwhnf x

newtype Dlog25519Proof = Dlog25519Proof (FixedByteString Dlog25519ProofLength)
    deriving (Eq)
    deriving (Show, Serialize, AE.FromJSON, AE.ToJSON) via FBSHex Dlog25519ProofLength

-- |Generate a random proof (could be completely invalid). Meant for testing.
randomProof :: RandomGen g => g -> (Dlog25519Proof, g)
randomProof gen = (key, gen')
  where
    (gen0, gen') = split gen
    bytes = pack (take dlogProofSize $ randoms gen0)
    key = Dlog25519Proof bytes

foreign import ccall safe "eddsa_verify_dlog_ed25519"
    verifyDlogFFI ::
        Ptr Word8 ->
        CSize ->
        Ptr Word8 ->
        Ptr Word8 ->
        IO Int32

foreign import ccall safe "eddsa_prove_dlog_ed25519"
    proveDlogFFI ::
        Ptr Word8 -> -- challenge bytes
        CSize ->
        Ptr Word8 -> -- public key bytes
        Ptr Word8 -> -- secret key bytes
        Ptr Word8 -> -- Return pointer for proof data
        IO Int32

checkDlog25519Proof ::
    -- |The challenge prefix to use
    BS.ByteString ->
    -- |Public key serialized in bytes (needs to be 32 bytes in length).
    BS.ByteString ->
    -- |Purported proof.
    Dlog25519Proof ->
    Bool
checkDlog25519Proof challenge publicKey (Dlog25519Proof proof) = unsafePerformIO $
    BS.unsafeUseAsCStringLen challenge $ \(c_ptr, c_len) ->
        BS.unsafeUseAsCStringLen publicKey $ \(pk_ptr, pk_len) ->
            if pk_len /= 32
                then return False
                else withPtrReadOnly proof $ \proof_ptr -> do
                    r <- verifyDlogFFI (castPtr c_ptr) (fromIntegral c_len) (castPtr pk_ptr) proof_ptr
                    return (r == 1)

-- |NB: This crucially relies on key serialization being consistent.
checkDlog25519ProofSig ::
    -- |The challenge prefix to use
    BS.ByteString ->
    -- |The VRF public key.
    Sig.VerifyKey ->
    -- |Purported proof.
    Dlog25519Proof ->
    Bool
checkDlog25519ProofSig challenge (Sig.VerifyKeyEd25519 vfkey) = checkDlog25519Proof challenge (encode vfkey)

checkDlog25519ProofVRF ::
    -- |The challenge prefix to use
    BS.ByteString ->
    -- |The VRF public key.
    VRF.PublicKey ->
    -- |Purported proof.
    Dlog25519Proof ->
    Bool
checkDlog25519ProofVRF challenge = checkDlog25519Proof challenge . encode

-- |NB: This crucially relies on key serialization being consistent.
checkDlog25519ProofBlock ::
    -- |The challenge prefix to use
    BS.ByteString ->
    -- |The VRF public key.
    BlockSig.VerifyKey ->
    -- |Purported proof.
    Dlog25519Proof ->
    Bool
checkDlog25519ProofBlock challenge vfkey = checkDlog25519Proof challenge (encode vfkey)

proveDlog25519 :: BS.ByteString -> BS.ByteString -> BS.ByteString -> IO (Maybe Dlog25519Proof)
proveDlog25519 challenge publicKey secretKey =
    BS.unsafeUseAsCStringLen challenge $ \(c_ptr, c_len) ->
        BS.unsafeUseAsCStringLen publicKey $ \(pk_ptr, pk_len) ->
            if pk_len /= 32
                then return Nothing
                else BS.unsafeUseAsCStringLen secretKey $ \(sk_ptr, sk_len) ->
                    if sk_len /= 32
                        then return Nothing
                        else do
                            (r, bs) <- createWith $ proveDlogFFI (castPtr c_ptr) (fromIntegral c_len) (castPtr pk_ptr) (castPtr sk_ptr)
                            if r == 0
                                then return (Just (Dlog25519Proof bs))
                                else return Nothing

-- |NB: Key serialization must not add length information.
proveDlog25519KP :: BS.ByteString -> Sig.KeyPair -> IO (Maybe Dlog25519Proof)
proveDlog25519KP challenge Sig.KeyPairEd25519{..} =
    proveDlog25519 challenge (encode verifyKey) (encode signKey)

-- |NB: Key serialization must not add length information.
proveDlog25519Block :: BS.ByteString -> BlockSig.KeyPair -> IO (Maybe Dlog25519Proof)
proveDlog25519Block challenge BlockSig.KeyPair{..} =
    proveDlog25519 challenge (encode verifyKey) (encode signKey)

-- |NB: Key serialization must not add length information.
proveDlog25519VRF :: BS.ByteString -> VRF.KeyPair -> IO (Maybe Dlog25519Proof)
proveDlog25519VRF challenge (VRF.KeyPair sigKey vfKey) =
    proveDlog25519 challenge (encode vfKey) (encode sigKey)
