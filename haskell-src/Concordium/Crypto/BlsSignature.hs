module Concordium.Crypto.BlsSignature (
    PublicKey,
    SecretKey (..),
    Signature,
    Proof,
    generateSecretKey,
    derivePublicKey,
    sign,
    verify,
    aggregate,
    aggregateMany,
    verifyAggregate,
    emptySignature,
    freeSecretKey,
    proveKnowledgeOfSK,
    checkProofOfKnowledgeSK,
    publicKeySize,
    proofSize,
)
where

import Concordium.Crypto.ByteStringHelpers
import Concordium.Crypto.FFIHelpers

import Control.DeepSeq
import qualified Data.Aeson as AE
import Data.ByteString
import Data.ByteString.Unsafe as BS
import Data.Int
import qualified Data.List as List
import Data.Serialize
import Data.Word
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Marshal.Array
import Foreign.Ptr
import System.IO.Unsafe

newtype PublicKey = PublicKey (ForeignPtr PublicKey)
newtype SecretKey = SecretKey (ForeignPtr SecretKey)
newtype Signature = Signature (ForeignPtr Signature)
newtype Proof = Proof (ForeignPtr Proof)

instance NFData PublicKey where
    rnf x = rwhnf x

instance NFData SecretKey where
    rnf x = rwhnf x

instance NFData Proof where
    rnf x = rwhnf x

foreign import ccall unsafe "&bls_free_sk" freeSecretKey :: FunPtr (Ptr SecretKey -> IO ())
foreign import ccall unsafe "bls_generate_secretkey" generateSecretKeyPtr :: IO (Ptr SecretKey)
foreign import ccall unsafe "bls_sk_to_bytes" toBytesSecretKey :: Ptr SecretKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "bls_sk_from_bytes" fromBytesSecretKey :: Ptr Word8 -> CSize -> IO (Ptr SecretKey)
foreign import ccall unsafe "bls_sk_eq" equalsSecretKey :: Ptr SecretKey -> Ptr SecretKey -> IO Word8
foreign import ccall unsafe "bls_sk_cmp" cmpSecretKey :: Ptr SecretKey -> Ptr SecretKey -> IO Int32

foreign import ccall unsafe "&bls_free_pk" freePublicKey :: FunPtr (Ptr PublicKey -> IO ())
foreign import ccall unsafe "bls_derive_publickey" derivePublicKeyPtr :: Ptr SecretKey -> IO (Ptr PublicKey)
foreign import ccall unsafe "bls_pk_to_bytes" toBytesPublicKey :: Ptr PublicKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "bls_pk_from_bytes" fromBytesPublicKey :: Ptr Word8 -> CSize -> IO (Ptr PublicKey)
foreign import ccall unsafe "bls_pk_eq" equalsPublicKey :: Ptr PublicKey -> Ptr PublicKey -> IO Word8
foreign import ccall unsafe "bls_pk_cmp" cmpPublicKey :: Ptr PublicKey -> Ptr PublicKey -> IO Int32

foreign import ccall unsafe "&bls_free_sig" freeSignature :: FunPtr (Ptr Signature -> IO ())
foreign import ccall unsafe "bls_sig_to_bytes" toBytesSignature :: Ptr Signature -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "bls_sig_from_bytes" fromBytesSignature :: Ptr Word8 -> CSize -> IO (Ptr Signature)
foreign import ccall unsafe "bls_empty_sig" emptyBlsSig :: IO (Ptr Signature)
foreign import ccall unsafe "bls_sig_eq" equalsSignature :: Ptr Signature -> Ptr Signature -> IO Word8
foreign import ccall unsafe "bls_sig_cmp" cmpSignature :: Ptr Signature -> Ptr Signature -> IO Int32

foreign import ccall unsafe "&bls_free_proof" freeProof :: FunPtr (Ptr Proof -> IO ())
foreign import ccall unsafe "bls_proof_to_bytes" toBytesProof :: Ptr Proof -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "bls_proof_from_bytes" fromBytesProof :: Ptr Word8 -> CSize -> IO (Ptr Proof)
foreign import ccall unsafe "bls_proof_eq" equalsProof :: Ptr Proof -> Ptr Proof -> IO Word8
foreign import ccall unsafe "bls_proof_cmp" cmpProof :: Ptr Proof -> Ptr Proof -> IO Int32

foreign import ccall unsafe "bls_sign" signBls :: Ptr Word8 -> CSize -> Ptr SecretKey -> IO (Ptr Signature)
foreign import ccall safe "bls_verify" verifyBls :: Ptr Word8 -> CSize -> Ptr PublicKey -> Ptr Signature -> IO Word8
foreign import ccall unsafe "bls_aggregate" aggregateBls :: Ptr Signature -> Ptr Signature -> IO (Ptr Signature)
foreign import ccall safe "bls_verify_aggregate" verifyBlsAggregate :: Ptr Word8 -> CSize -> Ptr (Ptr PublicKey) -> CSize -> Ptr Signature -> IO Word8
foreign import ccall safe "bls_prove" proveBls :: Ptr Word8 -> CSize -> Ptr SecretKey -> IO (Ptr Proof)
foreign import ccall safe "bls_check_proof" checkProofBls :: Ptr Word8 -> CSize -> Ptr Proof -> Ptr PublicKey -> IO Word8

withSecretKey :: SecretKey -> (Ptr SecretKey -> IO b) -> IO b
withSecretKey (SecretKey fp) = withForeignPtr fp

withPublicKey :: PublicKey -> (Ptr PublicKey -> IO b) -> IO b
withPublicKey (PublicKey fp) = withForeignPtr fp

withSignature :: Signature -> (Ptr Signature -> IO b) -> IO b
withSignature (Signature fp) = withForeignPtr fp

withProof :: Proof -> (Ptr Proof -> IO b) -> IO b
withProof (Proof fp) = withForeignPtr fp

secretKeySize :: Int
secretKeySize = 32

publicKeySize :: Int
publicKeySize = 96

signatureSize :: Int
signatureSize = 48

proofSize :: Int
proofSize = 64

-- SecretKey implementations

instance Serialize SecretKey where
    get = do
        bs <- getByteString secretKeySize
        case fromBytesHelper freeSecretKey fromBytesSecretKey bs of
            Nothing -> fail "Cannot decode SecretKey"
            Just x -> return $ SecretKey x

    put (SecretKey p) =
        let bs = toBytesHelper toBytesSecretKey p
        in  putByteString bs

instance Show SecretKey where
    show = byteStringToHex . encode

-- Serializes to bytes and compares bytes
-- NOT CONSTANT TIME, USE ONLY FOR TESTING
instance Eq SecretKey where
    SecretKey p1 == SecretKey p2 = eqHelper p1 p2 equalsSecretKey

-- Serializes to bytes and compares bytes
-- NOT CONSTANT TIME, USE ONLY FOR TESTING
instance Ord SecretKey where
    compare (SecretKey sk1) (SecretKey sk2) =
        cmpHelper sk1 sk2 cmpSecretKey

instance AE.FromJSON SecretKey where
    parseJSON = AE.withText "Bls.SecretKey" deserializeBase16

instance AE.ToJSON SecretKey where
    toJSON v = AE.String (serializeBase16 v)

-- PublicKey implementations

instance Serialize PublicKey where
    get = do
        bs <- getByteString publicKeySize
        case fromBytesHelper freePublicKey fromBytesPublicKey bs of
            Nothing -> fail "Cannot decode PublicKey"
            Just x -> return $ PublicKey x

    put (PublicKey p) =
        let bs = toBytesHelper toBytesPublicKey p
        in  putByteString bs

instance Show PublicKey where
    show = byteStringToHex . encode

-- Serializes to bytes and compares bytes
instance Eq PublicKey where
    PublicKey p1 == PublicKey p2 = eqHelper p1 p2 equalsPublicKey

-- Serializes to bytes and compares bytes
instance Ord PublicKey where
    compare (PublicKey pk1) (PublicKey pk2) =
        cmpHelper pk1 pk2 cmpPublicKey

instance AE.FromJSON PublicKey where
    parseJSON = AE.withText "Bls.PublicKey" deserializeBase16

instance AE.ToJSON PublicKey where
    toJSON v = AE.String (serializeBase16 v)

-- Signature implementations

instance Serialize Signature where
    get = do
        bs <- getByteString signatureSize
        case fromBytesHelper freeSignature fromBytesSignature bs of
            Nothing -> fail "Cannot decode Signature"
            Just x -> return $ Signature x

    put (Signature p) =
        let bs = toBytesHelper toBytesSignature p
        in  putByteString bs

instance Show Signature where
    show = byteStringToHex . encode

-- Serializes to bytes and compares bytes
instance Eq Signature where
    Signature p1 == Signature p2 = eqHelper p1 p2 equalsSignature

-- Serializes to bytes and compares bytes
instance Ord Signature where
    compare (Signature sig1) (Signature sig2) =
        cmpHelper sig1 sig2 cmpSignature

instance AE.FromJSON Signature where
    parseJSON = AE.withText "Bls.Signature" deserializeBase16

instance AE.ToJSON Signature where
    toJSON v = AE.String (serializeBase16 v)

-- Proof implementations

instance Serialize Proof where
    get = do
        bs <- getByteString proofSize
        case fromBytesHelper freeProof fromBytesProof bs of
            Nothing -> fail "Cannot decode Proof"
            Just x -> return $ Proof x

    put (Proof p) =
        let bs = toBytesHelper toBytesProof p
        in  putByteString bs

instance Show Proof where
    show = byteStringToHex . encode

-- Serializes to bytes and compares bytes
instance Eq Proof where
    Proof p1 == Proof p2 = eqHelper p1 p2 equalsProof

-- Serializes to bytes and compares bytes
instance Ord Proof where
    compare (Proof p1) (Proof p2) =
        cmpHelper p1 p2 cmpProof

instance AE.FromJSON Proof where
    parseJSON = AE.withText "Bls.Proof" deserializeBase16

instance AE.ToJSON Proof where
    toJSON p = AE.String (serializeBase16 p)

-- Signature scheme implementation

-- |Generate a secret key using a system random number generator.
generateSecretKey :: IO SecretKey
generateSecretKey = do
    ptr <- generateSecretKeyPtr
    SecretKey <$> newForeignPtr freeSecretKey ptr

-- |Derive a public key from a given secret key.
derivePublicKey :: SecretKey -> PublicKey
derivePublicKey sk = PublicKey <$> unsafePerformIO $ do
    pkptr <- withSecretKey sk derivePublicKeyPtr
    newForeignPtr freePublicKey pkptr

emptySignature :: Signature
emptySignature = Signature <$> unsafePerformIO $ do
    sigptr <- emptyBlsSig
    newForeignPtr freeSignature sigptr

sign :: ByteString -> SecretKey -> Signature
sign m sk = Signature <$> unsafePerformIO $ do
    -- unsafeUseAsCString is ok here, mlen == 0 is appropriately handled in rust
    sigptr <- BS.unsafeUseAsCStringLen m $ \(m', mlen) ->
        withSecretKey sk $ signBls (castPtr m') (fromIntegral mlen)
    newForeignPtr freeSignature sigptr

-- |Verify a single signature.
verify :: ByteString -> PublicKey -> Signature -> Bool
verify m pk sig = unsafePerformIO $ do
    -- unsafeUseAsCString is ok here, mlen == 0 is appropriately handled in rust
    BS.unsafeUseAsCStringLen m $ \(m', mlen) ->
        withPublicKey pk $ \pk' ->
            withSignature sig $! (fmap (== 1) . verifyBls (castPtr m') (fromIntegral mlen) pk')

-- |Aggregate two signatures together.
aggregate :: Signature -> Signature -> Signature
aggregate sig1 sig2 = Signature <$> unsafePerformIO $ do
    sigptr <- withSignature sig1 $ \sig1' ->
        withSignature sig2 $ \sig2' ->
            aggregateBls sig1' sig2'
    newForeignPtr freeSignature sigptr

-- |Verify a signature on bytestring under the list of public keys
-- The order of the public key list is irrelevant to the result
verifyAggregate :: ByteString -> [PublicKey] -> Signature -> Bool
verifyAggregate m pks sig = unsafePerformIO $ do
    -- unsafeUseAsCString is ok here, mlen == 0 is appropriately handled in rust
    BS.unsafeUseAsCStringLen m $ \(m', mlen) ->
        withSignature sig $ \sig' ->
            withKeyArray [] pks $ \arrlen -> \headptr ->
                (== 1) <$> verifyBlsAggregate (castPtr m') (fromIntegral mlen) headptr (fromIntegral arrlen) sig'
  where
    withKeyArray ps [] f = withArrayLen ps f
    withKeyArray ps (pk : pks_) f = withPublicKey pk $ \pk' -> withKeyArray (pk' : ps) pks_ f

-- |Create a proof of knowledge of your secret key
proveKnowledgeOfSK :: ByteString -> SecretKey -> IO Proof
proveKnowledgeOfSK context sk =
    Proof <$> do
        -- unsafeUseAsCString is ok here, clen == 0 is appropriately handled in rust
        proofPtr <- BS.unsafeUseAsCStringLen context $ \(c, clen) ->
            withSecretKey sk $ \sk' ->
                proveBls (castPtr c) (fromIntegral clen) sk'
        newForeignPtr freeProof proofPtr

-- |Check a proof of knowledge for a publickey
checkProofOfKnowledgeSK :: ByteString -> Proof -> PublicKey -> Bool
checkProofOfKnowledgeSK context proof pk = unsafePerformIO $ do
    -- unsafeUseAsCString is ok here, clen == 0 is appropriately handled in rust
    BS.unsafeUseAsCStringLen context $ \(c, clen) ->
        withPublicKey pk $ \pk' ->
            withProof proof $ \proof' ->
                (== 1) <$> checkProofBls (castPtr c) (fromIntegral clen) proof' pk'

instance Semigroup Signature where
    (<>) = aggregate

instance Monoid Signature where
    mempty = emptySignature

-- |Aggregate a list of signatures.
aggregateMany :: [Signature] -> Signature
aggregateMany (s : sigs) = List.foldl' aggregate s sigs
aggregateMany [] = emptySignature
