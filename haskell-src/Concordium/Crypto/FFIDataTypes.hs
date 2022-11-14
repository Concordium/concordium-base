module Concordium.Crypto.FFIDataTypes (
    -- * Pedersen commitment keys.
    PedersenKey,
    generatePedersenKey,
    withPedersenKey,

    -- * PointCheval-Sanders public keys.
    PsSigKey,
    generatePsSigKey,
    withPsSigKey,

    -- * Elgamal public and private keys.
    ElgamalPublicKey,
    ElgamalSecretKey,
    withElgamalPublicKey,
    withElgamalSecretKey,
    generateElgamalSecretKeyFromSeed,

    -- * G1 group elements.
    GroupElement,
    withGroupElement,
    generateGroupElementFromSeed,
    deriveElgamalPublicKey,

    -- * Elgamal ciphers in Bls12 G1 group.
    ElgamalCipher,
    generateElgamalCipher,
    withElgamalCipher,
    zeroElgamalCipher,
    unsafeMakeCipher,
)
where

import Concordium.Crypto.ByteStringHelpers
import Concordium.Crypto.FFIHelpers
import Concordium.ID.Parameters

import Control.DeepSeq
import qualified Data.Aeson as AE
import Data.ByteString as BS
import Data.Serialize
import Data.Word
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Ptr
import System.IO.Unsafe (unsafePerformIO)

newtype PedersenKey = PedersenKey (ForeignPtr PedersenKey)
newtype PsSigKey = PsSigKey (ForeignPtr PsSigKey)

-- | Element of the G1 group of the Bls curve
newtype GroupElement = GroupElement (ForeignPtr GroupElement)

newtype ElgamalPublicKey = ElgamalPublicKey (ForeignPtr ElgamalPublicKey)
newtype ElgamalSecretKey = ElgamalSecretKey (ForeignPtr ElgamalSecretKey)

newtype ElgamalCipher = ElgamalCipher (ForeignPtr ElgamalCipher)

-- |Instances for benchmarking
instance NFData PedersenKey where
    rnf = (`seq` ())

instance NFData PsSigKey where
    rnf = (`seq` ())
instance NFData ElgamalPublicKey where
    rnf = (`seq` ())
instance NFData ElgamalSecretKey where
    rnf = (`seq` ())
instance NFData GroupElement where
    rnf = (`seq` ())
instance NFData ElgamalCipher where
    rnf = (`seq` ())

foreign import ccall unsafe "&pedersen_key_free" freePedersenKey :: FunPtr (Ptr PedersenKey -> IO ())
foreign import ccall safe "pedersen_key_to_bytes" toBytesPedersenKey :: Ptr PedersenKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall safe "pedersen_key_from_bytes" fromBytesPedersenKey :: Ptr Word8 -> CSize -> IO (Ptr PedersenKey)
foreign import ccall unsafe "pedersen_key_gen" generatePedersenKeyPtr :: CSize -> IO (Ptr PedersenKey)

foreign import ccall unsafe "&ps_sig_key_free" freePsSigKey :: FunPtr (Ptr PsSigKey -> IO ())
foreign import ccall safe "ps_sig_key_to_bytes" toBytesPsSigKey :: Ptr PsSigKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall safe "ps_sig_key_from_bytes" fromBytesPsSigKey :: Ptr Word8 -> CSize -> IO (Ptr PsSigKey)
foreign import ccall unsafe "ps_sig_key_gen" generatePsSigKeyPtr :: CSize -> IO (Ptr PsSigKey)

foreign import ccall unsafe "&group_element_free" freeGroupElement :: FunPtr (Ptr GroupElement -> IO ())
foreign import ccall unsafe "group_element_to_bytes" toBytesGroupElement :: Ptr GroupElement -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "group_element_from_bytes" fromBytesGroupElement :: Ptr Word8 -> CSize -> IO (Ptr GroupElement)
foreign import ccall unsafe "group_element_from_seed" generateGroupElementFromSeedPtr :: Ptr GlobalContext -> Word64 -> IO (Ptr GroupElement)

foreign import ccall unsafe "&elgamal_pub_key_free" freeElgamalPublicKey :: FunPtr (Ptr ElgamalPublicKey -> IO ())
foreign import ccall unsafe "elgamal_pub_key_to_bytes" toBytesElgamalPublicKey :: Ptr ElgamalPublicKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "elgamal_pub_key_from_bytes" fromBytesElgamalPublicKey :: Ptr Word8 -> CSize -> IO (Ptr ElgamalPublicKey)

foreign import ccall unsafe "&elgamal_sec_key_free" freeElgamalSecretKey :: FunPtr (Ptr ElgamalSecretKey -> IO ())
foreign import ccall unsafe "elgamal_sec_key_to_bytes" toBytesElgamalSecretKey :: Ptr ElgamalSecretKey -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "elgamal_sec_key_from_bytes" fromBytesElgamalSecretKey :: Ptr Word8 -> CSize -> IO (Ptr ElgamalSecretKey)
foreign import ccall unsafe "elgamal_sec_key_gen_seed" generateElgamalSecretKeyFromSeedPtr :: Ptr GlobalContext -> Word64 -> IO (Ptr ElgamalSecretKey)

foreign import ccall unsafe "derive_public_key" deriveElgamalPublicKeyPtr :: Ptr GlobalContext -> Ptr GroupElement -> IO (Ptr ElgamalPublicKey)

foreign import ccall unsafe "&elgamal_cipher_free" freeElgamalCipher :: FunPtr (Ptr ElgamalCipher -> IO ())
foreign import ccall unsafe "elgamal_cipher_to_bytes" toBytesElgamalCipher :: Ptr ElgamalCipher -> Ptr CSize -> IO (Ptr Word8)
foreign import ccall unsafe "elgamal_cipher_from_bytes" fromBytesElgamalCipher :: Ptr Word8 -> CSize -> IO (Ptr ElgamalCipher)
foreign import ccall unsafe "elgamal_cipher_gen" generateElgamalCipherPtr :: IO (Ptr ElgamalCipher)
foreign import ccall unsafe "elgamal_cipher_zero" zeroElgamalCipherPtr :: IO (Ptr ElgamalCipher)

withPedersenKey :: PedersenKey -> (Ptr PedersenKey -> IO b) -> IO b
withPedersenKey (PedersenKey fp) = withForeignPtr fp

withPsSigKey :: PsSigKey -> (Ptr PsSigKey -> IO b) -> IO b
withPsSigKey (PsSigKey fp) = withForeignPtr fp

withGroupElement :: GroupElement -> (Ptr GroupElement -> IO b) -> IO b
withGroupElement (GroupElement fp) = withForeignPtr fp

withElgamalSecretKey :: ElgamalSecretKey -> (Ptr ElgamalSecretKey -> IO b) -> IO b
withElgamalSecretKey (ElgamalSecretKey fp) = withForeignPtr fp

withElgamalCipher :: ElgamalCipher -> (Ptr ElgamalCipher -> IO b) -> IO b
withElgamalCipher (ElgamalCipher fp) = withForeignPtr fp

withElgamalPublicKey :: ElgamalPublicKey -> (Ptr ElgamalPublicKey -> IO b) -> IO b
withElgamalPublicKey (ElgamalPublicKey fp) = withForeignPtr fp

-- |NOTE: This instance is different than the rust one. We add explicit length
-- information up front.
instance Serialize PedersenKey where
    get = do
        v <- getWord32be
        bs <- getByteString (fromIntegral v)
        case fromBytesHelper freePedersenKey fromBytesPedersenKey bs of
            Nothing -> fail "Cannot decode cipher."
            Just x -> return $ PedersenKey x

    put (PedersenKey e) =
        let bs = toBytesHelper toBytesPedersenKey $ e
        in  putByteString (runPut (putWord32be (fromIntegral (BS.length bs))) <> bs)

instance Show PedersenKey where
    show = byteStringToHex . BS.drop 4 . encode

instance AE.ToJSON PedersenKey where
    toJSON v = AE.String (serializeBase16WithLength4 v)

instance AE.FromJSON PedersenKey where
    parseJSON = AE.withText "PedersenKey in base16" deserializeBase16WithLength4

-- |This instance should only be used for testing
instance Eq PedersenKey where
    key == key' = encode key == encode key'

generatePedersenKey :: Int -> IO PedersenKey
generatePedersenKey n = do
    ptr <- generatePedersenKeyPtr (fromIntegral n)
    PedersenKey <$> newForeignPtr freePedersenKey ptr

-- |NOTE: This instance is different than the rust one. We add explicit length
-- information up front.
instance Serialize PsSigKey where
    get = do
        v <- getWord32be
        bs <- getByteString (fromIntegral v)
        case fromBytesHelper freePsSigKey fromBytesPsSigKey bs of
            Nothing -> fail "Cannot decode cipher."
            Just x -> return $ PsSigKey x

    put (PsSigKey e) =
        let bs = toBytesHelper toBytesPsSigKey $ e
        in  putByteString (runPut (putWord32be (fromIntegral (BS.length bs))) <> bs)

instance Show PsSigKey where
    show = byteStringToHex . BS.drop 4 . encode

-- |This instance should only be used for testing
instance Eq PsSigKey where
    key == key' = encode key == encode key'

instance AE.ToJSON PsSigKey where
    toJSON v = AE.String (serializeBase16WithLength4 v)

instance AE.FromJSON PsSigKey where
    parseJSON = AE.withText "PsSigKey in base16" deserializeBase16WithLength4

generatePsSigKey :: Int -> IO PsSigKey
generatePsSigKey n = do
    ptr <- generatePsSigKeyPtr (fromIntegral n)
    PsSigKey <$> newForeignPtr freePsSigKey ptr

elgamalGroupLen :: Int
elgamalGroupLen = 48

scalarLen :: Int
scalarLen = 32

instance Serialize GroupElement where
    get = do
        bs <- getByteString elgamalGroupLen
        case fromBytesHelper freeGroupElement fromBytesGroupElement bs of
            Nothing -> fail "Cannot decode second component of the elgamal public key."
            Just x -> return $ GroupElement x

    put (GroupElement e) =
        let bs = toBytesHelper toBytesGroupElement $ e
        in  putByteString bs

instance Show GroupElement where
    show = byteStringToHex . encode

-- |This instance should only be used for testing
instance Eq GroupElement where
    key == key' = encode key == encode key'

instance AE.ToJSON GroupElement where
    toJSON v = AE.String (serializeBase16 v)

instance AE.FromJSON GroupElement where
    parseJSON = AE.withText "Group element in base16" deserializeBase16

instance Serialize ElgamalPublicKey where
    get = do
        bs <- getByteString (2 * elgamalGroupLen)
        case fromBytesHelper freeElgamalPublicKey fromBytesElgamalPublicKey bs of
            Nothing -> fail "Cannot decode cipher."
            Just x -> return $ ElgamalPublicKey x

    put (ElgamalPublicKey e) =
        let bs = toBytesHelper toBytesElgamalPublicKey e
        in  putByteString bs

instance Show ElgamalPublicKey where
    show = byteStringToHex . encode

-- |This instance should only be used for testing
instance Eq ElgamalPublicKey where
    key == key' = encode key == encode key'

instance AE.ToJSON ElgamalPublicKey where
    toJSON v = AE.String (serializeBase16 v)

instance AE.FromJSON ElgamalPublicKey where
    parseJSON = AE.withText "Elgamal public key in base16" deserializeBase16

instance Serialize ElgamalSecretKey where
    get = do
        bs <- getByteString (scalarLen + elgamalGroupLen)
        case fromBytesHelper freeElgamalSecretKey fromBytesElgamalSecretKey bs of
            Nothing -> fail "Cannot decode cipher."
            Just x -> return $ ElgamalSecretKey x

    put (ElgamalSecretKey e) =
        let bs = toBytesHelper toBytesElgamalSecretKey e
        in  putByteString bs

instance Show ElgamalSecretKey where
    show = byteStringToHex . encode

-- |NB: This instance should only be used for testing.
instance Eq ElgamalSecretKey where
    key == key' = encode key == encode key'

instance AE.ToJSON ElgamalSecretKey where
    toJSON v = AE.String (serializeBase16 v)

instance AE.FromJSON ElgamalSecretKey where
    parseJSON = AE.withText "Elgamal secret key in base16" deserializeBase16

{-# WARNING generateGroupElementFromSeed "Not cryptographically secure, do not use in production." #-}
generateGroupElementFromSeed :: GlobalContext -> Word64 -> GroupElement
generateGroupElementFromSeed gc seed = GroupElement . unsafePerformIO $
    withGlobalContext gc $ \gcPtr ->
        newForeignPtr freeGroupElement =<< generateGroupElementFromSeedPtr gcPtr seed

deriveElgamalPublicKey :: GlobalContext -> GroupElement -> ElgamalPublicKey
deriveElgamalPublicKey gc ge = unsafePerformIO $
    withGlobalContext gc $ \gcPtr ->
        withGroupElement ge $ \gePtr -> do
            ptr <- deriveElgamalPublicKeyPtr gcPtr gePtr
            ElgamalPublicKey <$> newForeignPtr freeElgamalPublicKey ptr

{-# WARNING generateElgamalSecretKeyFromSeed "Not cryptographically secure, do not use in production." #-}
generateElgamalSecretKeyFromSeed :: GlobalContext -> Word64 -> ElgamalSecretKey
generateElgamalSecretKeyFromSeed gc seed = unsafePerformIO $
    withGlobalContext gc $ \gcPtr -> do
        ptr <- generateElgamalSecretKeyFromSeedPtr gcPtr seed
        ElgamalSecretKey <$> newForeignPtr freeElgamalSecretKey ptr

-- * Elgamal cipher related definitions.

instance Serialize ElgamalCipher where
    get = do
        bs <- getByteString (2 * elgamalGroupLen)
        case fromBytesHelper freeElgamalCipher fromBytesElgamalCipher bs of
            Nothing -> fail "Cannot decode cipher."
            Just x -> return $ ElgamalCipher x

    put (ElgamalCipher e) =
        let bs = toBytesHelper toBytesElgamalCipher e
        in  putByteString bs

instance Show ElgamalCipher where
    show = byteStringToHex . encode

-- |This instance should only be used for testing
instance Eq ElgamalCipher where
    key == key' = encode key == encode key'

instance AE.ToJSON ElgamalCipher where
    toJSON v = AE.String (serializeBase16 v)

instance AE.FromJSON ElgamalCipher where
    parseJSON = AE.withText "Elgamal cipher in base16" deserializeBase16

generateElgamalCipher :: IO ElgamalCipher
generateElgamalCipher = do
    ptr <- generateElgamalCipherPtr
    unsafeMakeCipher ptr

-- |Encryption of 0 in the exponent, with randomness 0.
zeroElgamalCipher :: ElgamalCipher
zeroElgamalCipher = unsafePerformIO $ do
    ptr <- zeroElgamalCipherPtr
    unsafeMakeCipher ptr

-- |Construct an Elgamal cipher from a pointer to it.
-- This is unsafe in two different ways
--
-- - if the pointer is Null or does not point to an `ElgamalCipher` structure the behaviour is undefined.
-- - if this function is called twice on the same value it will lead to a double free.
unsafeMakeCipher :: Ptr ElgamalCipher -> IO ElgamalCipher
unsafeMakeCipher ptr = ElgamalCipher <$> newForeignPtr freeElgamalCipher ptr
