-- | Dummy values generated for the tests
module Concordium.Crypto.DummyData (
    -- * BlockSignature
    randomBlockKeyPair,
    genBlockKeyPair,

    -- * BlsSignature
    randomBlsSecretKey,
    secretBlsKeyGen,
    generateBlsSecretKeyFromSeed,

    -- * Ed25519
    randomEd25519KeyPair,
    genEd25519KeyPair,

    -- * SigScheme
    genSigSchemeKeyPair,

    -- * Standard keys
    mateuszKP,
    alesKP,
    alesVK,
    thomasKP,
    thomasVK,
    accountVFKeyFrom,
) where

import Concordium.Crypto.BlockSignature as Block
import Concordium.Crypto.BlsSignature as Bls
import Concordium.Crypto.Ed25519Signature as Ed25519
import Concordium.Crypto.SignatureScheme as SigScheme
import qualified Data.ByteString as BS
import Data.Serialize
import Foreign.C.Types
import Foreign.ForeignPtr
import Foreign.Ptr
import System.IO.Unsafe
import System.Random
import Test.QuickCheck

{-# WARNING randomBlockKeyPair "Not cryptographically secure. DO NOT USE IN PRODUCTION." #-}
randomBlockKeyPair :: RandomGen g => g -> (Block.KeyPair, g)
randomBlockKeyPair g =
    let ((signKey, verifyKey), g') = randomEd25519KeyPair g
    in  (KeyPair{..}, g')

{-# WARNING genBlockKeyPair "Not cryptographically secure. DO NOT USE IN PRODUCTION." #-}
genBlockKeyPair :: Gen Block.KeyPair
genBlockKeyPair = uncurry Block.KeyPair <$> genEd25519KeyPair

-- | Provides deterministic key generation from seed.
foreign import ccall unsafe "bls_generate_secretkey_from_seed" generateSecretKeyPtrFromSeed :: CSize -> IO (Ptr Bls.SecretKey)

-- | Provides deterministic key generation for testing purposes.
{-# WARNING randomBlsSecretKey "Not cryptographically secure. DO NOT USE IN PRODUCTION." #-}
randomBlsSecretKey :: (RandomGen g) => g -> (Bls.SecretKey, g)
randomBlsSecretKey gen = (sk, gen')
  where
    (nextSeed, gen') = random gen
    sk = generateBlsSecretKeyFromSeed $ (fromIntegral :: Int -> CSize) nextSeed

-- | Provides deterministic key generation for testing purposes.
{-# WARNING secretBlsKeyGen "Not cryptographically secure. DO NOT USE IN PRODUCTION." #-}
secretBlsKeyGen :: Gen Bls.SecretKey
secretBlsKeyGen = resize (2 ^ (30 :: Int)) $ fst . randomBlsSecretKey . mkStdGen <$> arbitrary

-- | Provides deterministic key generation for testing purposes.
{-# WARNING generateBlsSecretKeyFromSeed "Not cryptographically secure. DO NOT USE IN PRODUCTION." #-}
generateBlsSecretKeyFromSeed :: CSize -> Bls.SecretKey
generateBlsSecretKeyFromSeed seed = unsafePerformIO $ do
    ptr <- generateSecretKeyPtrFromSeed seed
    Bls.SecretKey <$> newForeignPtr freeSecretKey ptr

{-# WARNING randomEd25519KeyPair "Not cryptographically secure, DO NOT USE IN PRODUCTION." #-}
randomEd25519KeyPair :: RandomGen g => g -> ((Ed25519.SignKey, Ed25519.VerifyKey), g)
randomEd25519KeyPair gen = ((signKey, deriveVerifyKey signKey), gen')
  where
    (gen0, gen') = split gen
    privKeyBytes = BS.pack $ take signKeySize $ randoms gen0
    signKey =
        case decode privKeyBytes of
            Left _ -> error "Any sequence of bytes is a valid private key in this scheme."
            Right sk -> sk

{-# WARNING genEd25519KeyPair "Not cryptographically secure, DO NOT USE IN PRODUCTION." #-}
genEd25519KeyPair :: Gen (Ed25519.SignKey, Ed25519.VerifyKey)
genEd25519KeyPair = do
    privKeyBytes <- BS.pack <$> vector signKeySize
    let signKey = case decode privKeyBytes of
            Left _ -> error "Any sequence of bytes is a valid private key in this scheme."
            Right sk -> sk
    return (signKey, deriveVerifyKey signKey)

{-# WARNING genSigSchemeKeyPair "Not cryptographically secure, DO NOT USE IN PRODUCTION." #-}
genSigSchemeKeyPair :: Gen SigScheme.KeyPair
genSigSchemeKeyPair = uncurry SigScheme.KeyPairEd25519 <$> genEd25519KeyPair

{-# WARNING mateuszKP "Do not use in production." #-}
mateuszKP :: SigScheme.KeyPair
mateuszKP = uncurry SigScheme.KeyPairEd25519 . fst $ randomEd25519KeyPair (mkStdGen 0)

{-# WARNING alesKP "Do not use in production." #-}
alesKP :: SigScheme.KeyPair
alesKP = uncurry SigScheme.KeyPairEd25519 . fst $ randomEd25519KeyPair (mkStdGen 1)

{-# WARNING alesVK "Do not use in production." #-}
alesVK :: SigScheme.VerifyKey
alesVK = correspondingVerifyKey alesKP

{-# WARNING thomasKP "Do not use in production." #-}
thomasKP :: SigScheme.KeyPair
thomasKP = uncurry SigScheme.KeyPairEd25519 . fst $ randomEd25519KeyPair (mkStdGen 2)

{-# WARNING thomasVK "Do not use in production." #-}
thomasVK :: SigScheme.VerifyKey
thomasVK = correspondingVerifyKey thomasKP

{-# WARNING accountVFKeyFrom "Do not use in production." #-}
accountVFKeyFrom :: Int -> SigScheme.VerifyKey
accountVFKeyFrom = correspondingVerifyKey . uncurry SigScheme.KeyPairEd25519 . fst . randomEd25519KeyPair . mkStdGen
