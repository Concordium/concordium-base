{-| This module provides the necessary primitives for encrypted amount transfers. -}
{-# LANGUAGE DerivingStrategies, DerivingVia, StandaloneDeriving #-}
module Concordium.Crypto.EncryptedTransfers where 

import Data.Serialize
import Data.Word
import Data.Aeson
import Data.ByteString.Short
import Foreign.Ptr
import Foreign.Marshal (alloca)
import Foreign.Storable (peek)
import Foreign.C.Types
import System.IO.Unsafe (unsafeDupablePerformIO)

import Concordium.Crypto.FFIDataTypes
import Concordium.Crypto.ByteStringHelpers
import Concordium.ID.Parameters

-- | Aggregate two encrypted amounts together.
foreign import ccall unsafe "aggregate_encrypted_amounts"
  aggregate_encrypted_amounts ::
     Ptr ElgamalCipher -- ^ High chunk of the first amount.
     -> Ptr ElgamalCipher -- ^ Low chunk of the first amount.
     -> Ptr ElgamalCipher -- ^ High chunk of the second amount.
     -> Ptr ElgamalCipher -- ^ Low chunk of the second amount.
     -> Ptr (Ptr ElgamalCipher) -- ^Place to write the pointer to the high chunk of the result.
     -> Ptr (Ptr ElgamalCipher) -- ^Place to write the pointer to the low chunk of the result.
     -> IO ()


-- | Verify an encrypted transfer proof.
foreign import ccall unsafe "verify_encrypted_transfer"
  verify_encrypted_transfer ::
       Ptr GlobalContext -- ^Pointer to the global context needed to validate the proof.
     -> Ptr ElgamalCipher -- ^ High chunk of the current balance.
     -> Ptr ElgamalCipher -- ^ Low chunk of the current balance.
     -> Ptr ElgamalCipher -- ^ High chunk of the remaining balance.
     -> Ptr ElgamalCipher -- ^ Low chunk of the remaining balance.
     -> Ptr ElgamalCipher -- ^ High chunk of the transfer amount.
     -> Ptr ElgamalCipher -- ^ Low chunk of the transfer amount.
     -> CSize  -- ^ Length of the proof bytes.
     -> Ptr Word8 -- ^ Pointer to the proof bytes.
     -> IO Word8 -- ^ Return either 0 if proof checking failed, or non-zero in case of success.

data EncryptedAmount = EncryptedAmount{
  -- | Encryption of the high-chunk (highest 32 bits).
  encryptionHigh :: ElgamalCipher,
  -- | Encryption of the high-chunk (lowest 32 bits).
  encryptionLow :: ElgamalCipher
  }
  deriving (Show, FromJSON, ToJSON) via Base16JSONSerialize EncryptedAmount
  deriving(Eq)

instance Serialize EncryptedAmount where
  put EncryptedAmount{..} = put encryptionHigh <> put encryptionLow
  get = do
    encryptionHigh <- get
    encryptionLow <- get
    return EncryptedAmount{..}

-- |An indexed used to determine which encryped amounts were used in a transaction.
newtype EncryptedAmountAggIndex = EncryptedAmountAggIndex {theAggIndex :: Word64}
    deriving newtype (Eq, Show, Ord, FromJSON, ToJSON, Num, Integral, Real, Enum)

instance Serialize EncryptedAmountAggIndex where
  put (EncryptedAmountAggIndex i) = putWord64be i
  get = EncryptedAmountAggIndex <$> getWord64be

-- |An individual index of an encrypted amount. This is used when assigning
-- indices for encrypted amounts added to an account.
newtype EncryptedAmountIndex = EncryptedAmountIndex {theIndex :: Word64}
    deriving newtype (Eq, Show, Ord, FromJSON, ToJSON, Num, Integral, Real, Enum)

instance Serialize EncryptedAmountIndex where
  put (EncryptedAmountIndex i) = putWord64be i
  get = EncryptedAmountIndex <$> getWord64be

-- |Add an offset to an encrypted amount aggregation index to obtain a new encrypted amount index.
-- It is assume that this will not overflow. The function is still safe in case of overflow,
-- but it will wrap around.
addToAggIndex :: EncryptedAmountAggIndex -> Word -> EncryptedAmountIndex
addToAggIndex (EncryptedAmountAggIndex aggIdx) len = EncryptedAmountIndex (aggIdx + fromIntegral len)

-- FIXME: Serialization here is probably wrong, and needs to be fixed once the proof
-- is known.
newtype EncryptedAmountTransferProof = EncryptedAmountTransferProof { theEncryptedTransferProof :: ShortByteString }
    deriving(Eq, Show, FromJSON, ToJSON) via ByteStringHex
    deriving Serialize via Short65K

-- FIXME: Serialization here is probably wrong, and needs to be fixed once the proof
-- is known.
newtype EncryptAmountProof = EncryptAmountProof { theEncryptProof :: ShortByteString }
    deriving(Eq, Show, FromJSON, ToJSON) via ByteStringHex
    deriving Serialize via Short65K

-- FIXME: Serialization here is probably wrong, and needs to be fixed once the proof
-- is known.
newtype DecryptAmountProof = DecryptAmountProof ShortByteString
    deriving(Eq, Show, FromJSON, ToJSON) via ByteStringHex
    deriving Serialize via Short65K

-- * Functions for verifying proofs, and aggregating amounts, used from the scheduler.

-- |Aggregate two encrypted amounts together. This operation is strict and
-- associative.
aggregateAmounts :: EncryptedAmount -> EncryptedAmount -> EncryptedAmount
aggregateAmounts left right = unsafeDupablePerformIO $ do
  withElgamalCipher (encryptionHigh left) $ \leftHighPtr ->
    withElgamalCipher (encryptionLow left) $ \leftLowPtr ->
      withElgamalCipher (encryptionHigh right) $ \rightHighPtr ->
        withElgamalCipher (encryptionLow right) $ \rightLowPtr ->
          alloca $ \outHighPtr ->
            alloca $ \outLowPtr -> do
              aggregate_encrypted_amounts leftHighPtr leftLowPtr rightHighPtr rightLowPtr outHighPtr outLowPtr
              outHigh <- unsafeMakeCipher =<< peek outHighPtr
              outLow <- unsafeMakeCipher =<< peek outLowPtr
              return EncryptedAmount{encryptionHigh = outHigh, encryptionLow = outLow}

verifyEncryptedTransferProof ::
  -- |Global context with parameters
  GlobalContext ->
  -- |Aggregated encrypted amount on the sender's account that was used.
  EncryptedAmount ->
  -- |Remaining amount on the sender's account after the transfer.
  EncryptedAmount ->
  -- |Amount to transfer
  EncryptedAmount ->
  -- |Proof of validity of the transfer.
  EncryptedAmountTransferProof ->
  Bool
verifyEncryptedTransferProof gc initialAmount remainingAmount transferAmount proof = unsafeDupablePerformIO $ do
  withGlobalContext gc $ \gcPtr ->
    withElgamalCipher (encryptionHigh initialAmount) $ \initialHighPtr ->
      withElgamalCipher (encryptionLow initialAmount) $ \initialLowPtr ->
        withElgamalCipher (encryptionHigh remainingAmount) $ \remainingHighPtr ->
          withElgamalCipher (encryptionLow remainingAmount) $ \remainingLowPtr ->
            withElgamalCipher (encryptionHigh transferAmount) $ \transferHighPtr ->
              withElgamalCipher (encryptionLow transferAmount) $ \transferLowPtr ->
                -- this is safe since the called function handles the 0 length case correctly.
                useAsCStringLen (theEncryptedTransferProof proof) $ \(bytesPtr, len) -> do
                  res <- verify_encrypted_transfer
                          gcPtr
                          initialHighPtr
                          initialLowPtr
                          remainingHighPtr
                          remainingLowPtr
                          transferHighPtr
                          transferLowPtr
                          (fromIntegral len)
                          (castPtr bytesPtr)
                  return (res /= 0)
