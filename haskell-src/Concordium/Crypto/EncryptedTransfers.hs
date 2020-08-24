{-| This module provides the necessary primitives for encrypted amount transfers. -}
{-# LANGUAGE DerivingStrategies, DerivingVia, StandaloneDeriving #-}
module Concordium.Crypto.EncryptedTransfers where

import Data.Serialize
import Data.Word
import Data.Aeson
import Data.ByteString.Short
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BS
import Foreign.Ptr
import Foreign.Marshal (alloca)
import Foreign.Storable (peek)
import Foreign.C.Types
import System.IO.Unsafe (unsafeDupablePerformIO)
import Data.Foldable(foldl')

import Concordium.Crypto.FFIDataTypes
import Concordium.Crypto.ByteStringHelpers
import Concordium.ID.Parameters
import Concordium.ID.Types

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
     -> Ptr ElgamalSecond -- ^ Public key of the receiver.
     -> Ptr ElgamalSecond -- ^ Public key of the sender.
     -> Ptr ElgamalCipher -- ^ High chunk of the current balance.
     -> Ptr ElgamalCipher -- ^ Low chunk of the current balance.
     -> Ptr Word8 -- ^ Pointer to the transfer data bytes.
     -> CSize  -- ^ Length of the transfer data bytes.
     -> IO Word8 -- ^ Return either 0 if proof checking failed, or non-zero in case of success.

foreign import ccall unsafe "verify_sec_to_pub_transfer"
  verify_sec_to_pub_transfer ::
       Ptr GlobalContext -- ^Pointer to the global context needed to validate the proof.
     -> Ptr ElgamalSecond -- ^ Public key of the sender.
     -> Ptr ElgamalCipher -- ^ High chunk of the current balance.
     -> Ptr ElgamalCipher -- ^ Low chunk of the current balance.
     -> Ptr Word8 -- ^ Pointer to the transfer data bytes.
     -> CSize  -- ^ Length of the transfer data bytes.
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

newtype EncryptedAmountTransferProof = EncryptedAmountTransferProof { theEncryptedTransferProof :: ShortByteString }
    deriving(Eq, Show, FromJSON, ToJSON) via ByteStringHex

-- | Custom serialization functions for proofs which allow us to have the same
-- serialization as in rust, provided enough context, i.e., length.
getEncryptedAmountTransferProof :: Word32 -> Get EncryptedAmountTransferProof
getEncryptedAmountTransferProof len = EncryptedAmountTransferProof <$> getShortByteString (fromIntegral len)

-- |Put the proof directly without the length.
-- The proof can be deserialized in the right contexts using 'getEncryptedAmountTransferProof'
putEncryptedAmountTransferProof :: EncryptedAmountTransferProof -> Put
putEncryptedAmountTransferProof = putShortByteString . theEncryptedTransferProof

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

newtype TransferToPublicProof = TransferToPublicProof { theTransferToPublicProof :: ShortByteString }
  deriving (Eq, Show, FromJSON, ToJSON) via ByteStringHex
  deriving Serialize via Short65K

-- | Custom serialization functions for proofs which allow us to have the same
-- serialization as in rust, provided enough context, i.e., length.
getTrasnferToPublicProof :: Word32 -> Get TransferToPublicProof
getTrasnferToPublicProof len = TransferToPublicProof <$> getShortByteString (fromIntegral len)

-- |Put the proof directly without the length.
-- The proof can be deserialized in the right contexts using 'getEncryptedAmountTransferProof'
putTransferToPublicProof :: TransferToPublicProof -> Put
putTransferToPublicProof = putShortByteString . theTransferToPublicProof

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

instance Semigroup EncryptedAmount where
  (<>) = aggregateAmounts

instance Monoid EncryptedAmount where
  mempty = EncryptedAmount zeroElgamalCipher zeroElgamalCipher
  -- mconcat is redefined for efficiency reasons. The default implemenation uses
  -- foldr, which is bad in this case since `aggregateAmounts` is strict in the
  -- second argument.
  mconcat [] = mempty
  mconcat (x:xs) = foldl' aggregateAmounts x xs

dummy_encrypt_amount ::
  Ptr GlobalContext -- ^Global context
  -> Word64 -- ^Amount to be encrypted
  -> Ptr (Ptr ElgamalCipher) -- ^Place to write the pointer to the high chunk of the result.
  -> Ptr (Ptr ElgamalCipher) -- ^Place to write the pointer to the low chunk of the result.
  -> IO ()
dummy_encrypt_amount = undefined

encryptAmount :: GlobalContext -> Word64 -> EncryptedAmount
encryptAmount gc amount = unsafeDupablePerformIO $
  withGlobalContext gc $ \gcPtr ->
  alloca $ \outHighPtr ->
  alloca $ \outLowPtr -> do
      dummy_encrypt_amount gcPtr amount outHighPtr outLowPtr
      outHigh <- unsafeMakeCipher =<< peek outHighPtr
      outLow <- unsafeMakeCipher =<< peek outLowPtr
      return EncryptedAmount{encryptionHigh = outHigh, encryptionLow = outLow}

type EncryptedAmountTransferBytes = BS.ByteString

-- |Prepare encrypted amount transfer bytes to send through FFI. This implements
-- the right serialization to match that defined in Rust for the
-- @EncryptedAmountTransferData@.
prepareEncryptedAmountTransferBytes ::
  -- |Remaining amount on the account
  EncryptedAmount ->
  -- |Amount to transfer
  EncryptedAmount ->
  -- |Index of the encrypted amounts used as input.
  EncryptedAmountAggIndex ->
  -- |Proof of validity of transaction.
  EncryptedAmountTransferProof ->
  -- |Serialized data
  EncryptedAmountTransferBytes
prepareEncryptedAmountTransferBytes remainingAmount transferAmount idx proof = runPut putter
  where putter =
          put remainingAmount <>
          put transferAmount <>
          put idx <>
          putEncryptedAmountTransferProof proof

verifyEncryptedTransferProof ::
  -- |Global context with parameters
  GlobalContext ->
  -- |Public key of the receiver.
  AccountEncryptionKey ->
  -- |Public key of the sender.
  AccountEncryptionKey ->
  -- |Aggregated encrypted amount on the sender's account that was used.
  EncryptedAmount ->
  -- |Proof of validity of the transfer.
  EncryptedAmountTransferBytes ->
  Bool
verifyEncryptedTransferProof gc receiverPK senderPK initialAmount transferData = unsafeDupablePerformIO $ do
  withGlobalContext gc $ \gcPtr ->
    withElgamalSecond receiverPK' $ \receiverPKPtr ->
      withElgamalSecond senderPK' $ \senderPKPtr ->
        withElgamalCipher (encryptionHigh initialAmount) $ \initialHighPtr ->
          withElgamalCipher (encryptionLow initialAmount) $ \initialLowPtr ->
            -- this is safe since the called function handles the 0 length case correctly.
            BS.unsafeUseAsCStringLen transferData $ \(bytesPtr, len) -> do
               res <- verify_encrypted_transfer
                       gcPtr
                       receiverPKPtr
                       senderPKPtr
                       initialHighPtr
                       initialLowPtr
                       (castPtr bytesPtr)
                       (fromIntegral len)
               return (res /= 0)
  where AccountEncryptionKey (RegIdCred receiverPK') = receiverPK
        AccountEncryptionKey (RegIdCred senderPK') = senderPK

type TransferToPublicBytes = BS.ByteString

-- |Prepare encrypted amount transfer bytes to send through FFI. This implements
-- the right serialization to match that defined in Rust for the
-- @EncryptedAmountTransferData@.
prepareTransferToPublicBytes ::
  -- |Remaining amount on the account
  EncryptedAmount ->
  -- |Amount to transfer
  Word64 ->
  -- |Index of the encrypted amounts used as input.
  EncryptedAmountAggIndex ->
  -- |Proof of validity of transaction.
  TransferToPublicProof ->
  -- |Serialized data
  TransferToPublicBytes
prepareTransferToPublicBytes remainingAmount transferAmount idx proof = runPut putter
  where putter =
          put remainingAmount <>
          put transferAmount <>
          put idx <>
          putTransferToPublicProof proof

verifySecretToPublicTransferProof ::
  -- |Global context with parameters
  GlobalContext ->
  -- |Public key of the sender.
  AccountEncryptionKey ->
  -- |Aggregated encrypted amount on the sender's account that was used.
  EncryptedAmount ->
  -- |Proof of validity of the transfer.
  TransferToPublicBytes ->
  Bool
verifySecretToPublicTransferProof gc senderPK initialAmount transferData = unsafeDupablePerformIO $ do
  withGlobalContext gc $ \gcPtr ->
    withElgamalSecond senderPK' $ \senderPKPtr ->
      withElgamalCipher (encryptionHigh initialAmount) $ \initialHighPtr ->
        withElgamalCipher (encryptionLow initialAmount) $ \initialLowPtr ->
          -- this is safe since the called function handles the 0 length case correctly.
          BS.unsafeUseAsCStringLen transferData $ \(bytesPtr, len) -> do
             res <- verify_sec_to_pub_transfer
                     gcPtr
                     senderPKPtr
                     initialHighPtr
                     initialLowPtr
                     (castPtr bytesPtr)
                     (fromIntegral len)
             return (res /= 0)
  where AccountEncryptionKey (RegIdCred senderPK') = senderPK
