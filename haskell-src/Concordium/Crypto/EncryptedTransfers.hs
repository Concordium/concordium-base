{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}

-- | This module provides the necessary primitives for encrypted amount transfers.
module Concordium.Crypto.EncryptedTransfers (
    -- * Encrypted amount
    EncryptedAmount (..),
    aggregateAmounts,
    isZeroEncryptedAmount,

    -- * Encrypted indices
    EncryptedAmountAggIndex (..),
    EncryptedAmountIndex (..),
    addToAggIndex,

    -- * Aggregated decrypted amount
    AggregatedDecryptedAmount,
    makeAggregatedDecryptedAmount,
    withAggregatedDecryptedAmount,

    -- * Public to secret transfer
    encryptAmountZeroRandomness,

    -- * Encrypted transfer
    EncryptedAmountTransferData (..),
    EncryptedAmountTransferProof,
    getEncryptedAmountTransferProof,
    putEncryptedAmountTransferProof,
    makeEncryptedAmountTransferData,
    verifyEncryptedTransferProof,

    -- * Secret to public transfer
    SecToPubAmountTransferData (..),
    SecToPubAmountTransferProof,
    getSecToPubAmountTransferProof,
    putSecToPubAmountTransferProof,
    makeSecToPubAmountTransferData,
    verifySecretToPublicTransferProof,

    -- * Decryption of encrypted amounts.
    computeTable,
    decryptAmount,
    encryptAmount,
) where

import Data.Aeson
import Data.ByteString.Short
import Data.Foldable (foldl')
import Data.Serialize
import Data.Word
import Foreign (ForeignPtr, Storable, newForeignPtr, peek, withForeignPtr)
import Foreign.C (CStringLen)
import Foreign.C.Types (CChar)
import Foreign.Marshal (alloca)
import Foreign.Ptr
import System.IO.Unsafe

import Concordium.Common.Amount
import Concordium.Crypto.ByteStringHelpers
import Concordium.Crypto.FFIDataTypes
import Concordium.Crypto.FFIHelpers
import Concordium.ID.Parameters
import Concordium.ID.Types

-- Note: The FFI functions imported in this file are defined in encrypted_transfers/src/ffi.rs

--------------------------------------------------------------------------------
------------------------------- EncryptedAmount --------------------------------
--------------------------------------------------------------------------------

-- | See `EncryptedAmounts` in encrypted_transfers/src/types.rs
data EncryptedAmount = EncryptedAmount
    { -- | Encryption of the high-chunk (highest 32 bits).
      encryptionHigh :: ElgamalCipher,
      -- | Encryption of the low-chunk (lowest 32 bits).
      encryptionLow :: ElgamalCipher
    }
    deriving (Show, FromJSON, ToJSON) via Base16JSONSerialize EncryptedAmount
    deriving (Eq)

instance Serialize EncryptedAmount where
    put EncryptedAmount{..} = put encryptionLow <> put encryptionHigh
    get = do
        encryptionLow <- get
        encryptionHigh <- get
        return EncryptedAmount{..}

instance Semigroup EncryptedAmount where
    (<>) = aggregateAmounts

instance Monoid EncryptedAmount where
    mempty = EncryptedAmount zeroElgamalCipher zeroElgamalCipher

    -- mconcat is redefined for efficiency reasons. The default implemenation uses
    -- foldr, which is bad in this case since `aggregateAmounts` is strict in the
    -- second argument.
    mconcat [] = mempty
    mconcat (x : xs) = foldl' aggregateAmounts x xs

foreign import ccall unsafe "is_zero_encrypted_amount"
    is_zero_encrypted_amount ::
        -- | High chunk of the first amount.
        Ptr ElgamalCipher ->
        -- | Low chunk of the first amount.
        Ptr ElgamalCipher ->
        IO Word8

-- | Aggregate two encrypted amounts together.
foreign import ccall unsafe "aggregate_encrypted_amounts"
    aggregate_encrypted_amounts ::
        -- | High chunk of the first amount.
        Ptr ElgamalCipher ->
        -- | Low chunk of the first amount.
        Ptr ElgamalCipher ->
        -- | High chunk of the second amount.
        Ptr ElgamalCipher ->
        -- | Low chunk of the second amount.
        Ptr ElgamalCipher ->
        -- | Place to write the pointer to the high chunk of the result.
        Ptr (Ptr ElgamalCipher) ->
        -- | Place to write the pointer to the low chunk of the result.
        Ptr (Ptr ElgamalCipher) ->
        IO ()

-- |Check whether the encrypted amount is an encryption of 0 with randomness 0.
isZeroEncryptedAmount :: EncryptedAmount -> Bool
isZeroEncryptedAmount EncryptedAmount{..} = unsafeDupablePerformIO $
    withElgamalCipher encryptionHigh $ \highPtr ->
        withElgamalCipher encryptionLow $ \lowPtr -> do
            res <- is_zero_encrypted_amount highPtr lowPtr
            return (res == 1)

-- |Aggregate two encrypted amounts together. This operation is strict and
-- associative.
aggregateAmounts :: EncryptedAmount -> EncryptedAmount -> EncryptedAmount
aggregateAmounts left right = unsafePerformIO $ do
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

--------------------------------------------------------------------------------
-------------------------- Encrypted aggregated index --------------------------
--------------------------------------------------------------------------------

-- |An index used to determine which encrypted amounts were used in a transaction.
newtype EncryptedAmountAggIndex = EncryptedAmountAggIndex {theAggIndex :: Word64}
    deriving newtype (Eq, Show, Ord, FromJSON, ToJSON, Num, Integral, Real, Enum, Storable, Serialize)

--------------------------------------------------------------------------------
---------------------------- Encrypted amount index ----------------------------
--------------------------------------------------------------------------------

-- |An individual index of an encrypted amount. This is used when assigning
-- indices for encrypted amounts added to an account.
newtype EncryptedAmountIndex = EncryptedAmountIndex {theIndex :: Word64}
    deriving newtype (Eq, Show, Ord, FromJSON, ToJSON, Num, Integral, Real, Enum, Serialize)

-- |Add an offset to an encrypted amount aggregation index to obtain a new encrypted amount index.
-- It is assume that this will not overflow. The function is still safe in case of overflow,
-- but it will wrap around.
addToAggIndex :: EncryptedAmountAggIndex -> Word -> EncryptedAmountIndex
addToAggIndex (EncryptedAmountAggIndex aggIdx) len = EncryptedAmountIndex (aggIdx + fromIntegral len)

--------------------------------------------------------------------------------
------------------------- Aggregated Encrypted Amount --------------------------
--------------------------------------------------------------------------------

foreign import ccall unsafe "make_aggregated_decrypted_amount"
    make_aggregated_decrypted_amount ::
        -- | High chunk of the encrypted amount
        Ptr ElgamalCipher ->
        -- | Low chunk of the encrypted amount
        Ptr ElgamalCipher ->
        -- | Amount in plaintext
        Word64 ->
        -- | Index up to which amounts have been aggregated
        EncryptedAmountAggIndex ->
        IO (Ptr AggregatedDecryptedAmount)

foreign import ccall unsafe "&free_aggregated_decrypted_amount"
    free_aggregated_decrypted_amount ::
        FunPtr (Ptr AggregatedDecryptedAmount -> IO ())

newtype AggregatedDecryptedAmount = AggregatedDecryptedAmount (ForeignPtr AggregatedDecryptedAmount)
withAggregatedDecryptedAmount :: AggregatedDecryptedAmount -> (Ptr AggregatedDecryptedAmount -> IO b) -> IO b
withAggregatedDecryptedAmount (AggregatedDecryptedAmount ptr) = withForeignPtr ptr

makeAggregatedDecryptedAmount :: EncryptedAmount -> Amount -> EncryptedAmountAggIndex -> AggregatedDecryptedAmount
makeAggregatedDecryptedAmount encAmount (Amount amount) idx = unsafePerformIO $
    withElgamalCipher (encryptionHigh encAmount) $ \enc_hi ->
        withElgamalCipher (encryptionLow encAmount) $ \enc_lo ->
            AggregatedDecryptedAmount <$> (newForeignPtr free_aggregated_decrypted_amount =<< make_aggregated_decrypted_amount enc_hi enc_lo amount idx)

--------------------------------------------------------------------------------
-------------------------- Public to secret transfer ---------------------------
--------------------------------------------------------------------------------

foreign import ccall unsafe "encrypt_amount_with_zero_randomness"
    encrypt_amount_with_zero_randomness ::
        -- | Global context
        Ptr GlobalContext ->
        -- | Amount to be encrypted
        Word64 ->
        -- | Place to write the pointer to the high chunk of the result.
        Ptr (Ptr ElgamalCipher) ->
        -- | Place to write the pointer to the low chunk of the result.
        Ptr (Ptr ElgamalCipher) ->
        IO ()

-- | Encrypt the given amount with zero randomness. To be used in transfer to secret
encryptAmountZeroRandomness :: GlobalContext -> Amount -> EncryptedAmount
encryptAmountZeroRandomness gc (Amount amount) = unsafePerformIO $
    withGlobalContext gc $ \gcPtr ->
        alloca $ \outHighPtr ->
            alloca $ \outLowPtr -> do
                encrypt_amount_with_zero_randomness gcPtr amount outHighPtr outLowPtr
                outHigh <- unsafeMakeCipher =<< peek outHighPtr
                outLow <- unsafeMakeCipher =<< peek outLowPtr
                return EncryptedAmount{encryptionHigh = outHigh, encryptionLow = outLow}

--------------------------------------------------------------------------------
--------------------------- Encrypted transfer data ----------------------------
--------------------------------------------------------------------------------

foreign import ccall safe "make_encrypted_transfer_data"
    make_encrypted_transfer_data ::
        -- | Pointer to the global context
        Ptr GlobalContext ->
        -- | Public key of the receiver
        Ptr ElgamalPublicKey ->
        -- | Secret key of the sender
        Ptr ElgamalSecretKey ->
        -- | Encrypted amount placed for the transfer
        Ptr AggregatedDecryptedAmount ->
        -- | Amount that want to be transferred
        Word64 ->
        -- | Place to write the high chunk of the remaining amount
        Ptr (Ptr ElgamalCipher) ->
        -- | Place to write the low chunk of the remaining amount
        Ptr (Ptr ElgamalCipher) ->
        -- | Place to write the high chunk of the transfer amount
        Ptr (Ptr ElgamalCipher) ->
        -- | Place to write the low chunk of the transfer amount
        Ptr (Ptr ElgamalCipher) ->
        -- | Place to write the index
        Ptr EncryptedAmountAggIndex ->
        -- | Place to write the length of the proof
        Ptr Word64 ->
        -- | Pointer to the proof
        IO (Ptr CChar)

-- | Serialized version of `EncryptedAmountTransferProof` in encrypted_transfers/src/types.rs
newtype EncryptedAmountTransferProof = EncryptedAmountTransferProof {theEncryptedAmountTransferProof :: ShortByteString}
    deriving (Eq, Show, FromJSON, ToJSON) via ByteStringHex
    deriving (Serialize) via Short65K

withEncryptedAmountTransferProof :: EncryptedAmountTransferProof -> (CStringLen -> IO a) -> IO a
withEncryptedAmountTransferProof (EncryptedAmountTransferProof s) = useAsCStringLen s

makeEncryptedAmountTransferProof :: CStringLen -> IO EncryptedAmountTransferProof
makeEncryptedAmountTransferProof c = do
    res <- EncryptedAmountTransferProof <$> packCStringLen c
    rs_free_array_len (castPtr (fst c)) (fromIntegral (snd c))
    return res

-- | Custom serialization functions for proofs which allow us to have the same
-- serialization as in rust, provided enough context, i.e., length.
getEncryptedAmountTransferProof :: Word32 -> Get EncryptedAmountTransferProof
getEncryptedAmountTransferProof len = EncryptedAmountTransferProof <$> getShortByteString (fromIntegral len)

-- |Put the proof directly without the length.
-- The proof can be deserialized in the right contexts using 'getEncryptedAmountTransferProof'
putEncryptedAmountTransferProof :: EncryptedAmountTransferProof -> Put
putEncryptedAmountTransferProof = putShortByteString . theEncryptedAmountTransferProof

-- | Haskell counterpart of `EncryptedAmountTransferData` in encrypted_transfers/src/types.rs
data EncryptedAmountTransferData = EncryptedAmountTransferData
    { eatdRemainingAmount :: !EncryptedAmount,
      eatdTransferAmount :: !EncryptedAmount,
      eatdIndex :: !EncryptedAmountAggIndex,
      eatdProof :: !EncryptedAmountTransferProof
    }
    deriving (Eq, Show)

instance FromJSON EncryptedAmountTransferData where
    parseJSON = withObject "Encrypted Amount Transfer Data" $ \v -> do
        eatdRemainingAmount <- v .: "remainingAmount"
        eatdTransferAmount <- v .: "transferAmount"
        eatdIndex <- v .: "index"
        eatdProof <- v .: "proof"
        return EncryptedAmountTransferData{..}

withEncryptedAmountTransferData ::
    EncryptedAmountTransferData ->
    (Ptr ElgamalCipher -> Ptr ElgamalCipher -> Ptr ElgamalCipher -> Ptr ElgamalCipher -> EncryptedAmountAggIndex -> Word64 -> Ptr CChar -> IO a) ->
    IO a
withEncryptedAmountTransferData EncryptedAmountTransferData{..} f =
    withElgamalCipher (encryptionHigh eatdRemainingAmount) $ \remaining_high ->
        withElgamalCipher (encryptionLow eatdRemainingAmount) $ \remaining_low ->
            withElgamalCipher (encryptionHigh eatdTransferAmount) $ \transfer_high ->
                withElgamalCipher (encryptionLow eatdTransferAmount) $ \transfer_low ->
                    withEncryptedAmountTransferProof eatdProof $ \(bytesPtr, len) -> do
                        f remaining_high remaining_low transfer_high transfer_low eatdIndex (fromIntegral len) bytesPtr

-- | Produce the payload of the encrypted amount transfer transaction.
makeEncryptedAmountTransferData ::
    -- | Global cryptographic parameters as they are on the chain
    -- where the transaction will be sent.
    GlobalContext ->
    -- | Public key of the receiver of the transfer
    ElgamalPublicKey ->
    -- | Secret key of the sender.
    ElgamalSecretKey ->
    -- | Input amount that is used in the transfer
    -- (i.e., amount on the sender's account).
    AggregatedDecryptedAmount ->
    -- | Amount to send.
    Amount ->
    -- | This function samples randomness to produce encryptions and zero-knowledge proofs.
    -- In rare cases it can fail to produce the data, although this should not happen in practice.
    -- If it does, retrying should resolve the issue.
    IO (Maybe EncryptedAmountTransferData)
makeEncryptedAmountTransferData gc receiverPk senderSk aggAmount (Amount desiredAmount) =
    withGlobalContext gc $ \gcPtr ->
        withElgamalPublicKey receiverPk $ \receiverPkPtr ->
            withElgamalSecretKey senderSk $ \senderSkPtr ->
                withAggregatedDecryptedAmount aggAmount $ \aggAmountPtr ->
                    alloca $ \rem_hi_ptr ->
                        alloca $ \rem_lo_ptr ->
                            alloca $ \trans_hi_ptr ->
                                alloca $ \trans_lo_ptr ->
                                    alloca $ \idx_ptr ->
                                        alloca $ \len_ptr -> do
                                            proof_ptr <- make_encrypted_transfer_data gcPtr receiverPkPtr senderSkPtr aggAmountPtr desiredAmount rem_hi_ptr rem_lo_ptr trans_hi_ptr trans_lo_ptr idx_ptr len_ptr
                                            if proof_ptr /= nullPtr
                                                then do
                                                    rem_hi <- unsafeMakeCipher =<< peek rem_hi_ptr
                                                    rem_lo <- unsafeMakeCipher =<< peek rem_lo_ptr
                                                    trans_hi <- unsafeMakeCipher =<< peek trans_hi_ptr
                                                    trans_lo <- unsafeMakeCipher =<< peek trans_lo_ptr
                                                    idx <- peek idx_ptr
                                                    len <- peek len_ptr
                                                    proof <- makeEncryptedAmountTransferProof (proof_ptr, fromIntegral len)
                                                    return $
                                                        Just
                                                            ( EncryptedAmountTransferData
                                                                { eatdRemainingAmount = EncryptedAmount rem_hi rem_lo,
                                                                  eatdTransferAmount = EncryptedAmount trans_hi trans_lo,
                                                                  eatdIndex = idx,
                                                                  eatdProof = proof
                                                                }
                                                            )
                                                else return Nothing

-- * Verify an encrypted transfer proof.
foreign import ccall safe "verify_encrypted_transfer"
    verify_encrypted_transfer ::
        -- | Pointer to the global context needed to validate the proof.
        Ptr GlobalContext ->
        -- | Public key of the receiver.
        Ptr ElgamalPublicKey ->
        -- | Public key of the sender.
        Ptr ElgamalPublicKey ->
        -- | High chunk of the current balance.
        Ptr ElgamalCipher ->
        -- | Low chunk of the current balance.
        Ptr ElgamalCipher ->
        -- | High chunk of the remaining amount.
        Ptr ElgamalCipher ->
        -- | Low chunk of the remaining amount.
        Ptr ElgamalCipher ->
        -- | High chunk of the transfer amount.
        Ptr ElgamalCipher ->
        -- | Low chunk of the transfer amount.
        Ptr ElgamalCipher ->
        -- | Index up to which amounts have been aggregated
        EncryptedAmountAggIndex ->
        -- | Pointer to the proof
        Ptr CChar ->
        -- | Length of the proof
        Word64 ->
        -- | Return either 0 if proof checking failed, or non-zero in case of success.
        IO Word8

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
    EncryptedAmountTransferData ->
    Bool
verifyEncryptedTransferProof gc receiverPK senderPK initialAmount transferData = unsafePerformIO $ do
    withGlobalContext gc $ \gcPtr ->
        withElgamalPublicKey receiverPK' $ \receiverPKPtr ->
            withElgamalPublicKey senderPK' $ \senderPKPtr ->
                withElgamalCipher (encryptionHigh initialAmount) $ \initialHighPtr ->
                    withElgamalCipher (encryptionLow initialAmount) $ \initialLowPtr ->
                        -- this is safe since the called function handles the 0 length case correctly.
                        withEncryptedAmountTransferData transferData $ \rem_hi rem_lo trans_hi trans_lo idx proof_len proof_ptr -> do
                            res <-
                                verify_encrypted_transfer
                                    gcPtr
                                    receiverPKPtr
                                    senderPKPtr
                                    initialHighPtr
                                    initialLowPtr
                                    rem_hi
                                    rem_lo
                                    trans_hi
                                    trans_lo
                                    idx
                                    proof_ptr
                                    proof_len
                            return (res /= 0)
  where
    AccountEncryptionKey receiverPK' = receiverPK
    AccountEncryptionKey senderPK' = senderPK

--------------------------------------------------------------------------------
--------------------------- Sec to pub transfer data ---------------------------
--------------------------------------------------------------------------------

foreign import ccall safe "make_sec_to_pub_data"
    make_sec_to_pub_transfer_data ::
        -- | Pointer to the global context
        Ptr GlobalContext ->
        -- | Secret key of the sender
        Ptr ElgamalSecretKey ->
        -- | Input encrypted amount for the transaction
        Ptr AggregatedDecryptedAmount ->
        -- | Amount to transfer.
        Word64 ->
        -- | High chunk of the remaining amount
        Ptr (Ptr ElgamalCipher) ->
        -- | Low chunk of the remaining amount
        Ptr (Ptr ElgamalCipher) ->
        -- | Place to write the index
        Ptr EncryptedAmountAggIndex ->
        -- | Place to write the length of the proof
        Ptr Word64 ->
        -- | The proof
        IO (Ptr CChar)

-- | Serialized version of `SecToPubAmountTransferProof` in encrypted_transfers/src/types.rs
newtype SecToPubAmountTransferProof = SecToPubAmountTransferProof {theSecToPubAmountTransferProof :: ShortByteString}
    deriving (Eq, Show, FromJSON, ToJSON) via ByteStringHex
    deriving (Serialize) via Short65K

withSecToPubAmountTransferProof :: SecToPubAmountTransferProof -> (CStringLen -> IO a) -> IO a
withSecToPubAmountTransferProof (SecToPubAmountTransferProof s) = useAsCStringLen s

makeSecToPubAmountTransferProof :: CStringLen -> IO SecToPubAmountTransferProof
makeSecToPubAmountTransferProof c = SecToPubAmountTransferProof <$> packCStringLen c

-- | Custom serialization functions for proofs which allow us to have the same
-- serialization as in rust, provided enough context, i.e., length.
getSecToPubAmountTransferProof :: Word32 -> Get SecToPubAmountTransferProof
getSecToPubAmountTransferProof len = SecToPubAmountTransferProof <$> getShortByteString (fromIntegral len)

-- |Put the proof directly without the length.
-- The proof can be deserialized in the right contexts using 'getSecToPubAmountTransferProof'
putSecToPubAmountTransferProof :: SecToPubAmountTransferProof -> Put
putSecToPubAmountTransferProof = putShortByteString . theSecToPubAmountTransferProof

-- | Haskell counterpart of `SecToPubAmountTransferData` in encrypted_transfers/src/types.rs
data SecToPubAmountTransferData = SecToPubAmountTransferData
    { stpatdRemainingAmount :: !EncryptedAmount,
      stpatdTransferAmount :: !Amount,
      stpatdIndex :: !EncryptedAmountAggIndex,
      stpatdProof :: !SecToPubAmountTransferProof
    }
    deriving (Eq, Show)

instance FromJSON SecToPubAmountTransferData where
    parseJSON = withObject "Secret To Public Transfer Data" $ \v -> do
        stpatdRemainingAmount <- v .: "remainingAmount"
        stpatdTransferAmount <- v .: "transferAmount"
        stpatdIndex <- v .: "index"
        stpatdProof <- v .: "proof"
        return SecToPubAmountTransferData{..}

withSecToPubAmountTransferData ::
    SecToPubAmountTransferData ->
    (Ptr ElgamalCipher -> Ptr ElgamalCipher -> Word64 -> EncryptedAmountAggIndex -> Word64 -> Ptr CChar -> IO a) ->
    IO a
withSecToPubAmountTransferData SecToPubAmountTransferData{..} f = do
    withElgamalCipher (encryptionHigh stpatdRemainingAmount) $ \remaining_high ->
        withElgamalCipher (encryptionLow stpatdRemainingAmount) $ \remaining_low ->
            withSecToPubAmountTransferProof stpatdProof $ \(proof, proof_len) ->
                f remaining_high remaining_low (_amount stpatdTransferAmount) stpatdIndex (fromIntegral proof_len) proof

-- | Make the payload of encrypted to public transfer transaction.
makeSecToPubAmountTransferData ::
    -- | Global cryptographic parameters as they are on the chain
    -- where the transaction will be sent.
    GlobalContext ->
    -- | Secret key of the account
    ElgamalSecretKey ->
    -- | Input amount that is used in the transfer
    -- (i.e., amount on the sender's account).
    AggregatedDecryptedAmount ->
    -- | Amount to transfer to public balance.
    Amount ->
    -- | This function samples randomness to produce zero-knowledge proofs. In
    -- some cases it might sample randomness that makes it fail, returning
    -- 'Nothing'. This should not happen in practice (the probability is
    -- negligible), but if it does retrying is the best remedy.
    IO (Maybe SecToPubAmountTransferData)
makeSecToPubAmountTransferData gc sk aggAmount (Amount amount) =
    withGlobalContext gc $ \gcPtr ->
        withElgamalSecretKey sk $ \skPtr ->
            withAggregatedDecryptedAmount aggAmount $ \aggAmountPtr ->
                alloca $ \rem_hi_ptr ->
                    alloca $ \rem_lo_ptr ->
                        alloca $ \idx_ptr ->
                            alloca $ \len_ptr -> do
                                proof_ptr <- make_sec_to_pub_transfer_data gcPtr skPtr aggAmountPtr amount rem_hi_ptr rem_lo_ptr idx_ptr len_ptr
                                if proof_ptr == nullPtr
                                    then return Nothing
                                    else do
                                        rem_hi <- unsafeMakeCipher =<< peek rem_hi_ptr
                                        rem_lo <- unsafeMakeCipher =<< peek rem_lo_ptr
                                        idx <- peek idx_ptr
                                        len <- peek len_ptr
                                        proof <- makeSecToPubAmountTransferProof (proof_ptr, fromIntegral len)
                                        return $
                                            Just
                                                SecToPubAmountTransferData
                                                    { stpatdRemainingAmount = EncryptedAmount rem_hi rem_lo,
                                                      stpatdTransferAmount = Amount amount,
                                                      stpatdIndex = idx,
                                                      stpatdProof = proof
                                                    }

foreign import ccall safe "verify_sec_to_pub_transfer"
    verify_sec_to_pub_transfer ::
        -- | Pointer to the global context needed to validate the proof.
        Ptr GlobalContext ->
        -- | Public key of the sender.
        Ptr ElgamalPublicKey ->
        -- | High chunk of the current balance.
        Ptr ElgamalCipher ->
        -- | Low chunk of the current balance.
        Ptr ElgamalCipher ->
        -- | High chunk of the remaining amount.
        Ptr ElgamalCipher ->
        -- | Low chunk of the remaining amount.
        Ptr ElgamalCipher ->
        -- | Plaintext amount that is to be transferred
        Word64 ->
        -- | Index up to which amounts have been aggregated
        EncryptedAmountAggIndex ->
        -- | Pointer to the proof
        Ptr CChar ->
        Word64 ->
        -- | Return either 0 if proof checking failed, or non-zero in case of success.
        IO Word8

verifySecretToPublicTransferProof ::
    -- |Global context with parameters
    GlobalContext ->
    -- |Public key of the sender.
    AccountEncryptionKey ->
    -- |Aggregated encrypted amount on the sender's account that was used.
    EncryptedAmount ->
    -- |Proof of validity of the transfer.
    SecToPubAmountTransferData ->
    Bool
verifySecretToPublicTransferProof gc senderPK initialAmount transferData = unsafePerformIO $ do
    withGlobalContext gc $ \gcPtr ->
        withElgamalPublicKey senderPK' $ \senderPKPtr ->
            withElgamalCipher (encryptionHigh initialAmount) $ \initialHighPtr ->
                withElgamalCipher (encryptionLow initialAmount) $ \initialLowPtr ->
                    -- this is safe since the called function handles the 0 length case correctly.
                    withSecToPubAmountTransferData transferData $ \rem_hi rem_lo amount idx proof_len proof_ptr -> do
                        res <-
                            verify_sec_to_pub_transfer
                                gcPtr
                                senderPKPtr
                                initialHighPtr
                                initialLowPtr
                                rem_hi
                                rem_lo
                                amount
                                idx
                                proof_ptr
                                proof_len
                        return (res /= 0)
  where
    AccountEncryptionKey senderPK' = senderPK

-- |Decrypt an encrypted amount.

-- |Baby-step-giant-step table to speed-up decryption.
newtype Table = Table (ForeignPtr Table)

withTable :: Table -> (Ptr Table -> IO b) -> IO b
withTable (Table fp) = withForeignPtr fp

-- Precompute the baby step giant step table
foreign import ccall safe "compute_table"
    computeTablePtr :: Ptr GlobalContext -> Word64 -> IO (Ptr Table)

foreign import ccall unsafe "&free_table"
    freeTable :: FunPtr (Ptr Table -> IO ())

foreign import ccall safe "decrypt_amount"
    decryptAmountPtr ::
        Ptr Table ->
        Ptr ElgamalSecretKey ->
        -- |Pointer to high bits of the amount
        Ptr ElgamalCipher ->
        -- |Pointer to low bits of the amount
        Ptr ElgamalCipher ->
        IO Word64

-- |Compute the table in the context of the global context. The 'Word64'
-- arguments determines the size of the table, a good number to choose is 2^16,
-- although a bigger table might be better if many decryptions are going to be
-- performed.
computeTable :: GlobalContext -> Word64 -> Table
computeTable gc m = Table . unsafePerformIO $ do
    r <- withGlobalContext gc (flip computeTablePtr m)
    newForeignPtr freeTable r

-- |Decrypt an encrypted amount that is assumed to have been encrypted with the
-- public key corresponding to the given secret key, as well as parameters in
-- global context and table. If this is not the case this function is almost
-- certainly going to appear to loop.
decryptAmount :: Table -> ElgamalSecretKey -> EncryptedAmount -> Amount
decryptAmount table sec EncryptedAmount{..} = Amount . unsafePerformIO $
    withTable table $ \tablePtr ->
        withElgamalSecretKey sec $ \secPtr ->
            withElgamalCipher encryptionHigh $ \highPtr ->
                withElgamalCipher encryptionLow $ decryptAmountPtr tablePtr secPtr highPtr

--------------------------------------------------------------------------------
-------------------------- Helper mostly for testing ---------------------------
--------------------------------------------------------------------------------

foreign import ccall safe "encrypt_amount"
    encrypt_amount ::
        -- | Global context
        Ptr GlobalContext ->
        -- | Public key with which to encrypt.
        Ptr ElgamalPublicKey ->
        -- | Amount to be encrypted
        Word64 ->
        -- | Place to write the pointer to the high chunk of the result.
        Ptr (Ptr ElgamalCipher) ->
        -- | Place to write the pointer to the low chunk of the result.
        Ptr (Ptr ElgamalCipher) ->
        IO ()

-- | Encrypt the given amount. This is non-deterministic since it samples
-- randomness to encrypt with.
encryptAmount :: GlobalContext -> ElgamalPublicKey -> Amount -> IO EncryptedAmount
encryptAmount gc pub (Amount amount) =
    withGlobalContext gc $ \gcPtr ->
        withElgamalPublicKey pub $ \pubPtr ->
            alloca $ \outHighPtr ->
                alloca $ \outLowPtr -> do
                    encrypt_amount gcPtr pubPtr amount outHighPtr outLowPtr
                    outHigh <- unsafeMakeCipher =<< peek outHighPtr
                    outLow <- unsafeMakeCipher =<< peek outLowPtr
                    return EncryptedAmount{encryptionHigh = outHigh, encryptionLow = outLow}
