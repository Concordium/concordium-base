{-# LANGUAGE DerivingVia #-}
-- | This module defines the variants for having persistent transactions.
--
-- Transactions can now exist in two forms: in memory and in the disk.
-- A transaction in memory will be a BareTransaction.
-- A transaction in the disk will be a PersistentBareTransaction. It holds a WeakPtr that
-- will be pointing to an existing in memory version of the transaction when it has been loaded
-- until it is not needed anymore so that concurrent accesses to this transaction won't need
-- to read again the database.
-- A block will hold a list of PersistentBlockItems.
-- The operations for converting the transaction from the disk version to the memory version
-- will be done at the treestate level so that the rest of the modules will receive always
-- BasicTransactions
module Concordium.Types.PersistentBlockItems where

import Concordium.Types.Transactions
import System.Mem.Weak
import Concordium.Types
import System.IO.Unsafe
import Data.Serialize
import Concordium.Types.HashableTo

-- | PersistentBlockItem is mostly a transaction metadata, with a possibly weak pointer to an actual block item.
newtype PersistentBlockItem = PersistentBlockItem { ptr :: WithMetadata (Weak BlockItem) }
    deriving(Eq, Ord, BIMetadata, HashableTo TransactionHash) via (WithMetadata (Weak BlockItem))

instance Show PersistentBlockItem where
  show p = show (wmdHash (ptr p))

instance ToPut PersistentBlockItem where
  {-# INLINE toPut #-}
  toPut t = put (getHash (ptr t) :: TransactionHash) <>
            putInt64be (fromIntegral (wmdSize (ptr t)))

-- |Create an empty weak pointer
--
-- Creating a pointer that points to `undefined` with no finalizers and finalizing it
-- immediately, results in an empty pointer that always return `Nothing`
-- when dereferenced.
emptyWeak :: IO (Weak a)
emptyWeak = do
  pointer <- mkWeakPtr undefined Nothing
  finalize pointer
  return pointer

getPersistentBlockItem :: TransactionTime -> Get PersistentBlockItem
getPersistentBlockItem wmdArrivalTime = do
  wmdHash <- get
  wmdSize <- fromIntegral <$> getInt64be
  let wmdData = unsafePerformIO emptyWeak
  return PersistentBlockItem{ptr = WithMetadata{..}}
