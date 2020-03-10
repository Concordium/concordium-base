-- | This module defines the variants for having persistent transactions.
--
-- Transactions can now exist in two forms: in memory and in the disk.
-- A transaction in memory will be a BareTransaction.
-- A transaction in the disk will be a PersistentBareTransaction. It holds a WeakPtr that
-- will be pointing to an existing in memory version of the transaction when it has been loaded
-- until it is not needed anymore so that concurrent accesses to this transaction won't need
-- to read again the database.
-- A block will hold a list of PersistentTransactions.
-- The operations for converting the transaction from the disk version to the memory version
-- will be done at the treestate level so that the rest of the modules will receive always
-- BasicTransactions
module Concordium.Types.PersistentTransactions where

import Concordium.Types.Transactions
import System.Mem.Weak
import Concordium.Types
import System.IO.Unsafe
import Data.Serialize
import Concordium.Types.HashableTo

-- | The persistent bare transaction holds the transaction hash in order
-- to be able to retrieve the memory transaction from the disk and a Weak pointer
-- to have some kind of caching of the value.
data PersistentBareTransaction = PersistentBareTransaction {
    pbtHash :: !TransactionHash,
    pbtPtr :: !(Weak BareTransaction)
  }

instance Show PersistentBareTransaction where
  show = show . pbtHash

-- | PersistentTransaction a PersistentBareTransaction. The hash field is included in
-- the PersistentBareTransaction
data PersistentTransaction = PersistentTransaction {
  ptrBareTransaction :: !PersistentBareTransaction,
  ptrSize :: !Int,
  ptrArrivalTime :: !TransactionTime
  } deriving (Show)

instance Eq PersistentTransaction where
  t1 == t2 = (pbtHash $ ptrBareTransaction t1) == (pbtHash $ ptrBareTransaction t2)

instance Ord PersistentTransaction where
  compare t1 t2 = compare (pbtHash $ ptrBareTransaction t1) (pbtHash $ ptrBareTransaction t2)

instance Serialize PersistentTransaction where
  put t = do
    put . (getHash :: PersistentTransaction -> TransactionHash) $ t
    put $ ptrSize t
  get = fail "Use getPersistentTransaction instead"

instance HashableTo TransactionHash PersistentTransaction where
  getHash = pbtHash . ptrBareTransaction

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

getPersistentTransaction :: TransactionTime -> Get PersistentTransaction
getPersistentTransaction ar = do
  h <- get
  s <- get
  let e = unsafePerformIO emptyWeak
  return $ PersistentTransaction (PersistentBareTransaction h e) s ar
