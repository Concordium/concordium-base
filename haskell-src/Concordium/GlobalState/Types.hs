{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleContexts #-}
{-# OPTIONS_GHC -Wall #-}
module Concordium.GlobalState.Types (module Concordium.GlobalState.Types, AH.AccountAddress(..)) where

import GHC.Generics

import Data.Hashable(Hashable)
import Data.Word

import Concordium.Crypto.SHA256(Hash)
import qualified Concordium.Crypto.SHA256 as H
import qualified Concordium.ID.AccountHolder as AH
import Concordium.ID.Types
import Data.ByteString.Char8(ByteString)
import Concordium.GlobalState.HashableTo

import qualified Data.Serialize as S
import qualified Data.Serialize.Put as P
import qualified Data.Serialize.Get as G


data Hashed a = Hashed {unhashed :: a, hashed :: H.Hash}

instance HashableTo H.Hash (Hashed a) where
    getHash = hashed

makeHashed :: HashableTo H.Hash a => a -> Hashed a
makeHashed v = Hashed v (getHash v)

instance Eq (Hashed a) where
    a == b = hashed a == hashed b

instance Ord (Hashed a) where
    compare a b = compare (hashed a) (hashed b)

-- * Blockchain specific types.
-- Eventually these will be replaced by types given by the global store.
-- For now they are placeholders

data ContractAddress = ContractAddress { contractIndex :: !Word64
                                       , contractVersion :: !Word64} 
    deriving(Eq, Generic)

instance Hashable ContractAddress

instance Show ContractAddress where
  show (ContractAddress i v) = "<" ++ show i ++ ", " ++ show v ++ ">"

instance S.Serialize ContractAddress where
  get = ContractAddress <$> G.getWord64be <*> G.getWord64be
  put (ContractAddress i v) = P.putWord64be i <> P.putWord64be v


-- |An address is either a contract or account.
data Address = AddressAccount !AH.AccountAddress
             | AddressContract !ContractAddress
            deriving(Show)

instance S.Serialize Address where
  get = do
    h <- G.getWord8 -- FIXME: this is inefficient but ok for testing. The size
                    -- of the data should already tell what address it is.
    case h of
      0 -> AddressAccount <$> S.get
      1 -> AddressContract <$> S.get
      _ -> fail "Only two types of addresses are supported."

  put (AddressAccount acc) = P.putWord8 0 <> S.put acc
  put (AddressContract cnt) = P.putWord8 1 <> S.put cnt


-- |Type of GTU amounts.
newtype Amount = Amount { _amount :: Word64 }
    deriving(Eq, Ord, Enum, Num, Integral, Real, Hashable)

instance Show Amount where
  show = show . _amount

instance S.Serialize Amount where
  get = Amount <$> G.getWord64be
  put (Amount v) = P.putWord64be v


newtype Nonce = Nonce Word64
    deriving(Eq, Show, Ord, Num)

instance S.Serialize Nonce where
  put (Nonce w) = P.putWord64be w
  get = Nonce <$> G.getWord64be

minNonce :: Nonce
minNonce = 1

data Account = Account {
  accountAddress :: !AH.AccountAddress -- ^Address of the account.
  ,accountNonce :: !Nonce  -- ^Next available nonce for this account.
  ,accountAmount :: !Amount -- ^Current public account balance.
  ,accountCreationInformation :: AccountCreationInformation
  }

instance S.Serialize Account where
  put Account{..} = S.put accountAddress <> S.put accountNonce <> S.put accountAmount <> S.put accountCreationInformation
  get = Account <$> S.get <*> S.get <*> S.get <*> S.get

instance HashableTo Hash Account where
  getHash = H.hash . S.runPut . S.put

-- |Serialized payload of the transaction
newtype SerializedPayload = SerializedPayload { _spayload :: ByteString }
    deriving(Eq, Show)

-- |FIXME: This instance is probably wrong. What we want is just putByteString since the body is already serialized.
instance S.Serialize SerializedPayload where
  put = S.put . _spayload
  get = SerializedPayload <$> S.get

-- *Types that are morally part of the consensus, but need to be exposed in
-- other parts of the system as well, e.g., in smart contracts.

newtype Slot = Slot Word64 deriving (Eq, Ord, Num, Real, Enum, Integral, Show, S.Serialize)
newtype BlockHeight = BlockHeight {theBlockHeight :: Word64} deriving (Eq, Ord, Num, Real, Enum, Integral, Show, S.Serialize)

-- |Blockchain metadata as needed by contract execution.
data ChainMetadata =
  ChainMetadata { slotNumber :: Slot
                -- |Height of the current block (the block which the transaction is going to be a part of).
                , blockHeight :: BlockHeight 
                -- |Height of the last finalized block. NB: Each block has a
                -- pointer to the last finalized block, and this field is the
                -- height of that block. This information is stable with respect
                -- to time. In the future a block between that block and the
                -- current block might become finalized, so the distance
                -- blockHeight - finalizedHeight is an upper bound only.
                , finalizedHeight :: BlockHeight
                }
