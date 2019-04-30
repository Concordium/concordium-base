{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE DerivingStrategies #-}
{-# OPTIONS_GHC -Wall #-}
module Concordium.Types (module Concordium.Types, AH.AccountAddress(..)) where

import GHC.Generics


import qualified Concordium.Crypto.BlockSignature as Sig
import qualified Concordium.Crypto.SHA256 as Hash
import qualified Concordium.Crypto.VRF as VRF
import qualified Concordium.ID.AccountHolder as AH
import Concordium.ID.Types
import Concordium.Types.HashableTo

import Data.Hashable(Hashable)
import Data.Word
import Data.ByteString.Char8(ByteString)
import qualified Data.ByteString.Char8 as BS
import Data.Bits

import qualified Data.Serialize as S
import qualified Data.Serialize.Put as P
import qualified Data.Serialize.Get as G

import Lens.Micro.Platform

data Hashed a = Hashed {unhashed :: a, hashed :: Hash.Hash}

instance HashableTo Hash.Hash (Hashed a) where
    getHash = hashed

makeHashed :: HashableTo Hash.Hash a => a -> Hashed a
makeHashed v = Hashed v (getHash v)

instance Eq (Hashed a) where
    a == b = hashed a == hashed b

instance Ord (Hashed a) where
    compare a b = compare (hashed a) (hashed b)

-- * Blockchain specific types.
-- Eventually these will be replaced by types given by the global store.
-- For now they are placeholders

newtype ContractIndex = ContractIndex Word64
    deriving newtype (Eq, Ord, Num, Enum, Bounded, Real, Hashable, Show, Bits, Integral)

instance S.Serialize ContractIndex where
    get = ContractIndex <$> G.getWord64be
    put (ContractIndex i) = P.putWord64be i

newtype ContractSubindex = ContractSubindex Word64
    deriving newtype (Eq, Ord, Num, Enum, Bounded, Real, Hashable, Show, Integral)

instance S.Serialize ContractSubindex where
    get = ContractSubindex <$> G.getWord64be
    put (ContractSubindex i) = P.putWord64be i

data ContractAddress = ContractAddress { contractIndex :: !ContractIndex
                                       , contractSubindex :: !ContractSubindex} 
    deriving(Eq, Generic)

instance Hashable ContractAddress

instance Show ContractAddress where
  show (ContractAddress i v) = "<" ++ show i ++ ", " ++ show v ++ ">"

instance S.Serialize ContractAddress where
  get = ContractAddress <$> S.get <*> S.get
  put (ContractAddress i v) = S.put i <> S.put v


-- |An address is either a contract or account.
data Address = AddressAccount !AH.AccountAddress
             | AddressContract !ContractAddress
            deriving(Show, Eq)

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
    deriving(Eq, Show, Ord, Num, Enum)

instance S.Serialize Nonce where
  put (Nonce w) = P.putWord64be w
  get = Nonce <$> G.getWord64be

minNonce :: Nonce
minNonce = 1

data Account = Account {
  _accountAddress :: !AH.AccountAddress -- ^Address of the account.
  ,_accountNonce :: !Nonce  -- ^Next available nonce for this account.
  ,_accountAmount :: !Amount -- ^Current public account balance.
  ,_accountCreationInformation :: AccountCreationInformation
  }

makeLenses ''Account

instance S.Serialize Account where
  put Account{..} = S.put _accountAddress <> S.put _accountNonce <> S.put _accountAmount <> S.put _accountCreationInformation
  get = Account <$> S.get <*> S.get <*> S.get <*> S.get

instance HashableTo Hash.Hash Account where
  getHash = Hash.hash . S.runPut . S.put

-- |Serialized payload of the transaction
newtype EncodedPayload = EncodedPayload { _spayload :: ByteString }
    deriving(Eq, Show)

-- |NB: We explicitly put the length first, even though the body is already
-- serialized and thus it would normally not be necessary to do so. The reason
-- we do it is that at the moment a transaction can appear on a block even
-- though the body cannot be deserialized. Thus it is important to know
-- precisely the length of the body.
instance S.Serialize EncodedPayload where
  put (EncodedPayload p) = 
    P.putWord32be (fromIntegral (BS.length p)) <>
    P.putByteString p
  get = do
    l <- fromIntegral <$> G.getWord32be
    EncodedPayload <$> G.getByteString l

-- *Types that are morally part of the consensus, but need to be exposed in
-- other parts of the system as well, e.g., in smart contracts.

newtype Slot = Slot Word64 deriving (Eq, Ord, Num, Real, Enum, Integral, Show, S.Serialize)

-- |The slot number of the genesis block (0).
genesisSlot :: Slot
genesisSlot = 0

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


-- * Types related to blocks

type BlockHash = Hash.Hash
type BlockProof = VRF.Proof
type BlockSignature = Sig.Signature
-- TODO: The hash is redundant; should be removed
type BlockNonce = (VRF.Hash, VRF.Proof)

