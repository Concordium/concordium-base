{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE DerivingStrategies #-}
{-# OPTIONS_GHC -Wall #-}
module Concordium.Types (module Concordium.Types, AccountAddress(..), SchemeId, AccountVerificationKey) where

import GHC.Generics


import qualified Concordium.Crypto.BlockSignature as Sig
import qualified Concordium.Crypto.SHA256 as Hash
import qualified Concordium.Crypto.VRF as VRF
import Concordium.ID.Types
import qualified Concordium.ID.Account as AH
import Concordium.Crypto.SignatureScheme(SchemeId)
import Concordium.Types.HashableTo
import Control.Exception(assert)

import Data.Hashable(Hashable)
import Data.Word
import Data.ByteString.Char8(ByteString)
import qualified Data.ByteString.Short as BSS
import qualified Data.ByteString.Lazy.Char8 as BSL
import Data.ByteString.Builder(toLazyByteString, byteStringHex)
import Data.Bits
import Data.Ratio
import qualified Data.Set as Set
import Data.Set(Set)

import Data.Aeson as AE

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

-- * Types releated to bakers.
newtype BakerId = BakerId Word64
    deriving (Eq, Ord, Num, Enum, Bounded, Real, Hashable, Show, Integral)

instance S.Serialize BakerId where
    get = BakerId <$> G.getWord64be
    put (BakerId i) = P.putWord64be i

type LeadershipElectionNonce = ByteString
type BakerSignVerifyKey = Sig.VerifyKey
type BakerSignPrivateKey = Sig.KeyPair
type BakerElectionVerifyKey = VRF.PublicKey
type BakerElectionPrivateKey = VRF.KeyPair
type LotteryPower = Ratio Amount
type ElectionDifficulty = Double

type VoterId = Word64
type VoterVerificationKey = Sig.VerifyKey
type VoterVRFPublicKey = VRF.PublicKey
type VoterSignKey = Sig.SignKey
newtype VoterPower = VoterPower Int
    deriving newtype (Eq, Ord, Num, Enum, Bounded, Real, Show, Integral, S.Serialize)

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
    deriving(Eq, Ord, Generic)

instance FromJSON ContractAddress where
  parseJSON = withObject "ContractAddress" $ \v -> do
    i <- v .: "index"
    j <- v .: "subindex"
    return $ ContractAddress (fromIntegral (i :: Word64)) (fromIntegral (j :: Word64))

instance ToJSON ContractAddress where
  toJSON (ContractAddress i j) =
    object ["index" AE..= (fromIntegral i :: Word64), "subindex" AE..= (fromIntegral j :: Word64)]
  toEncoding (ContractAddress i j) =
    pairs ("index" AE..= (fromIntegral i :: Word64) <> "subindex" AE..= (fromIntegral j :: Word64))

instance Hashable ContractAddress

instance Show ContractAddress where
  show (ContractAddress i v) = "<" ++ show i ++ ", " ++ show v ++ ">"

instance S.Serialize ContractAddress where
  get = ContractAddress <$> S.get <*> S.get
  put (ContractAddress i v) = S.put i <> S.put v

-- |Unique module reference.
newtype ModuleRef = ModuleRef {moduleRef :: Hash.Hash}
    deriving(Eq, Ord, Hashable)

instance Show ModuleRef where
  show (ModuleRef m) = show m

instance S.Serialize ModuleRef where
  get = getModuleRef
  put = putModuleRef

getModuleRef :: G.Get ModuleRef
getModuleRef = ModuleRef <$> S.get

putModuleRef :: P.Putter ModuleRef
putModuleRef (ModuleRef mref) = do
  S.put mref

-- |An address is either a contract or account.
data Address = AddressAccount !AccountAddress
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
-- FIXME: This likely needs to be Word128.
newtype Amount = Amount { _amount :: Word64 }
    deriving(Eq, Ord, Enum, Bounded, Num, Integral, Real, Hashable)

instance Show Amount where
  show = show . _amount

instance S.Serialize Amount where
  get = Amount <$> G.getWord64be
  put (Amount v) = P.putWord64be v

-- |Type representing a difference between amounts.
newtype AmountDelta = AmountDelta { amountDelta :: Integer }
    deriving (Eq, Ord, Enum, Num, Integral, Real)

amountToDelta :: Amount -> AmountDelta
amountToDelta = fromIntegral

amountDiff :: Amount -> Amount -> AmountDelta
amountDiff amt1 amt2 = fromIntegral amt1 - fromIntegral amt2

applyAmountDelta ::  AmountDelta -> Amount -> Amount
applyAmountDelta del amt =
        assert (amt' >= fromIntegral (minBound :: Amount)) $
        assert (amt' <= fromIntegral (maxBound :: Amount)) $
            fromIntegral amt'
    where
        amt' = fromIntegral amt + del

-- |The type used to count exact execution cost. This cost is then converted to
-- amounts in some way.
newtype Energy = Energy { _energy :: Word64 }
    deriving(Eq, Enum, Ord, Num, Real, Integral, Hashable)

instance Show Energy where
  show = show . _energy

instance S.Serialize Energy where
  get = Energy <$> G.getWord64be
  put (Energy v) = P.putWord64be v

newtype Nonce = Nonce Word64
    deriving(Eq, Show, Ord, Num, Enum)

instance S.Serialize Nonce where
  put (Nonce w) = P.putWord64be w
  get = Nonce <$> G.getWord64be

minNonce :: Nonce
minNonce = 1

newtype EncryptedAmount = EncryptedAmount ByteString
    deriving(Eq, S.Serialize)

instance Show EncryptedAmount where
  show (EncryptedAmount amnt) = BSL.unpack . toLazyByteString . byteStringHex $ amnt

data Account = Account {
  -- |Address of the account.
  _accountAddress :: !AccountAddress
  -- |Next available nonce for this account.
  ,_accountNonce :: !Nonce
  -- |Current public account balance.
  ,_accountAmount :: !Amount
  -- |List of encrypted amounts on the account.
  ,_accountEncryptedAmount :: ![EncryptedAmount]
  -- |Encryption key with which the encrypted amount on this account must be
  -- encrypted. Other accounts use it to send encrypted amounts to this account,
  -- if the key exists. Accounts start with no encryption key, and once the key
  -- is chosen it cannot be changed.
  ,_accountEncryptionKey :: !(Maybe AccountEncryptionKey)
  -- |The key used to verify transaction signatures.
  ,_accountVerificationKey :: !AccountVerificationKey
  -- |Signature scheme of the account.
  ,_accountSignatureScheme :: SchemeId
  -- |FIXME: Once it is clearer what policies are and how they affect execution
  -- we might expand credentials into a more efficient data structure allowing
  -- more efficient checking of credentials/policies, but until then we just
  -- keep the data that was sent as part of the transaction. Note that most of
  -- the data is not needed on a regular basis. The only part relevant for
  -- transaction execution is the policy. In particular the policy will always
  -- have an expiration date. Once it is clear how this date is used it will be
  -- lifted up so that we only ever check credentials which are not out of date.
  -- We do not retain proofs in global state.
  ,_accountCredentials :: ![CredentialDeploymentValues]
  -- |The baker to which this account's stake is delegated (if any).
  ,_accountStakeDelegate :: !(Maybe BakerId)
  -- |The set of instances belonging to this account.
  -- TODO: Revisit choice of datastructure.  Additions and removals
  -- are expected to be rare.  The set is traversed when stake delegation
  -- changes.
  ,_accountInstances :: !(Set ContractAddress)
  } deriving(Show)

makeLenses ''Account

instance S.Serialize Account where
  put Account{..} = S.put _accountAddress <>
                    S.put _accountNonce <>
                    S.put _accountAmount <>
                    S.put _accountEncryptedAmount <>
                    S.put _accountEncryptionKey <>
                    S.put _accountVerificationKey <>
                    S.put _accountSignatureScheme <>
                    S.put _accountCredentials <>
                    S.put _accountStakeDelegate <>
                    S.put (Set.toAscList _accountInstances)
  get = Account <$> S.get <*> S.get <*> S.get <*> S.get <*> S.get <*> S.get <*> S.get <*> S.get <*> S.get <*> (Set.fromList <$> S.get)

instance HashableTo Hash.Hash Account where
  getHash = Hash.hash . S.runPut . S.put

-- |Create an empty account with the given public key.
newAccount :: AccountVerificationKey -> SchemeId -> Account
newAccount _accountVerificationKey _accountSignatureScheme = Account {
        _accountAddress = AH.accountAddress _accountVerificationKey _accountSignatureScheme,
        _accountNonce = minNonce,
        _accountAmount = 0,
        _accountEncryptedAmount = [],
        _accountEncryptionKey = Nothing,
        _accountCredentials = [],
        _accountStakeDelegate = Nothing,
        _accountInstances = Set.empty,
        ..
    }

-- |Serialized payload of the transaction
newtype EncodedPayload = EncodedPayload { _spayload :: BSS.ShortByteString }
    deriving(Eq, Show)

payloadSize :: EncodedPayload -> Int
payloadSize = BSS.length . _spayload

-- |NB: We explicitly put the length first, even though the body is already
-- serialized and thus it would normally not be necessary to do so. The reason
-- we do it is that at the moment a transaction can appear on a block even
-- though the body cannot be deserialized. Thus it is important to know
-- precisely the length of the body.
instance S.Serialize EncodedPayload where
  put (EncodedPayload p) = 
    P.putWord32be (fromIntegral (BSS.length p)) <>
    P.putShortByteString p
  get = do
    l <- fromIntegral <$> G.getWord32be
    EncodedPayload <$> G.getShortByteString l

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
type BlockNonce = VRF.Proof

