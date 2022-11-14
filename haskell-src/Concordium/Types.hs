{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}

-- |Basic blockchain types.
module Concordium.Types (
    -- * Cost units
    module Concordium.Common.Amount,
    Energy (..),
    AmountDelta (..),
    amountToDelta,
    amountDiff,
    applyAmountDelta,

    -- ** Exchange rates
    ExchangeRate (..),
    EnergyRate,
    computeEnergyRate,
    computeCost,

    -- * Mint and reward rates
    MintRate (..),
    mintAmount,
    AmountFraction (..),
    makeAmountFraction,
    addAmountFraction,
    hundredThousand,
    complementAmountFraction,
    takeFraction,
    fractionToRational,
    CommissionRates (..),
    finalizationCommission,
    bakingCommission,
    transactionCommission,

    -- * Time units
    Duration (..),
    durationToNominalDiffTime,
    getTransactionTime,
    Timestamp (..),
    timestampToUTCTime,
    utcTimeToTimestamp,
    timestampToSeconds,
    addDuration,
    DurationSeconds (..),
    addDurationSeconds,
    TransactionTime (..),
    TransactionExpiryTime,
    utcTimeToTransactionTime,
    transactionTimeToTimestamp,
    transactionExpired,
    transactionTimeToSlot,
    isTimestampBefore,

    -- * Accounts
    SchemeId,
    AccountAddress (..),
    AccountEncryptedAmount (..),
    initialAccountEncryptedAmount,
    isZeroAccountEncryptedAmount,
    incomingEncryptedAmounts,
    getIncomingAmountsList,
    aggregatedAmount,
    selfAmount,
    startIndex,
    Nonce (..),
    minNonce,
    AccountVerificationKey,
    AccountIndex (..),
    AccountIdentifier (..),
    decodeAccountIdentifier,

    -- * Smart contracts
    ModuleRef (..),
    ContractIndex (..),
    ContractSubindex (..),
    ContractAddress (..),

    -- ** Chain metadata
    ChainMetadata (..),
    encodeChainMeta,

    -- * Addresses
    Address (..),

    -- * URLs
    UrlText (..),
    maxUrlTextLength,
    emptyUrlText,

    -- * Registered Data
    RegisteredData (..),
    registeredDataFromBSS,
    maxRegisteredDataSize,

    -- * Transaction memo
    Memo (..),
    maxMemoSize,
    memoFromBSS,

    -- * Baking
    ElectionDifficulty (..),
    makeElectionDifficulty,
    makeElectionDifficultyUnchecked,
    getDoubleFromElectionDifficulty,
    LotteryPower,
    BakerAggregationProof,
    BakerAggregationPrivateKey,
    BakerAggregationVerifyKey,
    BakerElectionPrivateKey,
    BakerElectionVerifyKey,
    BakerSignPrivateKey,
    BakerSignVerifyKey,
    LeadershipElectionNonce,
    BakerId (..),
    DelegatorId (..),

    -- ** Block elements
    BlockNonce,
    BlockSignature,
    BlockProof,
    StateHashV0 (..),
    StateHash,
    BlockHash (..),
    BlockHeight (..),
    Slot (..),
    EpochLength,
    Epoch,
    RewardPeriodLength (..),
    genesisSlot,
    CredentialsPerBlockLimit,

    -- ** Transactions
    EncodedPayload (..),
    PayloadSize (..),
    putEncodedPayload,
    getEncodedPayload,
    payloadSize,
    validatePayloadSize,
    TransactionSignHashV0 (..),
    TransactionSignHash,
    transactionSignHashToByteString,
    TransactionHashV0 (..),
    TransactionHash,

    -- * Finalization
    VoterId,
    VoterPower (..),
    VoterSignKey,
    VoterVerificationKey,
    VoterVRFPublicKey,
    VoterAggregationPrivateKey,
    VoterAggregationVerifyKey,
    FinalizationIndex (..),
    FinalizationCommitteeSize,

    -- * Hashing
    Hashed' (..),
    Hashed,
    unhashed,
    makeHashed,

    -- * Regenesis
    GenesisIndex (..),

    -- * Protocol version
    module Concordium.Types.ProtocolVersion,
    module Concordium.Types.ProtocolVersion.JustForCPV1,

    -- * Account address identifications.
    AccountAddressEq (..),
    accountAddressEmbed,
    accountAddressPrefixSize,
    createAlias,
) where

import Data.Data (Data, Typeable)
import Data.Scientific
import Foreign.Storable

import Concordium.Common.Amount
import Concordium.Common.Time
import Concordium.Constants
import qualified Concordium.Crypto.BlockSignature as Sig
import qualified Concordium.Crypto.BlsSignature as Bls
import qualified Concordium.Crypto.ByteStringHelpers as BSH
import Concordium.Crypto.EncryptedTransfers
import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.Crypto.SignatureScheme (SchemeId)
import qualified Concordium.Crypto.VRF as VRF
import Concordium.ID.Types
import Concordium.Types.Block
import Concordium.Types.HashableTo
import Concordium.Types.ProtocolVersion
import Concordium.Types.ProtocolVersion.JustForCPV1
import Concordium.Types.SmartContracts
import qualified Data.FixedByteString as FBS

import Control.Exception (assert)
import Control.Monad
import Control.Monad.Except

import Data.Bits
import Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Short as BSS
import Data.Foldable
import Data.Hashable (Hashable (..))
import Data.Ratio
import qualified Data.Sequence as Seq
import Data.Word

import Data.Aeson as AE
import Data.Aeson.TH

import Data.Time
import Data.Time.Clock.POSIX

import qualified Data.Text as T
import qualified Data.Text.Encoding as T

import qualified Data.Serialize as S
import qualified Data.Serialize.Get as G
import qualified Data.Serialize.Put as P

import Lens.Micro.Platform

import Text.Read (readMaybe)

import Test.QuickCheck (Arbitrary, choose)
import Test.QuickCheck.Arbitrary (Arbitrary (arbitrary))

-- |A value equipped with its hash.
data Hashed' h a = Hashed {_unhashed :: a, _hashed :: h}

-- |A value equipped with a 'Hash.Hash'.
type Hashed = Hashed' Hash.Hash

instance HashableTo h (Hashed' h a) where
    getHash = _hashed

-- |This lens allows for getting and setting the value inside a Hashed structure.
-- If a value is updated the new hash is recomputed automatically.
unhashed :: (HashableTo h a) => Lens' (Hashed' h a) a
unhashed f h = makeHashed <$> f (_unhashed h)

-- |Construct a hashed value, given that the value is of a hashable type.
makeHashed :: HashableTo h a => a -> Hashed' h a
makeHashed v = Hashed v (getHash v)

instance Eq h => Eq (Hashed' h a) where
    a == b = _hashed a == _hashed b

instance (Eq h, Ord a) => Ord (Hashed' h a) where
    compare a b = compare (_unhashed a) (_unhashed b)

instance (Show a) => Show (Hashed' h a) where
    show = show . _unhashed

-- * Types related to bakers.

-- |The ID of a baker, which is the index of its account.
newtype BakerId = BakerId {bakerAccountIndex :: AccountIndex}
    deriving (Eq, Ord, Num, Enum, Bounded, Real, Hashable, Read, Show, Integral, FromJSON, ToJSON, Bits, S.Serialize) via AccountIndex

-- |The ID of a delegator, which is the index of its account.
newtype DelegatorId = DelegatorId {delegatorAccountIndex :: AccountIndex}
    deriving (Eq, Ord, Num, Enum, Bounded, Real, Hashable, Read, Show, Integral, FromJSON, ToJSON, Bits, S.Serialize) via AccountIndex

type LeadershipElectionNonce = Hash.Hash
type BakerSignVerifyKey = Sig.VerifyKey
type BakerSignPrivateKey = Sig.KeyPair
type BakerElectionVerifyKey = VRF.PublicKey
type BakerElectionPrivateKey = VRF.KeyPair
type BakerAggregationVerifyKey = Bls.PublicKey
type BakerAggregationPrivateKey = Bls.SecretKey
type BakerAggregationProof = Bls.Proof
type LotteryPower = Ratio Amount

-- |A wrapper type over units that are measured as parts per 100000.
-- This wrapper will be used by both @AmountFraction@ and @ElectionDifficulty@.
-- It was agreed in tokenomics discussions to be sufficient.
newtype PartsPerHundredThousands = PartsPerHundredThousands {partsPerHundredThousand :: Word32}
    deriving newtype (Eq, Ord, Num, Real, Enum, Integral)

hundredThousand :: Word32
hundredThousand = 100000

instance S.Serialize PartsPerHundredThousands where
    put (PartsPerHundredThousands f) = S.putWord32be f
    get = do
        f <- S.getWord32be
        unless (f <= hundredThousand) $ fail "Parts per hundred thousandths out of bounds"
        return (PartsPerHundredThousands f)

instance Show PartsPerHundredThousands where
    show (PartsPerHundredThousands f) = show (fromIntegral f / 100000 :: Double)

instance ToJSON PartsPerHundredThousands where
    toJSON (PartsPerHundredThousands f) = Number (scientific (fromIntegral f) (-5))

instance FromJSON PartsPerHundredThousands where
    parseJSON (Number s0) = do
        let s = normalize s0
        let ex = base10Exponent s
        unless (ex <= 0 && ex >= -5) $ fail "Precision out of bounds"
        let v = coefficient s * 10 ^ (5 + ex)
        unless (v >= 0 && v <= fromIntegral hundredThousand) $ fail "Fraction out of bounds"
        return (PartsPerHundredThousands (fromIntegral v))
    parseJSON _ = fail "Expected number"

instance Arbitrary PartsPerHundredThousands where
    arbitrary = PartsPerHundredThousands <$> choose (0, hundredThousand)

-- |Make a 'PartsPerHundredThousands'.
makePartsPerHundredThousands ::
    -- |Hundred thousandths
    Word32 ->
    PartsPerHundredThousands
makePartsPerHundredThousands v = assert (v <= hundredThousand) (PartsPerHundredThousands v)

-- |Add two PartsPerHundredThousands.
addPartsPerHundredThousands :: PartsPerHundredThousands -> PartsPerHundredThousands -> Maybe PartsPerHundredThousands
addPartsPerHundredThousands (PartsPerHundredThousands a) (PartsPerHundredThousands b)
    | a + b <= hundredThousand = Just (PartsPerHundredThousands (a + b))
    | otherwise = Nothing

-- |Compute @1 - f@.
complementPartsPerHundredThousands :: PartsPerHundredThousands -> PartsPerHundredThousands
complementPartsPerHundredThousands (PartsPerHundredThousands a) = PartsPerHundredThousands (hundredThousand - a)

-- |Compute a fraction of an amount, with the fraction given as parts per 100000.
-- The amount is rounded down to the nearest microGTU.
takeFractionFromPartsPerHundredThousands :: PartsPerHundredThousands -> Amount -> Amount
takeFractionFromPartsPerHundredThousands f = fromInteger . (`div` 100000) . (toInteger (partsPerHundredThousand f) *) . toInteger

partsPerHundredThousandsToRational :: PartsPerHundredThousands -> Rational
partsPerHundredThousandsToRational f = toInteger (partsPerHundredThousand f) % 100000

-- |A unicode representation of a Url.
-- The Utf8 encoding of the Url must be at most 'maxUrlTextLength' bytes.
newtype UrlText = UrlText T.Text
    deriving newtype (Eq, Show)

-- |The maximum allowed length of a 'UrlText' in bytes (Utf8 encoded).
maxUrlTextLength :: Word16
maxUrlTextLength = 2048

instance S.Serialize UrlText where
    put (UrlText url)
        | len <= fromIntegral maxUrlTextLength = do
            S.putWord16be (fromIntegral len)
            S.putByteString enc
        | otherwise = error "UrlText is too long"
      where
        enc = T.encodeUtf8 url
        len = BS.length enc
    get = do
        len <- S.getWord16be
        when (len > maxUrlTextLength) $
            fail ("UrlText is too long (" ++ show len ++ " > " ++ show maxUrlTextLength ++ ")")
        bytes <- S.getByteString (fromIntegral len)
        case T.decodeUtf8' bytes of
            Left e -> fail (show e)
            Right r -> return (UrlText r)

instance AE.ToJSON UrlText where
    toJSON (UrlText t) = AE.toJSON t
    toEncoding (UrlText t) = AE.toEncoding t

instance AE.FromJSON UrlText where
    parseJSON = AE.withText "URL" $ \t -> do
        let len = BS.length (T.encodeUtf8 t)
        when (len > fromIntegral maxUrlTextLength) $
            fail ("UrlText is too long (" ++ show len ++ " > " ++ show maxUrlTextLength ++ ")")
        return (UrlText t)

emptyUrlText :: UrlText
emptyUrlText = UrlText ""

-- |Due to limitations on the ledger, there has to be some restriction on the
-- precision of the input for updating ElectionDifficult. For this purpose,
-- we will consider the parameter on the ChainUpdate as parts per 100000 which
-- should probably give enough precision.
--
-- This value will be converted into a Double when checking the election probability.
-- The value must be in the range [0,100000).
newtype ElectionDifficulty = ElectionDifficulty {edPartsPerHundredThousands :: PartsPerHundredThousands}
    deriving (Eq, Ord, Show, ToJSON, FromJSON, S.Serialize, Num, Integral, Enum, Real) via PartsPerHundredThousands

instance HashableTo Hash.Hash ElectionDifficulty where
    getHash = Hash.hash . S.encode

instance Monad m => MHashableTo m Hash.Hash ElectionDifficulty

-- |Make an election difficulty fraction.
-- The numerator (Word32) must be strictly less than 100000. This function will raise an exception otherwise.
makeElectionDifficulty ::
    Word32 ->
    ElectionDifficulty
makeElectionDifficulty v = let ppht = makePartsPerHundredThousands v in assert (ppht < 100000) $ ElectionDifficulty ppht

-- |Same as `makeElectionDifficulty`, but does not check its precondition.
makeElectionDifficultyUnchecked ::
    Word32 ->
    ElectionDifficulty
makeElectionDifficultyUnchecked = ElectionDifficulty . PartsPerHundredThousands

-- |Convert election difficulty to an IEEE754 double. In general this involves
-- some amount of rounding. Since the numerator of election difficulty is at
-- most 32-bits it can be fully represented as a Double without any loss of
-- precision. Thus the only source of rounding is division by 100000 which is
-- very small.
-- The maximum absolute error for any value of is about 7 * 10^-12.
getDoubleFromElectionDifficulty :: ElectionDifficulty -> Double
getDoubleFromElectionDifficulty = (/ 100000) . fromIntegral

-- |A sequential index of each finalization on a chain.
-- The genesis block has finalization index 0.
-- Note that this is not comparable with block height, since finalization does not occur at every
-- level of the chain.
newtype FinalizationIndex = FinalizationIndex {theFinalizationIndex :: Word64}
    deriving (Eq, Ord, Num, Real, Enum, Integral, Show, ToJSON, FromJSON) via Word64

instance S.Serialize FinalizationIndex where
    put (FinalizationIndex w) = S.putWord64be w
    get = FinalizationIndex <$> S.getWord64be

type FinalizationCommitteeSize = Word32

-- |An exchange rate (e.g. uGTU/Euro or Euro/Energy).
-- Infinity and zero are disallowed.
newtype ExchangeRate = ExchangeRate (Ratio Word64)
    deriving newtype (Eq, Ord, Num, Real, Show, Fractional, ToJSON)

-- |We require the serialization to be in reduced form to ensure
-- that an exchange rate has a unique serialized representation.
instance S.Serialize ExchangeRate where
    put (ExchangeRate r) =
        assert (numerator r /= 0 && denominator r /= 0) $
            S.put (numerator r) >> S.put (denominator r)
    get = do
        num <- S.get
        den <- S.get
        if num == 0 || den == 0 || gcd num den /= 1
            then fail "Invalid exchange rate"
            else return $ ExchangeRate (num % den)

instance FromJSON ExchangeRate where
    parseJSON v = do
        r <- parseJSON v
        if numerator r == 0 || denominator r == 0
            then fail "Invalid exchange rate"
            else return $ ExchangeRate r

instance HashableTo Hash.Hash ExchangeRate where
    getHash = Hash.hash . S.encode

instance Monad m => MHashableTo m Hash.Hash ExchangeRate

-- |Energy to GTU conversion rate in microGTU per Energy.
type EnergyRate = Rational

-- |Compute the exchange rate of microGTU per Energy from the
-- rate of microGTU per Euro and the rate of Euros per Energy.
computeEnergyRate ::
    -- |microGTU per Euro
    ExchangeRate ->
    -- |Euros per Energy
    ExchangeRate ->
    EnergyRate
computeEnergyRate microGTUPerEuro euroPerEnergy = toRational microGTUPerEuro * toRational euroPerEnergy

-- |Compute the cost of energy at a given rate.
-- This rounds up to the nearest microGTU.
computeCost ::
    EnergyRate ->
    Energy ->
    Amount
computeCost rate energy = ceiling (rate * fromIntegral energy)

-- * Minting and rewards

-- |A base-10 floating point number representation.
-- The value is @mrMantissa * 10^(-mrExponent)@.
--
-- At least 6 significant figures were required by the specification,
-- and 'Word32' provides 9.  Exponent values greater than about
-- 29 will not be necessary, since such a rate will be effectively
-- 0 (when we compute the amount that is minted based on a 64-bit
-- value as the current number of GTUs.)
data MintRate = MintRate
    { mrMantissa :: !Word32,
      mrExponent :: !Word8
    }

instance Eq MintRate where
    mr1 == mr2 = mrMantissa m1' == mrMantissa m2' && mrExponent m1' == mrExponent m2'
      where
        n mr@MintRate{..}
            | mrMantissa == 0 = MintRate 0 0
            | let (d, m) = mrMantissa `divMod` 10,
              m == 0,
              mrExponent > 0 =
                n (MintRate d (mrExponent - 1))
            | otherwise = mr
        m1' = n mr1
        m2' = n mr2

instance Show MintRate where
    show MintRate{..} = show mrMantissa ++ "e-" ++ show mrExponent

instance S.Serialize MintRate where
    put MintRate{..} = S.putWord32be mrMantissa >> S.putWord8 mrExponent
    get = do
        mrMantissa <- S.getWord32be
        mrExponent <- S.getWord8
        return MintRate{..}

instance ToJSON MintRate where
    toJSON MintRate{..} = Number (scientific (toInteger mrMantissa) (-fromIntegral mrExponent))

instance FromJSON MintRate where
    parseJSON (Number s0) = do
        let s = normalize s0
        unless (coefficient s >= 0 && coefficient s <= toInteger (maxBound :: Word32)) $ fail "Coefficient out of bounds"
        unless (base10Exponent s <= 0 && base10Exponent s >= -(fromIntegral (maxBound :: Word8))) $ fail "Exponent out of bounds"
        return
            MintRate
                { mrMantissa = fromInteger (coefficient s),
                  mrExponent = fromIntegral (-(base10Exponent s))
                }
    parseJSON _ = fail "Not a number"

instance HashableTo Hash.Hash MintRate where
    getHash = Hash.hash . S.encode

instance Monad m => MHashableTo m Hash.Hash MintRate

instance Arbitrary MintRate where
    arbitrary = do
        mrMantissa <- arbitrary
        let mantissaDigits = ceiling . logBase (10 :: Double) . fromIntegral $ mrMantissa
        -- By making the exponent no less than the number of decimal digits in the mantissa, we assure
        -- that the mint rate value stays below 1. As per comment for the `MintRate` definition,
        -- exponents above 29 aren't used in practice.
        mrExponent <- choose (mantissaDigits, 29)
        return MintRate{..}

-- |Compute an amount minted at a given rate.
-- The amount is rounded down to the nearest microGTU.
mintAmount :: MintRate -> Amount -> Amount
{-# INLINE mintAmount #-}
mintAmount mr = fromInteger . (`div` (10 ^ mrExponent mr)) . (toInteger (mrMantissa mr) *) . toInteger

-- |A fraction in [0,1] of an 'Amount', represented as parts per 100000.
newtype AmountFraction = AmountFraction {rfPartsPerHundredThousands :: PartsPerHundredThousands}
    deriving newtype (Eq, Ord, Show, ToJSON, FromJSON, S.Serialize, Arbitrary)

makeAmountFraction ::
    Word32 ->
    AmountFraction
makeAmountFraction = AmountFraction . makePartsPerHundredThousands

addAmountFraction :: AmountFraction -> AmountFraction -> Maybe AmountFraction
addAmountFraction (AmountFraction a) (AmountFraction b) = AmountFraction <$> addPartsPerHundredThousands a b

-- |Compute @1 - f@.
complementAmountFraction :: AmountFraction -> AmountFraction
complementAmountFraction (AmountFraction f) = AmountFraction $ complementPartsPerHundredThousands f

-- |Compute a fraction of an amount.
-- The amount is rounded down to the nearest microGTU.
takeFraction :: AmountFraction -> Amount -> Amount
takeFraction (AmountFraction f) = takeFractionFromPartsPerHundredThousands f

fractionToRational :: AmountFraction -> Rational
fractionToRational (AmountFraction f) = partsPerHundredThousandsToRational f

-- |The commission rates charged by a pool owner.
data CommissionRates = CommissionRates
    { -- |Fraction of finalization rewards charged by the pool owner.
      _finalizationCommission :: !AmountFraction,
      -- |Fraction of baking rewards charged by the pool owner.
      _bakingCommission :: !AmountFraction,
      -- |Fraction of transaction rewards charged by the pool owner.
      _transactionCommission :: !AmountFraction
    }
    deriving (Eq, Show)

-- Note: lenses are derived at the end of the file.

instance S.Serialize CommissionRates where
    put CommissionRates{..} = do
        S.put _finalizationCommission
        S.put _bakingCommission
        S.put _transactionCommission
    get = do
        _finalizationCommission <- S.get
        _bakingCommission <- S.get
        _transactionCommission <- S.get
        return CommissionRates{..}

instance ToJSON CommissionRates where
    toJSON CommissionRates{..} =
        object
            [ "finalizationCommission" AE..= _finalizationCommission,
              "bakingCommission" AE..= _bakingCommission,
              "transactionCommission" AE..= _transactionCommission
            ]

instance FromJSON CommissionRates where
    parseJSON = withObject "CommissionRates" $ \o -> do
        _finalizationCommission <- o .: "finalizationCommission"
        _bakingCommission <- o .: "bakingCommission"
        _transactionCommission <- o .: "transactionCommission"
        return CommissionRates{..}

type VoterId = Word64
type VoterVerificationKey = Sig.VerifyKey
type VoterVRFPublicKey = VRF.PublicKey
type VoterAggregationVerifyKey = Bls.PublicKey
type VoterSignKey = Sig.SignKey
type VoterAggregationPrivateKey = Bls.SecretKey
newtype VoterPower = VoterPower AmountUnit
    deriving newtype (Eq, Ord, Num, Enum, Bounded, Real, Show, Integral, S.Serialize)

-- * Blockchain specific types.

-- Eventually these will be replaced by types given by the global store.
-- For now they are placeholders

-- |The identifier associated with an account.
data AccountIdentifier
    = -- |Given credential registration id as an identifier.
      CredRegID !RawCredentialRegistrationID
    | -- |Given address as an identifier. Multiple addresses may refer to the same account.
      AccAddress !AccountAddress
    | -- |Given index as an identifier.
      AccIndex !AccountIndex

-- |Decode a null-terminated string as either an account address (base-58), account index (AccountIndex) or a
-- credential registration ID (base-16).
decodeAccountIdentifier :: ByteString -> Maybe AccountIdentifier
decodeAccountIdentifier bs =
    case addressFromBytes bs of
        Left _ ->
            case BSH.bsDeserializeBase16 bs of
                Nothing -> AccIndex <$> readMaybe (BS.unpack bs)
                Just cid -> Just $ CredRegID cid
        Right acc -> Just $ AccAddress acc

-- |The index of an account. Starting with 0,
-- each account is allocated a sequential @AccountIndex@
-- when it is created.  For the most part, this is only
-- used internally.  However, it is indirectly exposed through
-- 'BakerId'.
newtype AccountIndex = AccountIndex Word64
    deriving (Eq, Ord, Num, Enum, Bounded, Real, Hashable, Read, Show, Integral, FromJSON, ToJSON, Bits) via Word64

instance S.Serialize AccountIndex where
    get = AccountIndex <$> G.getWord64be
    put (AccountIndex i) = P.putWord64be i

instance HashableTo Hash.Hash AccountIndex where
    getHash = Hash.hash . S.encode

instance Monad m => MHashableTo m Hash.Hash AccountIndex

-- |Unique module reference.
newtype ModuleRef = ModuleRef {moduleRef :: Hash.Hash}
    deriving (Eq, Ord, Hashable, Typeable, Data)
    deriving (FromJSON, ToJSON, Read) via Hash.Hash

instance Show ModuleRef where
    show (ModuleRef m) = show m

instance S.Serialize ModuleRef where
    get = ModuleRef <$> S.get
    put (ModuleRef mref) = S.put mref

-- |An address is either a contract or account.
data Address
    = AddressAccount !AccountAddress
    | AddressContract !ContractAddress
    deriving (Eq)

instance S.Serialize Address where
    get = do
        h <- G.getWord8
        case h of
            0 -> AddressAccount <$> S.get
            1 -> AddressContract <$> S.get
            _ -> fail "Only two types of addresses are supported."

    put (AddressAccount acc) = P.putWord8 0 <> S.put acc
    put (AddressContract cnt) = P.putWord8 1 <> S.put cnt

instance Show Address where
    show (AddressAccount a) = show a
    show (AddressContract a) = show a

-- | Time in seconds since the unix epoch
newtype TransactionTime = TransactionTime {ttsSeconds :: Word64}
    deriving (Show, Read, Eq, Num, Ord, FromJSON, ToJSON, Real, Enum, Integral) via Word64

instance S.Serialize TransactionTime where
    put = P.putWord64be . ttsSeconds
    get = TransactionTime <$> G.getWord64be

-- |Get time in seconds since the unix epoch.
getTransactionTime :: IO TransactionTime
getTransactionTime = utcTimeToTransactionTime <$> getCurrentTime

utcTimeToTransactionTime :: UTCTime -> TransactionTime
utcTimeToTransactionTime = floor . utcTimeToPOSIXSeconds

-- | Expiry time of a transaction in seconds since the epoch
type TransactionExpiryTime = TransactionTime

-- | Convert a 'TransactionTime' (seconds since epoch) to a
-- 'Timestamp' (milliseconds since epoch).
transactionTimeToTimestamp :: TransactionTime -> Timestamp
transactionTimeToTimestamp (TransactionTime x) = Timestamp (1000 * x)

-- |Check if a transaction expiry time precedes a given timestamp.
transactionExpired :: TransactionExpiryTime -> Timestamp -> Bool
transactionExpired (TransactionTime x) (Timestamp t) = 1000 * x < t

-- |Type representing a difference between amounts.
newtype AmountDelta = AmountDelta {amountDelta :: Integer}
    deriving (Eq, Ord, Show, Enum, Num, Integral, Real)

amountToDelta :: Amount -> AmountDelta
amountToDelta = fromIntegral

amountDiff :: Amount -> Amount -> AmountDelta
amountDiff amt1 amt2 = fromIntegral amt1 - fromIntegral amt2

applyAmountDelta :: AmountDelta -> Amount -> Amount
applyAmountDelta del amt =
    assert (amt' >= fromIntegral (minBound :: Amount)) $
        assert (amt' <= fromIntegral (maxBound :: Amount)) $
            fromIntegral amt'
  where
    amt' = fromIntegral amt + del

-- |The type used to count exact execution cost. This cost is then converted to
-- amounts in some way.
newtype Energy = Energy {_energy :: Word64}
    deriving (Show, Read, Eq, Enum, Ord, Num, Real, Integral, Hashable, Bounded, FromJSON, ToJSON) via Word64

instance S.Serialize Energy where
    get = Energy <$> G.getWord64be
    put (Energy v) = P.putWord64be v

newtype Nonce = Nonce Word64
    deriving (Show, Read, Eq, Ord, Num, Enum, FromJSON, ToJSON) via Word64

instance S.Serialize Nonce where
    put (Nonce w) = P.putWord64be w
    get = Nonce <$> G.getWord64be

minNonce :: Nonce
minNonce = 1

-- |Data type for memos that can be added to transfers.
-- Max length of 'maxMemoSize' is assumed.
-- Create new values with 'memoFromBSS' to ensure assumed properties.
--
-- Note that the ToJSON instance of this type is derived, based on hex encoding.
-- The FromJSON instance is manually implemented to ensure length limits.
newtype Memo = Memo BSS.ShortByteString
    deriving (Eq)
    deriving (AE.ToJSON, Show) via BSH.ByteStringHex

-- |Maximum size for 'Memo'.
maxMemoSize :: Int
maxMemoSize = 256

tooBigErrorString :: String -> Int -> Int -> String
tooBigErrorString name len maxSize = "Size of the " ++ name ++ " (" ++ show len ++ " bytes) exceeds maximum allowed size (" ++ show maxSize ++ " bytes)."

-- |Construct 'Memo' from a 'BSS.ShortByteString'.
-- Fails if the length exceeds 'maxMemoSize'.
memoFromBSS :: MonadError String m => BSS.ShortByteString -> m Memo
memoFromBSS bss =
    if len <= maxMemoSize
        then return . Memo $ bss
        else throwError $ tooBigErrorString "memo" len maxMemoSize
  where
    len = BSS.length bss

instance S.Serialize Memo where
    put (Memo bss) = do
        S.putWord16be . fromIntegral . BSS.length $ bss
        S.putShortByteString bss

    get = G.label "Memo" $ do
        l <- fromIntegral <$> S.getWord16be
        unless (l <= maxMemoSize) $ fail $ tooBigErrorString "memo" l maxMemoSize
        Memo <$> S.getShortByteString l

instance AE.FromJSON Memo where
    parseJSON v = do
        (BSH.ByteStringHex bss) <- AE.parseJSON v
        case memoFromBSS bss of
            Left err -> fail err
            Right rd -> return rd

-- |Data type for registering data on chain.
-- Max length of 'maxRegisteredDataSize' is assumed.
-- Create new values with 'registeredDataFromBSS' to ensure assumed properties.
newtype RegisteredData = RegisteredData BSS.ShortByteString
    deriving (Eq)
    deriving (AE.ToJSON, Show) via BSH.ByteStringHex

-- |Maximum size for 'RegisteredData'.
maxRegisteredDataSize :: Int
maxRegisteredDataSize = 256

-- |Construct 'RegisteredData' from a 'BSS.ShortByteString'.
-- Fails if the length exceeds 'maxRegisteredDataSize'.
registeredDataFromBSS :: MonadError String m => BSS.ShortByteString -> m RegisteredData
registeredDataFromBSS bss =
    if len <= maxRegisteredDataSize
        then return . RegisteredData $ bss
        else throwError $ tooBigErrorString "data" len maxRegisteredDataSize
  where
    len = BSS.length bss

-- Uses two bytes for length to be more future-proof.
instance S.Serialize RegisteredData where
    put (RegisteredData bss) = do
        S.putWord16be . fromIntegral . BSS.length $ bss
        S.putShortByteString bss

    get = do
        l <- fromIntegral <$> S.getWord16be
        unless (l <= maxRegisteredDataSize) $ fail $ tooBigErrorString "data" l maxRegisteredDataSize
        RegisteredData <$> S.getShortByteString l

instance AE.FromJSON RegisteredData where
    parseJSON v = do
        (BSH.ByteStringHex bss) <- AE.parseJSON v
        case registeredDataFromBSS bss of
            Left err -> fail err
            Right rd -> return rd

-- * Account encrypted amount.

-- | Encrypted amounts stored on an account.
data AccountEncryptedAmount = AccountEncryptedAmount
    { -- | Encrypted amount that is a result of this accounts' actions.
      -- In particular this list includes the aggregate of
      --
      -- - remaining amounts that result when transferring to public balance
      -- - remaining amounts when transferring to another account
      -- - encrypted amounts that are transferred from public balance
      --
      -- When a transfer is made all of these must always be used.
      _selfAmount :: !EncryptedAmount,
      -- | Starting index for incoming encrypted amounts. If there is an aggregated amount
      -- present, this index is the one for such amount. Otherwise it refers to the first
      -- amount in the list of incoming encrypted amounts.
      _startIndex :: !EncryptedAmountAggIndex,
      -- |If 'Just', the amount that has resulted from aggregating other amounts and the
      -- number of aggregated amounts (must be at least 2 if present).
      _aggregatedAmount :: !(Maybe (EncryptedAmount, Word32)),
      -- | Amounts starting at @startIndex@ (or at @startIndex + 1@ if an aggregated amount is present).
      -- They are assumed to be numbered sequentially.
      -- This list (plus the optionally present aggregated amount) will never contain more than
      -- 'maxNumIncoming' values.
      _incomingEncryptedAmounts :: !(Seq.Seq EncryptedAmount)
    }
    deriving (Eq, Show)

-- |Check whether the account encrypted amount is zero. This checks that there
-- are no incoming amounts, and that the self amount is a specific encryption of
-- 0, with randomness 0.
isZeroAccountEncryptedAmount :: AccountEncryptedAmount -> Bool
isZeroAccountEncryptedAmount AccountEncryptedAmount{..} =
    _aggregatedAmount == Nothing
        && null _incomingEncryptedAmounts
        && isZeroEncryptedAmount _selfAmount

-- | When serializing to a JSON, we will put the aggregated amount if present at the
-- beginning of the `"incomingAmounts"` field.
instance AE.ToJSON AccountEncryptedAmount where
    toJSON AccountEncryptedAmount{..} =
        AE.object $
            [ "selfAmount" AE..= _selfAmount,
              "startIndex" AE..= _startIndex,
              "incomingAmounts" AE..= case _aggregatedAmount of
                Nothing -> _incomingEncryptedAmounts
                Just (e, _) -> e Seq.:<| _incomingEncryptedAmounts
            ]
                ++ aggregated
      where
        aggregated = case _aggregatedAmount of
            Nothing -> []
            Just (_, n) -> ["numAggregated" AE..= n]

-- | When deserializing from JSON, if the field `"numAggregated"` is present, we will
-- interpret the first item in the `"incomingAmounts"` list as the aggregated amount.
instance AE.FromJSON AccountEncryptedAmount where
    parseJSON = AE.withObject "AccountEncryptedAmount" $ \obj -> do
        _selfAmount <- obj AE..: "selfAmount"
        _startIndex <- obj AE..: "startIndex"
        incomingEncryptedAmounts <- obj AE..: "incomingAmounts"
        numAggregated <- obj AE..:? "numAggregated"
        (_aggregatedAmount, _incomingEncryptedAmounts) <-
            case numAggregated of
                Nothing -> return (Nothing, incomingEncryptedAmounts)
                Just n
                    | n > 1 -> case incomingEncryptedAmounts of
                        agg Seq.:<| rest ->
                            return (Just (agg, n), rest)
                        _ -> fail "The list of amounts doesn't contain any amounts but it claims some amounts have been aggregated"
                    | otherwise -> fail "Cannot have less than 2 amounts aggregated"
        return AccountEncryptedAmount{..}

-- |Initial encrypted amount on a newly created account.
initialAccountEncryptedAmount :: AccountEncryptedAmount
initialAccountEncryptedAmount =
    AccountEncryptedAmount
        { _selfAmount = mempty,
          _startIndex = 0,
          _incomingEncryptedAmounts = Seq.empty,
          _aggregatedAmount = Nothing
        }

instance S.Serialize AccountEncryptedAmount where
    put AccountEncryptedAmount{..} = do
        S.put _selfAmount
        S.put _startIndex
        S.putWord32be (fromIntegral (Seq.length _incomingEncryptedAmounts))
        mapM_ S.put _incomingEncryptedAmounts
        case _aggregatedAmount of
            Nothing -> S.putWord32be 0
            Just (e, n) -> do
                S.putWord32be n
                S.put e

    get = do
        _selfAmount <- S.get
        _startIndex <- S.get
        len <- S.getWord32be
        _incomingEncryptedAmounts <- Seq.fromList <$> replicateM (fromIntegral len) S.get
        mNumAggregated <- S.getWord32be
        case mNumAggregated of
            0 -> return AccountEncryptedAmount{_aggregatedAmount = Nothing, ..}
            n | n >= 2 -> do
                e <- S.get
                return AccountEncryptedAmount{_aggregatedAmount = Just (e, n), ..}
            _ -> fail "numAggregated must be at least 2, if non-zero."

makeLenses ''AccountEncryptedAmount

-- |Get the list of incoming amounts ordered by index, starting at `_startIndex`.
getIncomingAmountsList :: AccountEncryptedAmount -> [EncryptedAmount]
getIncomingAmountsList AccountEncryptedAmount{..} =
    toList $ case _aggregatedAmount of
        Nothing -> _incomingEncryptedAmounts
        Just (e, _) -> e Seq.:<| _incomingEncryptedAmounts

-- |Size of the transaction payload.
newtype PayloadSize = PayloadSize {thePayloadSize :: Word32}
    deriving (Eq, Show, Ord, Num, Real, Enum, Integral, FromJSON, ToJSON) via Word32

-- |Check that the payload size is within bounds of what the protocol version allows.
validatePayloadSize :: SProtocolVersion pv -> PayloadSize -> Bool
validatePayloadSize spv PayloadSize{..} = thePayloadSize <= maxPayloadSize spv

-- |Serialization format as specified
--
-- * @SPEC: <$DOCS/Transactions#transaction-header>
instance S.Serialize PayloadSize where
    put (PayloadSize n) = S.putWord32be n
    get = PayloadSize <$> S.getWord32be

-- |Serialized payload of the transaction
newtype EncodedPayload = EncodedPayload {_spayload :: BSS.ShortByteString}
    deriving (Eq, Show)

-- |There is no corresponding getter (to fit into the Serialize instance) since
-- encoded payload does not encode its own length. See 'getPayload' below.
putEncodedPayload :: P.Putter EncodedPayload
putEncodedPayload = P.putShortByteString . _spayload

-- |Get payload with given length.
getEncodedPayload :: PayloadSize -> G.Get EncodedPayload
getEncodedPayload (PayloadSize n) = EncodedPayload <$> G.getShortByteString (fromIntegral n)

payloadSize :: EncodedPayload -> PayloadSize
payloadSize = fromIntegral . BSS.length . _spayload

-- |Blockchain metadata as needed by contract execution.
newtype ChainMetadata = ChainMetadata
    { -- |Time at the beginning of the slot.
      slotTime :: Timestamp
    }

-- |Encode chain metadata for passing over FFI. Uses little-endian encoding
-- for integral values since that is what is expected on the other side of FFI.
-- This is deliberately not made into a serialize instance so that it is not accidentally
-- misused, since it differs in endianness from most other network-related serialization.
encodeChainMeta :: ChainMetadata -> ByteString
encodeChainMeta ChainMetadata{..} = S.runPut encoder
  where
    encoder = P.putWord64le (tsMillis slotTime)

-- |The hash of a transaction which is then signed.
-- (Naturally, this does not include the transaction signature.)
newtype TransactionSignHashV0 = TransactionSignHashV0 {v0TransactionSignHash :: Hash.Hash}
    deriving newtype (Eq, Ord, Show, S.Serialize, AE.ToJSON, AE.FromJSON, AE.FromJSONKey, AE.ToJSONKey, Read, Hashable)

type TransactionSignHash = TransactionSignHashV0

transactionSignHashToByteString :: TransactionSignHash -> ByteString
transactionSignHashToByteString = Hash.hashToByteString . v0TransactionSignHash

-- |Hash of a transaction including the signature.
-- (For credential deployments, there is no signature.)
newtype TransactionHashV0 = TransactionHashV0 {v0TransactionHash :: Hash.Hash}
    deriving newtype (Eq, Ord, Show, S.Serialize, AE.ToJSON, AE.FromJSON, AE.FromJSONKey, AE.ToJSONKey, Read, Hashable)

type TransactionHash = TransactionHashV0

-- These definitions __should__ be in Types.Block but due to some bugs related
-- to template haskell that is not possible. If we do move this, then
-- Types.Block must depend on some foreign functions (via the VRF/Sig modules)
-- which causes the AccountTransactionIndex template haskell derivation of
-- database schemas to fail.

-- |The type of a block hash. This should be independent of how the hash
-- is computed. Even if the hashing scheme changes over time, it should be
-- effectively impossible for two blocks on the same chain to have the same
-- 'BlockHash'.
--
-- (This type may need to change if the hash size changes or a different
-- hash function is used.)
newtype BlockHash = BlockHash {blockHash :: Hash.Hash}
    deriving newtype (Eq, Ord, Show, S.Serialize, ToJSON, FromJSON, FromJSONKey, ToJSONKey, Read, Hashable)

newtype StateHashV0 = StateHashV0 {v0StateHash :: Hash.Hash}
    deriving newtype (Eq, Ord, Show, S.Serialize, ToJSON, FromJSON, FromJSONKey, ToJSONKey, Read, Hashable)

type StateHash = StateHashV0

type BlockProof = VRF.Proof
type BlockSignature = Sig.Signature
type BlockNonce = VRF.Proof

-- |Compute the first slot at or above the given time.
transactionTimeToSlot ::
    -- |Genesis time
    Timestamp ->
    -- |Slot duration
    Duration ->
    -- |Time to convert
    TransactionTime ->
    Slot
transactionTimeToSlot genesis slotDur t
    | tt <= genesis = 0
    | otherwise = fromIntegral $ (tsMillis (tt - genesis - 1) `div` durationMillis slotDur) + 1
  where
    tt = transactionTimeToTimestamp t

-- |Type indicating the index of a (re)genesis block.
-- The initial genesis block has index @0@ and each subsequent regenesis
-- has an incrementally higher index.
newtype GenesisIndex = GenesisIndex Word32
    deriving (Show, Read, Eq, Enum, Ord, Num, Real, Integral, Hashable, Bounded, FromJSON, ToJSON, Storable) via Word32

instance S.Serialize GenesisIndex where
    put (GenesisIndex gi) = S.putWord32be gi
    get = GenesisIndex <$> S.getWord32be

-- |Equivalence class of account addresses. In protocol versions 1 and 2
-- addresses are in 1-1 correspondence with accounts. In protocol version 3 only
-- the first 29 bytes of the address uniquely identify an account. This type
-- wrapper is used to wrap account addresses and add different equality and
-- hashable instances so that we can identify transactions coming from different
-- addresses but the same account.
--
-- For backwards compatibility we retain the equality and hashable instances for
-- account addresses as they were since account addresses are compared in a few
-- places in the scheduler.
newtype AccountAddressEq = AccountAddressEq
    { aaeAddress :: AccountAddress
    }
    deriving (Show)

-- |Length of the account address prefix used when uniquely determining the account.
accountAddressPrefixSize :: Int
accountAddressPrefixSize = 29

{-# INLINE accountAddressEmbed #-}

-- |Embed an account address into its equivalence class.
accountAddressEmbed :: AccountAddress -> AccountAddressEq
accountAddressEmbed = AccountAddressEq

instance Eq AccountAddressEq where
    -- compare the first 29 bytes of the address
    AccountAddressEq (AccountAddress a1) == AccountAddressEq (AccountAddress a2) = FBS.unsafeCompareFixedByteStrings 0 accountAddressPrefixSize a1 a2 == EQ

instance Hashable AccountAddressEq where
    hashWithSalt s (AccountAddressEq (AccountAddress b)) = hashWithSalt s (FBS.unsafeReadWord64 b)
    {-# INLINE hashWithSalt #-}
    hash (AccountAddressEq (AccountAddress b)) = fromIntegral (FBS.unsafeReadWord64 b)
    {-# INLINE hash #-}

-- |Create an alias for the address using the counter. The counter is used
-- modulo 2^24, and the three bytes are appended in big endian order.
--
-- Examples
-- - @createAlias 2wkH4kHMn2WPndf8CxmsoFkX93ouZMJUwTBFSZpDCeNeGWa7dj (1 + 2 * 256 + 3 * 256^2) = 2wkH4kHMn2WPndf8CxmsoFkX93ouZMJUwTBFSZpDBez9cfL8oC@
-- - @createAlias 2wkH4kHMn2WPndf8CxmsoFkX93ouZMJUwTBFSZpDCeNeGWa7dj (1 + 2 * 256 + 3 * 256 * 256 + 4 * 256 * 256 * 256) = 2wkH4kHMn2WPndf8CxmsoFkX93ouZMJUwTBFSZpDBez9cfL8oC@
-- - @createAlias addr x = createAlias (createAlias addr y) x@ for any x and y
createAlias :: AccountAddress -> Word -> AccountAddress
createAlias (AccountAddress addr) count = AccountAddress ((addr .&. mask) .|. rest)
  where
    rest = FBS.encodeInteger (toInteger (count .&. 0xffffff))
    mask = complement (FBS.encodeInteger 0xffffff) -- mask to clear out the last three bytes of the addr

-- Template haskell derivations. At the end to get around staging restrictions.
$(deriveJSON defaultOptions{sumEncoding = TaggedObject{tagFieldName = "type", contentsFieldName = "address"}} ''Address)
makeLenses ''CommissionRates
