{-# LANGUAGE DerivingVia, ScopedTypeVariables, OverloadedStrings #-}
{-|
Module      : Concordium.Wasm
Description : Types used in the smart contract framework.

Basic types used in the Smart Contract Framework. A contract is a piece of
functionality that extends the base features that are built in the blockchain.

=Definition

A /Smart Contract Module/ is a set of /Contracts/. Each Contract has one @init@
method and zero or more @receive@ methods.

A /Module/ is received from the user in serialized wasm format
(i.e. 'WasmModule') and processed into an 'InstrumentedModule'. An
'InstrumentedModule' can then be instantiated using the associated
'ModuleInterface' which specifies the names of the exposed methods.

During its lifetime, a contract holds a 'ContractState' that can be interpreted
by the Interpreter and might contain variables used in the contract code.

Calling a method (both for a @receive@ and @init@ method) requires some
additional data that is specified in 'ReceiveContext' and 'InitContext'
respectively.

=Interpreter

The interpreter runs a method of the smart contract on a given 'ContractState'.

An execution of a contract can either be successful (which would generate a
'SuccessfulResultData') or fail (generating a 'ContractExecutionFailure'). If an
execution is successful, then an 'ActionsTree' is returned together with the new
'ContractState' and a list of events logged by the contract ('ContractEvent').
-}
module Concordium.Wasm (
  -- * Constants
  maxParameterLen,
  maxWasmModuleSize,

  -- * Modules
  -- ** Binary module
  --
  -- | A binary module contains the source of the contract in serialized wasm
  -- format. This source is not ready for execution and, after processing it
  -- into an 'InstrumentedModule', it should just be stored and retrieved on
  -- demand.
  ModuleSource(..),
  unsafeUseModuleSourceAsCStringLen,
  moduleSourceLength,
  WasmModule(..),
  getModuleRef,

  -- ** Instrumented module
  --
  -- | An instrumented module is a processed module that is ready to be
  -- instantiated and run.
  ModuleArtifact(..),
  InstrumentedModule(..),

  -- *** Methods
  --
  -- | A contract has one init method and several receive methods. A module can
  -- contain several contracts.
  InitName(..),
  isValidInitName,
  initContractName,
  ReceiveName(..),
  isValidReceiveName,
  contractAndFunctionName,
  Parameter(..),

  -- *** Module interface
  ModuleInterface(..),

  -- *** Contract state
  ContractState(..),
  ByteSize(..),
  contractStateSize,

  -- *** Contexts
  --
  -- | When calling a method on a contract, some context data is needed and has
  -- to be provided by the execution engine.
  InitContext(..),
  encodeInitContext,
  ReceiveContext(..),
  encodeReceiveContext,
  SenderPolicy(..),
  mkSenderPolicy,
  putSenderPolicies,

  -- * Interpreter

  -- ** Energy
  InterpreterEnergy(..),

  -- ** Interpreter outcome
  -- *** Successful execution
  ActionsTree(..),
  getActionsTree,
  ContractEvent(..),
  SuccessfulResultData(..),
  getSuccessfulResultData,
  -- *** Failed execution
  ContractExecutionFailure(..)
  ) where

import Control.Monad
import qualified Data.Aeson as AE
import qualified Data.ByteString as BS
import Data.ByteString(ByteString)
import qualified Data.ByteString.Base16 as BS16
import qualified Data.ByteString.Short as BSS
import Data.ByteString.Short(ShortByteString)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.Char (isPunctuation, isAlphaNum, isAscii)
import qualified Data.HashMap.Strict as HM
import Data.Hashable
import qualified Data.Map.Strict as Map
import Data.Serialize
import qualified Data.Set as Set
import qualified Data.Text as Text
import Data.Text(Text)
import qualified Data.Text.Encoding as Text
import Data.Time
import Data.Word
import Foreign.C (CStringLen)

import Concordium.Common.Time
import Concordium.Crypto.ByteStringHelpers(ByteStringHex(..))
import qualified Concordium.Crypto.SHA256 as H
import Concordium.ID.Types
import Concordium.Types
import Concordium.Types.HashableTo
import Concordium.Utils.Serialization

--------------------------------------------------------------------------------

-- |Maximum length of the parameter to init and receive methods.
maxParameterLen :: Word16
maxParameterLen = 1024

-- |Maximum module size.
maxWasmModuleSize :: Word32
maxWasmModuleSize = 65536 -- 65kB

--------------------------------------------------------------------------------

-- | The source of a contract in binary wasm format.
newtype ModuleSource = ModuleSource { moduleSource :: ByteString }
  deriving (Eq, Show)

instance Serialize ModuleSource where
  get = do
    len <- getWord32be
    unless (len <= maxWasmModuleSize) $ fail "Maximum module size exceeded."
    ModuleSource <$> getByteString (fromIntegral len)
  put = putByteStringWord32 . moduleSource

unsafeUseModuleSourceAsCStringLen :: ModuleSource -> (CStringLen -> IO a) -> IO a
unsafeUseModuleSourceAsCStringLen = unsafeUseAsCStringLen . moduleSource

moduleSourceLength :: ModuleSource -> Word64
moduleSourceLength = fromIntegral . BS.length . moduleSource

-- |Web assembly module in binary format.
data WasmModule = WasmModule {
  -- |Version of the Wasm standard and on-chain API this module corresponds to.
  wasmVersion :: Word32,
  -- |Source in binary wasm format.
  wasmSource :: ModuleSource
  } deriving(Eq, Show)

getModuleRef :: WasmModule -> ModuleRef
getModuleRef wm = ModuleRef (getHash wm)

instance Serialize WasmModule where
  put WasmModule{..} =
    putWord32be wasmVersion <>
    put wasmSource

  get = do
    wasmVersion <- getWord32be
    unless (wasmVersion == 0) $ fail "Unsupported Wasm module version."
    wasmSource <- get
    return WasmModule{..}

instance HashableTo H.Hash WasmModule where
  -- Hash the serialization directly, perhaps this needs to be revisited in the
  -- future.
  getHash wm = H.hash (encode wm)

--------------------------------------------------------------------------------

-- | A processed module artifact ready for execution.
newtype ModuleArtifact = ModuleArtifact { artifact :: ByteString }
    deriving (Eq, Show)

instance Serialize ModuleArtifact where
  put ma = putWord32be (fromIntegral (BS.length (artifact ma))) <>
           putByteString (artifact ma)

  get = do
    len <- getWord32be
    ModuleArtifact <$> getByteString (fromIntegral len)

-- |Web assembly module in binary format, instrumented with whatever it needs to
-- be instrumented with, and preprocessed to an executable format, ready to be
-- instantiated and run.
data InstrumentedModule = InstrumentedWasmModule {
  -- |Version of the Wasm standard and on-chain API this module corresponds to.
  imWasmVersion :: !Word32,
  -- |Source in binary wasm format.
  imWasmArtifact :: !ModuleArtifact
  } deriving(Eq, Show)

instance Serialize InstrumentedModule where
  put InstrumentedWasmModule{..} = do
    putWord32be imWasmVersion
    put imWasmArtifact

  get = InstrumentedWasmModule <$> getWord32be <*> get

--------------------------------------------------------------------------------

-- |Name of an init method inside a module.
newtype InitName = InitName { initName :: Text }
    deriving(Eq, Show, Ord)
    deriving(AE.ToJSON) via Text

-- |Check whether the given text is a valid init name.
-- This is the case if
--
-- * all characters are valid ascii characters in alphanumeric or punctuation classes
-- * the name does not contain @.@
-- * the name starts with `init_`
isValidInitName :: Text -> Bool
isValidInitName proposal =
  let hasValidCharacters = Text.all (\c -> isAscii c && (isAlphaNum c || isPunctuation c)) proposal
      hasDot = Text.any (== '.') proposal
  in "init_" `Text.isPrefixOf` proposal && hasValidCharacters && not hasDot

instance AE.FromJSON InitName where
  parseJSON = AE.withText "InitName" $ \initName -> do
    if isValidInitName initName then return InitName{..}
    else fail "Invalid init name."

instance Serialize InitName where
  put = putByteStringWord16 . Text.encodeUtf8 . initName
  get = do
    bs <- getByteStringWord16
    case Text.decodeUtf8' bs of
      Left _ -> fail "Not a valid utf-8 encoding."
      Right t | isValidInitName t -> return (InitName t)
              | otherwise -> fail "Not a valid init name."

-- |Name of a receive method inside a module.
newtype ReceiveName = ReceiveName { receiveName :: Text }
    deriving (Eq, Show, Ord)
    deriving(AE.ToJSON) via Text

-- |Check whether the given text is a valid receive name.
-- This is the case if
--
-- * all characters are valid ascii characters in alphanumeric or punctuation classes
-- * the name contains @.@
isValidReceiveName :: Text -> Bool
isValidReceiveName proposal =
  let hasValidCharacters = Text.all (\c -> isAscii c && (isAlphaNum c || isPunctuation c)) proposal
      hasDot = Text.any (== '.') proposal
  in hasValidCharacters && hasDot

-- |Extract the contract name from the init function name.
initContractName :: InitName -> Text
initContractName = Text.drop (Text.length "init_") . initName

-- |Extract the contract and function names from the receive name.
contractAndFunctionName :: ReceiveName -> (Text, Text)
contractAndFunctionName (ReceiveName n) = (cname, Text.drop 1 fname)
    where (cname, fname) = Text.span (/= '.') n

instance AE.FromJSON ReceiveName where
  parseJSON = AE.withText "ReceiveName" $ \receiveName -> do
    if isValidReceiveName receiveName then return ReceiveName{..}
    else fail "Invalid receive name."

instance Serialize ReceiveName where
  put = putByteStringWord16 . Text.encodeUtf8 . receiveName
  get = do
    bs <- getByteStringWord16
    case Text.decodeUtf8' bs of
      Left _ -> fail "Not a valid utf-8 encoding."
      Right t | isValidReceiveName t -> return (ReceiveName t)
              | otherwise -> fail $ "Not a valid receive name: " ++ Text.unpack t

-- |Parameter to either an init method or to a receive method.
-- The parameter is limited to 1kB in size. This is ensured
-- by deserialization methods.
newtype Parameter = Parameter { parameter :: ShortByteString }
    deriving(Eq, Show)
    deriving(AE.ToJSON, AE.FromJSON) via ByteStringHex

instance Serialize Parameter where
  put = putShortByteStringWord16 . parameter
  get = do
    len <- getWord16be
    unless (len <= maxParameterLen) $ fail "Parameter size exceeds limits."
    Parameter <$> getShortByteString (fromIntegral len)

--------------------------------------------------------------------------------

-- |A Wasm module interface with exposed entry-points.
data ModuleInterface = ModuleInterface {
  -- |Reference of the module on the chain.
  miModuleRef :: !ModuleRef,
  -- |Init methods exposed by this module.
  -- They should each be exposed with a type Amount -> Word32
  miExposedInit :: !(Set.Set InitName),
  -- |Receive methods exposed by this module, indexed by contract name.
  -- They should each be exposed with a type Amount -> Word32
  miExposedReceive :: !(Map.Map InitName (Set.Set ReceiveName)),
  -- |Module source in binary format, instrumented with whatever it needs to be instrumented with.
  miModule :: !InstrumentedModule,
  miModuleSize :: !Word64
  } deriving(Eq, Show)

instance Serialize ModuleInterface where
  get = do
    miModuleRef <- get
    miExposedInit <- getSafeSetOf get
    miExposedReceive <- getSafeMapOf get (getSafeSetOf get)
    miModule <- get
    miModuleSize <- getWord64be
    return ModuleInterface {..}
  put ModuleInterface{..} = do
    put miModuleRef
    putSafeSetOf put miExposedInit
    putSafeMapOf put (putSafeSetOf put) miExposedReceive
    put miModule
    putWord64be miModuleSize

-- |State of a smart contract. In general we don't know anything other than
-- it is a sequence of bytes.
-- FIXME: In the future this should be more structured allowing for more sharing.
newtype ContractState = ContractState {contractState :: BS.ByteString }
    deriving(Eq)

instance AE.ToJSON ContractState where
  toJSON ContractState{..} = AE.String (Text.decodeUtf8 (BS16.encode contractState))

-- The show instance just displays the bytes directly.
instance Show ContractState where
  show ContractState{..} = show (BS.unpack contractState)

-- |Type used to measure contract storage costs.
newtype ByteSize = ByteSize { _byteSize :: Word64 }
    deriving (Show, Read, Eq, Enum, Ord, Num, Real, Integral, Hashable, Bounded) via Word64

-- |It is assumed the type `a` can reliable represent 64-bit unsigned values.
-- It is intended to be used to automatically get the desired output type, using
-- something that is an instance of Num.
contractStateSize :: forall a . Integral a => ContractState -> a -> Maybe a
contractStateSize cs bs =
  if len <= bs then Just len
  else Nothing
  where len = fromIntegral (BS.length (contractState cs))

-- The serialize instance uses Word32 for length. This should be reasonable since
-- no instance should ever be able to produce a state bigger than 4GB.
instance Serialize ContractState where
  put ContractState{..} = do
    putWord32be (fromIntegral (BS.length contractState))
    putByteString contractState

  get = do
    len <- fromIntegral <$> getWord32be
    ContractState <$> getByteString len

instance HashableTo H.Hash ContractState where
  getHash cs = H.hash (encode cs)

--------------------------------------------------------------------------------

-- |Additional data needed specifically by the init method of the contract.
data InitContext = InitContext{
  -- |Origin of the transaction; who is initializing the contract.
  initOrigin :: !AccountAddress,
  -- |Policy of the
  icSenderPolicies :: ![SenderPolicy]
  }

-- |Encode into a bytestring, using little endian serialization where appropriate.
-- This should only be used when passing data to the smart-contracts engine.
encodeInitContext :: InitContext -> ByteString
encodeInitContext InitContext{..} =
  runPut $ put initOrigin <> putSenderPolicies icSenderPolicies

-- |Additional data needed specifically by the receive method of the contract.
data ReceiveContext = ReceiveContext
  { -- | The address of the account which initiated the top-level transaction.
    invoker :: !AccountAddress
    -- | The address of the contract being invoked.
  , selfAddress :: !ContractAddress
    -- | Amount on the smart contract instance just before the receive method is
    -- called.
  , selfBalance :: !Amount
    -- |Address of the account or contract who sent a message to the contract.
  , sender :: !Address
    -- |Owner of this smart contract instance.
  , owner :: !AccountAddress
    -- |Policy exposed to the smart contract. Either the policy of the sender account,
    -- or of the owner of the contract.
  , rcSenderPolicies :: ![SenderPolicy]
  }

-- |Encode into a bytestring, using little endian serialization where
-- appropriate.
encodeReceiveContext :: ReceiveContext -> ByteString
encodeReceiveContext ReceiveContext{..} = runPut encoder
  where encoder =
          put invoker <>
          putWord64le (_contractIndex (contractIndex selfAddress)) <>
          putWord64le (_contractSubindex (contractSubindex selfAddress)) <>
          putWord64le (_amount selfBalance) <>
          put sender <>
          put owner <>
          putSenderPolicies rcSenderPolicies

data SenderPolicy = SenderPolicy {
  -- |Identity of the identity provider who signed the identity object
  -- that created the policy.
  spIdentityProvider :: !IdentityProviderIdentity,
  -- |Beginning of the month where the identity object was created.
  spCreatedAt :: !Timestamp,
  -- |Beginning of the month where the identity object is no longer valid.
  spValidTo :: !Timestamp,
  -- |Attributes, by increasing order of the attribute tag.
  spItems :: ![(AttributeTag, AttributeValue)]
  }

mkSenderPolicy :: AccountCredential -> SenderPolicy
mkSenderPolicy ac =
    SenderPolicy{
       spCreatedAt = createdAtTs,
       spValidTo = validToTs,
       spItems = Map.toAscList (pItems credentialPolicy),
       spIdentityProvider = ipId ac
       }

    where credentialPolicy = policy ac
          createdAtTs =
            let ym = pCreatedAt credentialPolicy
                year = toInteger (ymYear ym)
                month = fromIntegral (ymMonth ym)
                expiryDay = fromGregorian year month 1 -- unchecked, always valid
            in utcTimeToTimestamp (UTCTime expiryDay 0)

          validToTs =
            let ym = pValidTo credentialPolicy
                year = toInteger (ymYear ym)
                month = fromIntegral (ymMonth ym)
                expiryYear = if month == 12 then year + 1 else year
                expiryMonth = if month == 12 then 1 else month + 1 -- (month % 12) + 1
                expiryDay = fromGregorian expiryYear expiryMonth 1 -- unchecked, always valid
            in utcTimeToTimestamp (UTCTime expiryDay 0)

-- |Put a list of policies in the format expected by smart contracts.
-- This is __not__ intended for general use.
putSenderPolicies :: [SenderPolicy] -> Put
putSenderPolicies ps = do
  putWord16le (fromIntegral (length ps))
  forM_ ps $ \sp ->
    let policyBytes = runPut $ putSenderPolicy sp
    -- we put length information for each of the policies so that the consumer
    -- can in principle skip through them.
    in putWord16le (fromIntegral (BS.length policyBytes)) <> putByteString policyBytes

putSenderPolicy :: SenderPolicy -> Put
putSenderPolicy SenderPolicy{spIdentityProvider = IP_ID ipIdentity,..} =
  putWord32le ipIdentity <>
  putWord64le (tsMillis spCreatedAt) <>
  putWord64le (tsMillis spValidTo) <>
  putWord16le (fromIntegral (length spItems)) <>
  mapM_ (\(k, AttributeValue v) -> put k <> putWord8 (fromIntegral (BSS.length v)) <> putShortByteString v) spItems

--------------------------------------------------------------------------------

-- |Energy used by the Wasm interpreter.
newtype InterpreterEnergy = InterpreterEnergy { iEnergy :: Word64 }
    deriving(Eq, Ord, Show, Num, Enum, Integral, Real)

-- * Interpreter related functions.

-- |Output actions generated by a single invocation of a receive method.
data ActionsTree =
  -- |Send a message to a smart contract.
  TSend {
      -- |Address to send to.
      erAddr :: !ContractAddress,
      -- |The receive method to invoke.
      erName :: !ReceiveName,
      -- |The amount to send together with the message.
      erAmount :: !Amount,
      -- |The message to send.
      erParameter :: !Parameter
      }
  -- |Transfer this many tokens to an account.
  | TSimpleTransfer {
      -- |The address to send to.
      erTo :: !AccountAddress,
      -- |The amount to send.
      erAmount :: !Amount
      }
  -- |Both left and right subtrees must succeed.
  | And !ActionsTree !ActionsTree
  -- |Try to execute events in the left subtree, if that
  -- fails try the right.
  | Or !ActionsTree !ActionsTree
  -- |Simply accept the invocation.
  | Accept
  deriving(Eq, Show)

-- |Process the actions tree as returned by the Interpreter.
-- This is deliberately not made into a serialize instance at the moment since (1) serialization is not needed
-- and (2) it is complicated.
getActionsTree :: Get ActionsTree
getActionsTree = getWord32be >>= getActionsTree'

getActionsTree' :: Word32 -> Get ActionsTree
getActionsTree' 0 = fail "Empty list of events."
getActionsTree' size = go HM.empty 0
    where go acc n | n == size = return (acc HM.! (size-1))
                   | otherwise = do
                       getWord8 >>= \case
                         0 -> do
                           erAddr <- get
                           erName <- get
                           erAmount <- get
                           erParameter <- get
                           let action = TSend{..}
                           go (HM.insert n action acc) (n+1)
                         1 -> do
                           erTo <- get
                           erAmount <- get
                           let action = TSimpleTransfer{..}
                           go (HM.insert n action acc) (n+1)
                         2 -> do
                           l <- getWord32be
                           r <- getWord32be
                           let action = Or <$> HM.lookup l acc <*> HM.lookup r acc
                           case action of
                             Nothing -> fail "Malformed Or stack."
                             Just act -> go (HM.insert n act acc) (n+1)
                         3 -> do
                           l <- getWord32be
                           r <- getWord32be
                           let action = And <$> HM.lookup l acc <*> HM.lookup r acc
                           case action of
                             Nothing -> fail "Malformed And stack."
                             Just act -> go (HM.insert n act acc) (n+1)
                         4 ->
                           let action = Accept
                           in go (HM.insert n action acc) (n+1)
                         tag -> fail $ "Unsupported tag: " ++ show tag

-- |Event as reported by contract execution.
newtype ContractEvent = ContractEvent BSS.ShortByteString
    deriving(Eq, Show)
    deriving(AE.ToJSON, AE.FromJSON) via ByteStringHex

instance Serialize ContractEvent where
  put (ContractEvent ev) = putShortByteStringWord32 ev
  get = ContractEvent <$> getShortByteStringWord32

data SuccessfulResultData a = SuccessfulResultData {
  messages :: !a,
  newState :: !ContractState,
  logs :: ![ContractEvent]
  }

-- |Specialized deserializer for processing FFI data.
--
-- If we update the integration, we should also update this deserializer.
getSuccessfulResultData :: Get a -> Get (SuccessfulResultData a)
getSuccessfulResultData messagesDecoder = do
  newState <- get
  len <- fromIntegral <$> getWord32be
  logs <- replicateM len get
  messages <- messagesDecoder
  return SuccessfulResultData{..}

-- |Reason for failure of contract execution.
data ContractExecutionFailure =
  ContractReject -- ^Contract decided to terminate execution.
  | RuntimeFailure -- ^A trap was triggered.
  deriving(Eq, Show)
