{-# LANGUAGE DerivingVia, DeriveGeneric, ScopedTypeVariables, OverloadedStrings #-}
module Concordium.Wasm where

import GHC.Generics
import Data.Word
import Control.Monad
import qualified Data.HashMap.Strict as HM
import Data.ByteString(ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Short(ShortByteString)
import qualified Data.ByteString.Base16 as BS16
import qualified Data.ByteString.Short as BSS
import Data.Serialize
import qualified Data.Aeson as AE
import Data.Char (isPunctuation, isAlphaNum, isAscii)
import Data.Text(Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import qualified Data.Set as Set
import qualified Data.Map.Strict as Map
import Data.Hashable

import Concordium.Crypto.ByteStringHelpers(ByteStringHex(..))
import qualified Concordium.Crypto.SHA256 as H

import Concordium.Types
import Concordium.Types.HashableTo
import Concordium.Utils.Serialization

type ModuleSource = ByteString

-- | A processed module artifact ready for execution.
newtype ModuleArtifact = ModuleArtifact { artifact :: ByteString }
    deriving(Eq, Show)

instance Serialize ModuleArtifact where
  put ma = putWord32be (fromIntegral (BS.length (artifact ma))) <>
           putByteString (artifact ma)

  get = do
    len <- getWord32be
    ModuleArtifact <$> getByteString (fromIntegral len)

-- |Web assembly module in binary format.
data WasmModule = WasmModule {
  -- |Version of the Wasm standard and on-chain API this module corresponds to.
  wasmVersion :: Word32,
  -- |Source in binary wasm format.
  wasmSource :: ModuleSource
  } deriving(Eq, Show)

moduleSize :: WasmModule -> Word64
moduleSize = fromIntegral . BS.length . wasmSource

getModuleRef :: WasmModule -> ModuleRef
getModuleRef wm = ModuleRef (getHash wm)

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

-- |Name of a receive method inside a module.
newtype ReceiveName = ReceiveName { receiveName :: Text }
    deriving (Eq, Show, Ord)
    deriving(AE.ToJSON) via Text

-- |Check whether the given text is a valid init name.
-- This is the case if
--
-- * all characters are valid ascii characters in alphanumeric or punctuation classes
-- * the name contains @.@
isValidReceiveName :: Text -> Bool
isValidReceiveName proposal =
  let hasValidCharacters = Text.all (\c -> isAscii c && (isAlphaNum c || isPunctuation c)) proposal
      hasDot = Text.any (== '.') proposal
  in hasValidCharacters && hasDot

instance AE.FromJSON ReceiveName where
  parseJSON = AE.withText "ReceiveName" $ \receiveName -> do
    if isValidReceiveName receiveName then return ReceiveName{..}
    else fail "Invalid receive name."

-- |Parameter to either an init method or to a receive method.
newtype Parameter = Parameter { parameter :: ShortByteString }
    deriving(Eq, Show)
    deriving(AE.ToJSON, AE.FromJSON) via ByteStringHex

-- |Web assembly module in binary format, instrumented with whatever it needs to
-- be instrumented with, and preprocessed to an executable format, ready to be instantiated
-- and run.
data InstrumentedModule = InstrumentedWasmModule {
  -- |Version of the Wasm standard and on-chain API this module corresponds to.
  imWasmVersion :: !Word32,
  -- |Source in binary wasm format.
  imWasmArtifact :: !ModuleArtifact
  } deriving(Eq, Show, Generic)


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
  -- |The source as deployed to the chain.
  miSourceModule :: !WasmModule
  } deriving(Eq, Show, Generic)

-- |Additional data needed specifically by the init method of the contract.
newtype InitContext = InitContext{
  -- |Origin of the transaction; who is initializing the contract.
  initOrigin :: AccountAddress
  }

-- |Additional data needed specifically by the receive method of the contract.
data ReceiveContext = ReceiveContext
  { -- | The address of the account which initiated the top-level transaction.
    invoker :: !AccountAddress
    -- | The address of the contract being invoked.
  , selfAddress :: !ContractAddress
    -- | Amount on the smart contract instnace just before the receive method is
    -- called.
  , selfBalance :: !Amount
  -- |Address of the account or contract who sent a message to the contract.
  , sender :: !Address
  -- |Owner of this smart contract instance.
  , owner :: !AccountAddress
  }

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

-- |Reason for failure of contract execution.
data ContractExecutionFailure =
  ContractReject -- ^Contract decided to terminate execution.
  | RuntimeFailure -- ^A trap was triggered.
  deriving(Eq, Show)

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

-- * Implementation of instances and the like.

instance Serialize InstrumentedModule where
  put InstrumentedWasmModule{..} =
    putWord32be imWasmVersion <>
    put imWasmArtifact

instance Serialize ModuleInterface where
-- FIXME: A more principled serialize method, order and ensure the order of sets.

instance Serialize WasmModule where
  put WasmModule{..} =
    putWord32be wasmVersion <>
    putByteStringWord32 wasmSource

  get = do
    wasmVersion <- getWord32be
    unless (wasmVersion == 0) $ fail "Unsupported Wasm module version."
    wasmSource <- getByteStringWord32
    return WasmModule{..}

instance HashableTo H.Hash WasmModule where
  -- Hash the serialization directly, perhaps this needs to be revisited in the future.
  getHash wm = H.hash (encode wm)

instance Serialize InitName where
  put = putByteStringWord16 . Text.encodeUtf8 . initName
  get = do
    bs <- getByteStringWord16
    case Text.decodeUtf8' bs of
      Left _ -> fail "Not a valid utf-8 encoding."
      Right t | isValidInitName t -> return (InitName t)
              | otherwise -> fail "Not a valid init name."

instance Serialize ReceiveName where
  put = putByteStringWord16 . Text.encodeUtf8 . receiveName
  get = do
    bs <- getByteStringWord16
    case Text.decodeUtf8' bs of
      Left _ -> fail "Not a valid utf-8 encoding."
      Right t | isValidReceiveName t -> return (ReceiveName t)
              | otherwise -> fail $ "Not a valid receive name: " ++ Text.unpack t

instance Serialize Parameter where
  put = putShortByteStringWord32 . parameter
  get = Parameter <$> getShortByteStringWord32

instance Serialize InitContext where
  put (InitContext origin) = put origin
  get = InitContext <$> get

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
          put owner

-- |Specialized deserializer for processing FFI data.
--
-- If we replace update the integration, we should also update this deserializer.
getSuccessfulResultData :: Get a -> Get (SuccessfulResultData a)
getSuccessfulResultData messagesDecoder = do
  newState <- get
  len <- fromIntegral <$> getWord32be
  logs <- replicateM len get
  messages <- messagesDecoder
  return SuccessfulResultData{..}
