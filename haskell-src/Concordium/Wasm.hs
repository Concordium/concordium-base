{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module      : Concordium.Wasm
-- Description : Types used in the smart contract framework.
--
-- Basic types used in the Smart Contract Framework. A contract is a piece of
-- functionality that extends the base features that are built in the blockchain.
--
-- = Definition
--
-- A /Smart Contract Module/ is a set of /Contracts/. Each Contract has one @init@
-- method and zero or more @receive@ methods.
--
-- A /Module/ is received from the user in serialized wasm format
-- (i.e. 'WasmModule') and processed into an 'InstrumentedModule'. An
-- 'InstrumentedModule' can then be instantiated using the associated
-- 'ModuleInterface' which specifies the names of the exposed methods.
--
-- During its lifetime, a contract holds a 'ContractState' that can be interpreted
-- by the Interpreter and might contain variables used in the contract code.
--
-- Calling a method (both for a @receive@ and @init@ method) requires some
-- additional data that is specified in 'ReceiveContext' and 'InitContext'
-- respectively.
--
-- = Interpreter
--
-- The interpreter runs a method of the smart contract on a given 'ContractState'.
--
-- An execution of a contract can either be successful (which would generate a
-- 'SuccessfulResultData') or fail (generating a 'ContractExecutionFailure'). If an
-- execution is successful, then an 'ActionsTree' is returned together with the new
-- 'ContractState' and a list of events logged by the contract ('ContractEvent').
module Concordium.Wasm (
    -- * Constants
    maxParameterLen,
    maxWasmModuleSizeV0,
    maxWasmModuleSizeV1,
    limitLogsAndReturnValues,

    -- * Modules

    -- ** Binary module

    --

    -- | A binary module contains the source of the contract in serialized wasm
    -- format. This source is not ready for execution and, after processing it
    -- into an 'InstrumentedModule', it should just be stored and retrieved on
    -- demand.
    ModuleSource (..),
    unsafeUseModuleSourceAsCStringLen,
    moduleSourceLength,
    WasmModule (..),
    wasmVersion,
    wasmSource,
    demoteWasmVersion,
    WasmModuleV (..),
    getModuleRef,
    WasmVersion (..),
    IsWasmVersion (..),
    SWasmVersion (..),
    V0,
    V1,

    -- *** Methods

    --

    -- | A contract has one init method and several receive methods. A module can
    -- contain several contracts.
    InitName (..),
    isValidInitName,
    extractInitName,
    initContractName,
    ReceiveName (..),
    isValidReceiveName,
    contractAndFunctionName,
    makeFallbackReceiveName,
    extractInitReceiveNames,
    EntrypointName (..),
    isValidEntrypointName,
    uncheckedMakeReceiveName,
    Parameter (..),
    emptyParameter,
    parameterLen,
    getParameter,
    getParameterUnchecked,
    putParameter,

    -- *** Contract state
    ContractState (..),
    ByteSize (..),
    contractStateSize,

    -- *** Contexts

    --

    -- | When calling a method on a contract, some context data is needed and has
    -- to be provided by the execution engine.
    InitContext (..),
    encodeInitContext,
    ReceiveContext (..),
    encodeReceiveContext,
    SenderPolicy (..),
    mkSenderPolicy,
    putSenderPolicies,

    -- * Interpreter

    -- ** Energy
    InterpreterEnergy (..),

    -- ** Interpreter outcome

    -- *** Successful execution
    ActionsTree (..),
    getActionsTree,
    ContractEvent (..),
    SuccessfulResultData (..),
    getSuccessfulResultData,

    -- *** Failed execution
    ContractExecutionFailure (..),
    -- |Instance queries
    InstanceInfo (..),

    -- *Miscelaneous helpers.
    putAmountLE,
    putExchangeRateLE,
) where

import Control.Monad
import qualified Data.Aeson as AE
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as BS16
import Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as BSS
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.Char (isAlphaNum, isAscii, isPunctuation)
import qualified Data.HashMap.Strict as HM
import Data.Hashable
import Data.Int (Int32)
import qualified Data.Map.Strict as Map
import Data.Ratio (denominator, numerator)
import Data.Serialize
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import Data.Time
import Data.Word
import Foreign.C (CStringLen)

import Concordium.Common.Time
import Concordium.Constants
import Concordium.Crypto.ByteStringHelpers (ByteStringHex (..))
import qualified Concordium.Crypto.SHA256 as H
import Concordium.ID.Types
import Concordium.Types
import Concordium.Types.HashableTo
import Concordium.Utils.Serialization

--------------------------------------------------------------------------------

-- |Supported versions of Wasm modules. This version defines available host
-- functions, their semantics, and limitations of contracts.
data WasmVersion = V0 | V1
    deriving (Eq, Show)

-- |Map the WasmVersion to a 32-bit word for serialization.
wasmVersionToWord :: WasmVersion -> Word32
wasmVersionToWord V0 = 0
wasmVersionToWord V1 = 1

-- |Converse to 'wasmVersionToWord'.
wordToWasmVersion :: Word32 -> Maybe WasmVersion
wordToWasmVersion 0 = Just V0
wordToWasmVersion 1 = Just V1
wordToWasmVersion _ = Nothing

instance Serialize WasmVersion where
    put = putWord32be . wasmVersionToWord

    get = do
        w <- getWord32be
        case wordToWasmVersion w of
            Just wv -> return wv
            Nothing -> fail $ "Unrecognized Wasm version number " ++ show w

instance AE.ToJSON WasmVersion where
    toJSON = AE.toJSON . wasmVersionToWord

instance AE.FromJSON WasmVersion where
    parseJSON v = do
        word <- AE.parseJSON v
        case wordToWasmVersion word of
            Just wv -> return wv
            Nothing -> fail $ "Unsupported Wasm version " ++ show word

-- |These type aliases are provided for convenience to avoid having to enable
-- DataKinds everywhere we need wasm version.
type V0 = 'V0

type V1 = 'V1

-- |Boilerplate to allow using the supplied version type parameter as a term.
data SWasmVersion (v :: WasmVersion) where
    SV0 :: SWasmVersion 'V0
    SV1 :: SWasmVersion 'V1

-- A typeclass that allows to pass SWasmVersion implicitly to computations via a
-- constraint.
class IsWasmVersion (v :: WasmVersion) where
    getWasmVersion :: SWasmVersion v

instance IsWasmVersion 'V0 where
    getWasmVersion = SV0

instance IsWasmVersion 'V1 where
    getWasmVersion = SV1

demoteWasmVersion :: SWasmVersion v -> WasmVersion
demoteWasmVersion SV0 = V0
demoteWasmVersion SV1 = V1

-- | The source of a contract in binary wasm format.
newtype ModuleSource (v :: WasmVersion) = ModuleSource {moduleSource :: ByteString}
    deriving (Eq, Show)

instance Serialize (ModuleSource V0) where
    get = do
        len <- getWord32be
        unless (len <= maxWasmModuleSizeV0) $ fail "Maximum module size exceeded."
        ModuleSource <$> getByteString (fromIntegral len)
    put = putByteStringWord32 . moduleSource

instance Serialize (ModuleSource V1) where
    get = do
        len <- getWord32be
        unless (len <= maxWasmModuleSizeV1) $ fail "Maximum module size exceeded."
        ModuleSource <$> getByteString (fromIntegral len)
    put = putByteStringWord32 . moduleSource

unsafeUseModuleSourceAsCStringLen :: ModuleSource v -> (CStringLen -> IO a) -> IO a
unsafeUseModuleSourceAsCStringLen = unsafeUseAsCStringLen . moduleSource

moduleSourceLength :: ModuleSource v -> Word64
moduleSourceLength = fromIntegral . BS.length . moduleSource

-- |A versioned module source. The serialization instance of this type, in contrast to ModuleSource,
-- records the version that was used.
newtype WasmModuleV (v :: WasmVersion) = WasmModuleV {wmvSource :: ModuleSource v}
    deriving (Eq, Show)

instance IsWasmVersion v => Serialize (WasmModuleV v) where
    put (WasmModuleV ws) = case getWasmVersion @v of
        SV0 -> put V0 <> put ws
        SV1 -> put V1 <> put ws

    get = case getWasmVersion @v of
        SV0 ->
            get >>= \case
                V0 -> WasmModuleV <$> get
                _ -> fail "Expecting a V0 module."
        SV1 ->
            get >>= \case
                V1 -> WasmModuleV <$> get
                _ -> fail "Expecting a V1 module."

-- |A module of either version 0 or 1.
data WasmModule
    = WasmModuleV0 (WasmModuleV V0)
    | WasmModuleV1 (WasmModuleV V1)
    deriving (Eq, Show)

getModuleRef :: forall v. IsWasmVersion v => WasmModuleV v -> ModuleRef
getModuleRef wm = case getWasmVersion @v of
    SV0 -> ModuleRef (getHash wm)
    SV1 -> ModuleRef (getHash wm)

-- |Get the WasmVersion of a WasmModule.
wasmVersion :: WasmModule -> WasmVersion
wasmVersion = \case
    WasmModuleV0 _ -> V0
    WasmModuleV1 _ -> V1

-- |Get the raw ModuleSource from a WasmModule.
wasmSource :: WasmModule -> ByteString
wasmSource = \case
    WasmModuleV0 wmv -> moduleSource . wmvSource $ wmv
    WasmModuleV1 wmv -> moduleSource . wmvSource $ wmv

instance Serialize WasmModule where
    put (WasmModuleV0 ws) =
        put ws
    put (WasmModuleV1 ws) =
        put ws

    get = do
        get >>= \case
            V0 -> WasmModuleV0 . WasmModuleV <$> get
            V1 -> WasmModuleV1 . WasmModuleV <$> get

instance HashableTo H.Hash WasmModule where
    -- Hash the serialization directly.
    getHash (WasmModuleV0 wm) = getHash wm
    getHash (WasmModuleV1 wm) = getHash wm

instance HashableTo H.Hash (WasmModuleV V0) where
    -- Hash the serialization directly.
    getHash (WasmModuleV wm) = H.hash (encode V0 <> encode wm)

instance HashableTo H.Hash (WasmModuleV V1) where
    -- Hash the serialization directly.
    getHash (WasmModuleV wm) = H.hash (encode V1 <> encode wm)

--------------------------------------------------------------------------------

-- |Name of an init method inside a module.
newtype InitName = InitName {initName :: Text}
    deriving (Eq, Ord)
    deriving (AE.ToJSON) via Text

instance Show InitName where
    show InitName{..} = show initName

-- |Check whether the given text is a valid init name.
-- This is the case if
--
-- * length is <= maxFuncNameSize
-- * all characters are valid ascii characters in alphanumeric or punctuation classes
-- * the name does not contain @.@
-- * the name starts with `init_`
isValidInitName :: Text -> Bool
isValidInitName proposal =
    -- The limit is specified in bytes, but Text.length returns the number of chars.
    -- This is not a problem, as we only allow ASCII.
    let hasValidLength = Text.length proposal <= maxFuncNameSize
        hasValidCharacters = Text.all (\c -> isAscii c && (isAlphaNum c || isPunctuation c)) proposal
        hasDot = Text.any (== '.') proposal
    in  "init_" `Text.isPrefixOf` proposal && hasValidLength && hasValidCharacters && not hasDot

-- |Check that the given string is a valid init name. If so construct it,
-- otherwise return Nothing.
extractInitName :: Text -> Maybe InitName
extractInitName nameText = do
    guard (isValidInitName nameText)
    return (InitName nameText)

instance AE.FromJSON InitName where
    parseJSON = AE.withText "InitName" $ \initName -> do
        if isValidInitName initName
            then return InitName{..}
            else fail "Invalid init name."

instance Serialize InitName where
    put = putByteStringWord16 . Text.encodeUtf8 . initName
    get = do
        bs <- getByteStringWord16
        case Text.decodeUtf8' bs of
            Left _ -> fail "Not a valid utf-8 encoding."
            Right t
                | isValidInitName t -> return (InitName t)
                | otherwise -> fail "Not a valid init name."

-- |Serialize an amount in little endian for use by passing data to smart
-- contracts.
putAmountLE :: Amount -> Put
putAmountLE (Amount a) = putWord64le a

-- |Serialize an exchange rate in little endian for use by passing data to smart
-- contracts.
putExchangeRateLE :: ExchangeRate -> Put
putExchangeRateLE (ExchangeRate ratio) = do
    putWord64le $ fromIntegral $ numerator ratio
    putWord64le $ fromIntegral $ denominator ratio

-- |Name of a receive method inside a module.
newtype ReceiveName = ReceiveName {receiveName :: Text}
    deriving (Eq, Ord)
    deriving (AE.ToJSON) via Text

instance Show ReceiveName where
    show ReceiveName{..} = show receiveName

-- |Check whether the given text is a valid receive name.
-- This is the case if
--
-- * length is <= maxFuncNameSize
-- * all characters are valid ascii characters in alphanumeric or punctuation classes
-- * the name contains @.@
isValidReceiveName :: Text -> Bool
isValidReceiveName proposal =
    -- The limit is specified in bytes, but Text.length returns the number of chars.
    -- This is not a problem, as we only allow ASCII.
    let hasValidLength = Text.length proposal <= maxFuncNameSize
        hasValidCharacters = Text.all (\c -> isAscii c && (isAlphaNum c || isPunctuation c)) proposal
        hasDot = Text.any (== '.') proposal
    in  hasValidLength && hasValidCharacters && hasDot

-- |Name of the entrypoint, i.e., the part of the receive name after the dot.
newtype EntrypointName = EntrypointName {entrypointName :: Text}
    deriving (Eq, Show, Ord)
    deriving (AE.ToJSON) via Text

-- |Check whether the given text is a valid entrypoint name.
-- This is the case if
--
-- * length is < maxFuncNameSize
-- * all characters are valid ascii characters in alphanumeric or punctuation classes
--
-- Note that these are necessary, but not sufficient, conditions for this
-- entrypoint name to be an entrypoint name of any contract.
isValidEntrypointName :: Text -> Bool
isValidEntrypointName proposal =
    -- The limit is specified in bytes, but Text.length returns the number of chars.
    -- This is not a problem, as we only allow ASCII.
    let hasValidLength = Text.length proposal < maxFuncNameSize
        hasValidCharacters = Text.all (\c -> isAscii c && (isAlphaNum c || isPunctuation c)) proposal
    in  hasValidLength && hasValidCharacters

instance Serialize EntrypointName where
    put = putByteStringWord16 . Text.encodeUtf8 . entrypointName
    get = do
        bs <- getByteStringWord16
        case Text.decodeUtf8' bs of
            Left _ -> fail "Not a valid utf-8 encoding."
            Right t
                | isValidEntrypointName t -> return (EntrypointName t)
                | otherwise -> fail $ "Not a valid entrypoint name: " ++ Text.unpack t

-- |Make a receive name from an init name and an entrypoint name. This does not check that the
-- resulting receive name is valid. It could be too long.
uncheckedMakeReceiveName :: InitName -> EntrypointName -> ReceiveName
uncheckedMakeReceiveName iName EntrypointName{..} = ReceiveName (initContractName iName <> "." <> entrypointName)

-- |Extract the contract name from the init function name.
initContractName :: InitName -> Text
initContractName = Text.drop (Text.length "init_") . initName

-- |Extract the contract and function names from the receive name.
contractAndFunctionName :: ReceiveName -> (Text, Text)
contractAndFunctionName (ReceiveName n) = (cname, Text.drop 1 fname)
  where
    (cname, fname) = Text.span (/= '.') n

-- |Check that the given string is a valid receive name, and extract the init
-- and receive names from it. The latter is just the name that was given and the
-- former is the name of the function that was used to create the instance to
-- which the receive function belongs.
extractInitReceiveNames :: Text -> Maybe (InitName, ReceiveName)
extractInitReceiveNames nameText = do
    guard (isValidReceiveName nameText)
    let cname = "init_" <> Text.takeWhile (/= '.') nameText
    return (InitName cname, ReceiveName nameText)

-- |Derive the name of a fallback entrypoint for the contract.
-- This is defined as the entrypoint "contractName.", i.e., with the empty function name.
makeFallbackReceiveName :: ReceiveName -> ReceiveName
makeFallbackReceiveName r =
    let (cname, _) = contractAndFunctionName r
    in  ReceiveName (cname <> ".")

instance AE.FromJSON ReceiveName where
    parseJSON = AE.withText "ReceiveName" $ \receiveName -> do
        if isValidReceiveName receiveName
            then return ReceiveName{..}
            else fail "Invalid receive name."

instance Serialize ReceiveName where
    put = putByteStringWord16 . Text.encodeUtf8 . receiveName
    get = do
        bs <- getByteStringWord16
        case Text.decodeUtf8' bs of
            Left _ -> fail "Not a valid utf-8 encoding."
            Right t
                | isValidReceiveName t -> return (ReceiveName t)
                | otherwise -> fail $ "Not a valid receive name: " ++ Text.unpack t

-- |Parameter to either an init method or to a receive method.
-- The parameter is limited to 1kB in size. This is ensured
-- by deserialization methods.
newtype Parameter = Parameter {parameter :: ShortByteString}
    deriving (Eq)
    deriving (AE.ToJSON, AE.FromJSON, Show) via ByteStringHex

-- |Parameter of size 0.
emptyParameter :: Parameter
emptyParameter = Parameter BSS.empty

-- |Put (serialize) a @Parameter@.
putParameter :: Putter Parameter
putParameter = putShortByteStringWord16 . parameter

-- |Get the size in bytes of the parameter.
parameterLen :: Parameter -> Word64
parameterLen (Parameter p) = fromIntegral (BSS.length p)

-- |Get (deserialize) a @Parameter@ and ensure that its size is valid. The size limit depends on the protocol version.
getParameter :: SProtocolVersion pv -> Get Parameter
getParameter spv = do
    len <- getWord16be
    unless (len <= maxParameterLen spv) $ fail "Parameter size exceeds the limit."
    Parameter <$> getShortByteString (fromIntegral len)

-- |Get (deserialize) a @Parameter@ *without checking that its size is valid*. This should only be used when
-- we know for a fact that the parameter size is within the valid bounds for the given protocol version.
getParameterUnchecked :: Get Parameter
getParameterUnchecked = do
    len <- getWord16be
    Parameter <$> getShortByteString (fromIntegral len)

--------------------------------------------------------------------------------

-- |State of a smart contract. In general we don't know anything other than
-- it is a sequence of bytes.
newtype ContractState = ContractState {contractState :: BS.ByteString}
    deriving (Eq)

instance AE.ToJSON ContractState where
    toJSON ContractState{..} = AE.String (Text.decodeUtf8 (BS16.encode contractState))

instance AE.FromJSON ContractState where
    parseJSON = AE.withText "ContractState" $ \csText ->
        case BS16.decode (Text.encodeUtf8 csText) of
            Right contractState -> return ContractState{..}
            Left _ -> fail "Invalid hex string."

-- The show instance just displays the bytes directly.
instance Show ContractState where
    show ContractState{..} = show (BS.unpack contractState)

-- |Type used to measure contract storage costs.
newtype ByteSize = ByteSize {_byteSize :: Word64}
    deriving (Show, Read, Eq, Enum, Ord, Num, Real, Integral, Hashable, Bounded) via Word64

-- |Get the size of the contract state in bytes.
{-# INLINE contractStateSize #-}
contractStateSize :: ContractState -> ByteSize
contractStateSize = fromIntegral . BS.length . contractState

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
data InitContext = InitContext
    { -- |Origin of the transaction; who is initializing the contract.
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
      invoker :: !AccountAddress,
      -- | The address of the contract being invoked.
      selfAddress :: !ContractAddress,
      -- | Amount on the smart contract instance just before the receive method is
      -- called.
      selfBalance :: !Amount,
      -- |Address of the account or contract who sent a message to the contract.
      sender :: !Address,
      -- |Owner of this smart contract instance.
      owner :: !AccountAddress,
      -- |Policy exposed to the smart contract. Either the policy of the sender account,
      -- or of the owner of the contract.
      rcSenderPolicies :: ![SenderPolicy]
    }

-- |Encode into a bytestring, using little endian serialization where
-- appropriate.
encodeReceiveContext :: ReceiveContext -> ByteString
encodeReceiveContext ReceiveContext{..} = runPut encoder
  where
    encoder =
        put invoker
            <> encodeContractAddress selfAddress
            <> putWord64le (_amount selfBalance)
            <> encodeAddress sender
            <> put owner
            <> putSenderPolicies rcSenderPolicies

    encodeContractAddress (ContractAddress ind subind) =
        putWord64le (_contractIndex ind)
            <> putWord64le (_contractSubindex subind)
    encodeAddress (AddressContract addr) = putWord8 1 <> encodeContractAddress addr
    encodeAddress (AddressAccount accAddr) = putWord8 0 <> put accAddr

data SenderPolicy = SenderPolicy
    { -- |Identity of the identity provider who signed the identity object
      -- that created the policy.
      spIdentityProvider :: !IdentityProviderIdentity,
      -- |Beginning of the month where the identity object was created.
      spCreatedAt :: !Timestamp,
      -- |Beginning of the month where the identity object is no longer valid.
      spValidTo :: !Timestamp,
      -- |Attributes, by increasing order of the attribute tag.
      spItems :: ![(AttributeTag, AttributeValue)]
    }

mkSenderPolicy :: AccountCredential' credTy -> SenderPolicy
mkSenderPolicy ac =
    SenderPolicy
        { spCreatedAt = createdAtTs,
          spValidTo = validToTs,
          spItems = Map.toAscList (pItems credentialPolicy),
          spIdentityProvider = ipId ac
        }
  where
    credentialPolicy = policy ac
    createdAtTs =
        let ym = pCreatedAt credentialPolicy
            year = toInteger (ymYear ym)
            month = fromIntegral (ymMonth ym)
            expiryDay = fromGregorian year month 1 -- unchecked, always valid
        in  utcTimeToTimestamp (UTCTime expiryDay 0)

    validToTs =
        let ym = pValidTo credentialPolicy
            year = toInteger (ymYear ym)
            month = fromIntegral (ymMonth ym)
            expiryYear = if month == 12 then year + 1 else year
            expiryMonth = if month == 12 then 1 else month + 1 -- (month % 12) + 1
            expiryDay = fromGregorian expiryYear expiryMonth 1 -- unchecked, always valid
        in  utcTimeToTimestamp (UTCTime expiryDay 0)

-- |Put a list of policies in the format expected by smart contracts.
-- This is __not__ intended for general use.
putSenderPolicies :: [SenderPolicy] -> Put
putSenderPolicies ps = do
    putWord16le (fromIntegral (length ps))
    forM_ ps $ \sp ->
        let policyBytes = runPut $ putSenderPolicy sp
        in  -- we put length information for each of the policies so that the consumer
            -- can in principle skip through them.
            putWord16le (fromIntegral (BS.length policyBytes)) <> putByteString policyBytes

putSenderPolicy :: SenderPolicy -> Put
putSenderPolicy SenderPolicy{spIdentityProvider = IP_ID ipIdentity, ..} =
    putWord32le ipIdentity
        <> putWord64le (tsMillis spCreatedAt)
        <> putWord64le (tsMillis spValidTo)
        <> putWord16le (fromIntegral (length spItems))
        <> mapM_ (\(k, AttributeValue v) -> put k <> putWord8 (fromIntegral (BSS.length v)) <> putShortByteString v) spItems

--------------------------------------------------------------------------------

-- |Energy used by the Wasm interpreter.
newtype InterpreterEnergy = InterpreterEnergy {iEnergy :: Word64}
    deriving (Eq, Ord, Show, Num, Enum, Integral, Real)

-- * Interpreter related functions.

-- |Output actions generated by a single invocation of a receive method.
data ActionsTree
    = -- |Send a message to a smart contract.
      TSend
        { -- |Address to send to.
          erAddr :: !ContractAddress,
          -- |The receive method to invoke.
          erName :: !ReceiveName,
          -- |The amount to send together with the message.
          erAmount :: !Amount,
          -- |The message to send.
          erParameter :: !Parameter
        }
    | -- |Transfer this many tokens to an account.
      TSimpleTransfer
        { -- |The address to send to.
          erTo :: !AccountAddress,
          -- |The amount to send.
          erAmount :: !Amount
        }
    | -- |Both left and right subtrees must succeed.
      And !ActionsTree !ActionsTree
    | -- |Try to execute events in the left subtree, if that
      -- fails try the right.
      Or !ActionsTree !ActionsTree
    | -- |Simply accept the invocation.
      Accept
    deriving (Eq, Show)

-- |Process the actions tree as returned by the Interpreter.
-- This is deliberately not made into a serialize instance at the moment since (1) serialization is not needed
-- and (2) it is complicated.
getActionsTree :: Get ActionsTree
getActionsTree = getWord32be >>= getActionsTree'

getActionsTree' :: Word32 -> Get ActionsTree
getActionsTree' 0 = fail "Empty list of events."
getActionsTree' size = go HM.empty 0
  where
    go acc n
        | n == size = return (acc HM.! (size - 1))
        | otherwise = do
            getWord8 >>= \case
                0 -> do
                    erAddr <- get
                    erName <- get
                    erAmount <- get
                    erParameter <- getParameterUnchecked
                    let action = TSend{..}
                    go (HM.insert n action acc) (n + 1)
                1 -> do
                    erTo <- get
                    erAmount <- get
                    let action = TSimpleTransfer{..}
                    go (HM.insert n action acc) (n + 1)
                2 -> do
                    l <- getWord32be
                    r <- getWord32be
                    let action = Or <$> HM.lookup l acc <*> HM.lookup r acc
                    case action of
                        Nothing -> fail "Malformed Or stack."
                        Just act -> go (HM.insert n act acc) (n + 1)
                3 -> do
                    l <- getWord32be
                    r <- getWord32be
                    let action = And <$> HM.lookup l acc <*> HM.lookup r acc
                    case action of
                        Nothing -> fail "Malformed And stack."
                        Just act -> go (HM.insert n act acc) (n + 1)
                4 ->
                    let action = Accept
                    in  go (HM.insert n action acc) (n + 1)
                tag -> fail $ "Unsupported tag: " ++ show tag

-- |Event as reported by contract execution.
newtype ContractEvent = ContractEvent BSS.ShortByteString
    deriving (Eq)
    deriving (AE.ToJSON, AE.FromJSON, Show) via ByteStringHex

instance Serialize ContractEvent where
    put (ContractEvent ev) = putShortByteStringWord32 ev
    get = ContractEvent <$> getShortByteStringWord32

data SuccessfulResultData a = SuccessfulResultData
    { messages :: !a,
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
data ContractExecutionFailure
    = -- |Contract decided to terminate execution.
      ContractReject {rejectReason :: Int32}
    | -- |A trap was triggered.
      RuntimeFailure
    deriving (Eq, Show)

-- |Data about the contract that is returned by a node query. The V0 and V1
-- instances are almost the same, but because the state of V1 instances is
-- unbounded in general, we cannot return it as such in queries. Thus there is
-- no "model" field for V1 instances.
data InstanceInfo
    = InstanceInfoV0
        { iiModel :: !ContractState,
          iiOwner :: !AccountAddress,
          iiAmount :: !Amount,
          iiMethods :: !(Set.Set ReceiveName),
          iiName :: !InitName,
          iiSourceModule :: !ModuleRef
        }
    | InstanceInfoV1
        { iiOwner :: !AccountAddress,
          iiAmount :: !Amount,
          iiMethods :: !(Set.Set ReceiveName),
          iiName :: !InitName,
          iiSourceModule :: !ModuleRef
        }
    deriving (Eq, Show)

-- |Helper function for JSON encoding an 'InstanceInfo'.
instancePairs :: AE.KeyValue kv => InstanceInfo -> [kv]
{-# INLINE instancePairs #-}
instancePairs InstanceInfoV0{..} =
    [ "model" AE..= iiModel,
      "owner" AE..= iiOwner,
      "amount" AE..= iiAmount,
      "methods" AE..= iiMethods,
      "name" AE..= iiName,
      "sourceModule" AE..= iiSourceModule,
      "version" AE..= V0
    ]
instancePairs InstanceInfoV1{..} =
    [ "owner" AE..= iiOwner,
      "amount" AE..= iiAmount,
      "methods" AE..= iiMethods,
      "name" AE..= iiName,
      "sourceModule" AE..= iiSourceModule,
      "version" AE..= V1
    ]

instance AE.ToJSON InstanceInfo where
    toJSON inst = AE.object $ instancePairs inst
    toEncoding inst = AE.pairs $ mconcat $ instancePairs inst

instance AE.FromJSON InstanceInfo where
    parseJSON = AE.withObject "InstanceInfo" $ \obj -> do
        iiOwner <- obj AE..: "owner"
        iiAmount <- obj AE..: "amount"
        iiMethods <- obj AE..: "methods"
        iiName <- obj AE..: "name"
        iiSourceModule <- obj AE..: "sourceModule"
        (obj AE..: "version") >>= \case
            V0 -> do
                iiModel <- obj AE..: "model"
                return InstanceInfoV0{..}
            V1 -> return InstanceInfoV1{..}
