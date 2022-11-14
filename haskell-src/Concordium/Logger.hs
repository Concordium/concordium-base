{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE TypeFamilies #-}

-- | Event logging monad.
module Concordium.Logger where

import Control.Exception
import Control.Monad.Catch
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Reader.Class
import Control.Monad.Trans.Class (MonadTrans (..))
import Control.Monad.Trans.Except
import Control.Monad.Trans.Maybe
import Control.Monad.Trans.RWS.Lazy as Lazy
import Control.Monad.Trans.RWS.Strict as Strict
import Control.Monad.Trans.Reader
import Control.Monad.Trans.State.Lazy as Lazy
import Control.Monad.Trans.State.Strict as Strict
import Control.Monad.Trans.Writer.Lazy as Lazy
import Control.Monad.Trans.Writer.Strict as Strict
import Data.Functor.Identity
import Data.Word

-- * Base types

-- These types are consumed in Rust through the ffi on consensus-rust/src/ffi.rs

-- | The source module for a log event.
data LogSource
    = Runner
    | Afgjort
    | Birk
    | Crypto
    | Kontrol
    | Skov
    | Baker
    | External
    | GlobalState
    | BlockState
    | TreeState
    | LMDB
    | Scheduler
    deriving (Eq, Ord, Show, Enum)

-- | Convert a 'LogSource' value to the representation required by the
--  Rust API.
logSourceId :: LogSource -> Word8
logSourceId = fromIntegral . fromEnum

-- | The logging level for a log event.
data LogLevel
    = LLError
    | LLWarning
    | LLInfo
    | LLDebug
    | LLTrace
    deriving (Eq, Ord)

instance Show LogLevel where
    show LLError = "ERROR"
    show LLWarning = "WARNING"
    show LLInfo = "INFO"
    show LLDebug = "DEBUG"
    show LLTrace = "TRACE"

-- | Convert a 'LogLevel' value to the representation required by the
--  Rust API.
logLevelId :: LogLevel -> Word8
logLevelId LLError = 1
logLevelId LLWarning = 2
logLevelId LLInfo = 3
logLevelId LLDebug = 4
logLevelId LLTrace = 5

-- | A method for logging an event in a given monad.
type LogMethod m = LogSource -> LogLevel -> String -> m ()

type LogIO = LoggerT IO

------------------------------------------------------------------------------

-- * The @LoggerT@ monad transformer

-- | The 'LoggerT' monad transformer equips a monad with logging
--  functionality.
newtype LoggerT m a = LoggerT {runLoggerT' :: ReaderT (LogMethod m) m a}
    deriving (Functor, Applicative, Monad, MonadIO, MonadReader (LogMethod m), MonadThrow, MonadCatch, MonadMask)

instance MonadTrans LoggerT where
    lift = LoggerT . lift
    {-# INLINE lift #-}

-- | Run an action in the 'LoggerT' monad, handling log events with the
--  given log method.
runLoggerT :: LoggerT m a -> LogMethod m -> m a
runLoggerT = runReaderT . runLoggerT'

-- | Run an action in the 'LoggerT' monad, discarding all log events.
runSilentLogger :: Applicative m => LoggerT m a -> m a
runSilentLogger = flip runLoggerT (\_ _ _ -> pure ())

------------------------------------------------------------------------------

-- * The @MonadLogger@ class

-- | Class for a monad that supports logging.
class Monad m => MonadLogger m where
    -- | Record a log event.
    logEvent :: LogMethod m
    default logEvent :: (MonadTrans t, MonadLogger m1, m ~ t m1) => LogMethod m
    logEvent src lvl msg = lift (logEvent src lvl msg)

-- These instances are declared in the same way as done in the mtl package.
-- See https://hackage.haskell.org/package/mtl-2.2.2/docs/src/Control.Monad.Reader.Class.html#MonadReader
instance Monad m => MonadLogger (LoggerT m) where
    logEvent src lvl msg = do
        logm <- Control.Monad.Reader.Class.ask
        lift $ logm src lvl msg

-- The Identity Monad will not do any logging. This instance is only used in the StaticEnvironment implementation
instance MonadLogger Identity where
    logEvent _ _ _ = pure ()

------------------------------------------------------------------------------
-- Instances for other mtl transformers.

instance MonadLogger m => MonadLogger (ExceptT e m)
instance MonadLogger m => MonadLogger (MaybeT m)
instance MonadLogger m => MonadLogger (Lazy.StateT s m)
instance MonadLogger m => MonadLogger (Strict.StateT e m)
instance MonadLogger m => MonadLogger (ReaderT e m)
instance (MonadLogger m, Monoid w) => MonadLogger (Lazy.WriterT w m)
instance (MonadLogger m, Monoid w) => MonadLogger (Strict.WriterT w m)
instance (MonadLogger m, Monoid w) => MonadLogger (Lazy.RWST r w s m)
instance (MonadLogger m, Monoid w) => MonadLogger (Strict.RWST r w s m)

--------------------------------------------------------------------------------

-- * Helpers

-- |Short alias to log an exception and throw it using the MonadIO instance
logExceptionAndThrow :: (MonadLogger m, MonadIO m, Exception e) => LogSource -> e -> m a
logExceptionAndThrow src exception = do
    logEvent src LLError $ displayException exception
    liftIO $ throwIO $ exception

-- |Short alias to log an error message and throw it using the MonadIO instance inside a userError
logErrorAndThrow :: (MonadLogger m, MonadIO m) => LogSource -> String -> m a
logErrorAndThrow src msg = do
    logEvent src LLError msg
    liftIO $ throwIO $ userError msg
