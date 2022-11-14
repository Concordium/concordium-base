{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE UndecidableInstances #-}

-- |This module defines the 'MonadPut' typeclass, which generalizes the 'PutM'
-- monad.  The main purpose of this generalization is to allow efficient
-- serialization to a file in a monadic context, where it may be undesirable
-- to build a large intermediate datastructure.
module Concordium.Utils.Serialization.Put where

import Control.Applicative
import Control.Monad.IO.Class
import Control.Monad.Reader
import Data.ByteString.Builder
import Data.Serialize
import System.IO

-- |Typeclass for efficient serialization.
class Monad m => MonadPut m where
    -- |Output a 'Builder'.
    build :: Builder -> m ()

    -- |Lift a value from the 'PutM' monad.
    liftPut :: PutM a -> m a
    liftPut p = do
        let (res, b) = runPutMBuilder p
        build b
        return res
    {-# INLINE liftPut #-}

-- |Serialize a value. Generalizes 'put' to 'MonadPut'.
sPut :: (Serialize a, MonadPut m) => a -> m ()
sPut = liftPut . put
{-# INLINE sPut #-}

instance MonadPut PutM where
    build = putBuilder
    {-# INLINE build #-}
    liftPut = id
    {-# INLINE liftPut #-}

-- |A monad transformer implementing 'MonadPut' that accumulates a 'Builder'.
newtype PutT m a = PutT {runPutT :: m (PutM a)}

instance Functor m => Functor (PutT m) where
    fmap f (PutT a) = PutT (fmap (fmap f) a)
    {-# INLINE fmap #-}

instance Applicative m => Applicative (PutT m) where
    pure = PutT . pure . pure
    {-# INLINE pure #-}
    (PutT f) <*> (PutT x) = PutT $ liftA2 (<*>) f x
    {-# INLINE (<*>) #-}

instance Monad m => Monad (PutT m) where
    a >>= f = PutT $ do
        (i, b0) <- runPutMBuilder <$> runPutT a
        (putBuilder b0 >>) <$> runPutT (f i)
    {-# INLINE (>>=) #-}

instance MonadTrans PutT where
    lift = PutT . fmap pure
    {-# INLINE lift #-}

instance Monad m => MonadPut (PutT m) where
    build = PutT . pure . putBuilder
    {-# INLINE build #-}

instance MonadIO m => MonadIO (PutT m) where
    liftIO = lift . liftIO
    {-# INLINE liftIO #-}

instance MonadReader r m => MonadReader r (PutT m) where
    ask = lift ask
    {-# INLINE ask #-}
    local f (PutT a) = PutT (local f a)
    {-# INLINE local #-}

-- |Monad transformer for serializing to a file.
newtype PutH m a = PutH {runPutH :: Handle -> m a}
    deriving (Functor, Applicative, Monad, MonadIO) via (ReaderT Handle m)
    deriving (MonadTrans) via (ReaderT Handle)

instance MonadIO m => MonadPut (PutH m) where
    build b = PutH $ \h -> liftIO $ hPutBuilder h b
    {-# INLINE build #-}

instance MonadReader r m => MonadReader r (PutH m) where
    ask = lift ask
    {-# INLINE ask #-}
    local f (PutH a) = PutH $ local f . a
