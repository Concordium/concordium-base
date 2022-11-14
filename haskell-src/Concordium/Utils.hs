{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE RankNTypes #-}

module Concordium.Utils where

import Control.Monad
import Control.Monad.Except
import Control.Monad.State.Class
import Data.Char
import qualified Data.HashMap.Strict as H
import Data.Hashable
import qualified Data.Map.Strict as M
import Data.Maybe
import Data.Monoid (First)
import qualified Data.Sequence as Seq
import qualified Data.Set as Set
import Lens.Micro.Internal
import Lens.Micro.Platform

-- |Strict version of `At`.
--
-- The implementations should be fairly similar to the implementation in `micro-platforms` but values
-- must be evaluated with bang patterns for removing laziness.
class (Ixed m) => At' m where
    at' :: Index m -> Lens' m (Maybe (IxValue m))

instance (Hashable k, Eq k) => At' (H.HashMap k v) where
    at' k f = H.alterF f k
    {-# INLINE at' #-}

instance Ord k => At' (M.Map k v) where
    at' k f = M.alterF f k
    {-# INLINE at' #-}

-- *Strict versions of some lenses.
(?~!) :: ASetter s t a (Maybe b) -> b -> s -> t
l ?~! b = b `seq` set l (Just b)
{-# INLINE (?~!) #-}

infixr 4 ?~!

-- *Strict versions of monadic state lenses.

-- |Strict version of `gets` that evaluates the given function strictly on the
-- state before returning.
gets' :: MonadState s m => (s -> a) -> m a
gets' f = f <$!> get
{-# INLINE gets' #-}

preuse' :: MonadState s m => Getting (First a) s a -> m (Maybe a)
preuse' l = gets' (preview l)
{-# INLINE preuse' #-}

use' :: MonadState s m => Getting a s a -> m a
use' l = gets' (view l)
{-# INLINE use' #-}

(.=!) :: MonadState s m => ASetter s s a b -> b -> m ()
l .=! x = modify' (l .~ x)
{-# INLINE (.=!) #-}

infix 4 .=!

(%=!) :: (MonadState s m) => ASetter s s a b -> (a -> b) -> m ()
l %=! f = modify' (l %~ f)
{-# INLINE (%=!) #-}

infix 4 %=!

(<~!) :: MonadState s m => ASetter s s a b -> m b -> m ()
l <~! mb = mb >>= (l .=!)
{-# INLINE (<~!) #-}

infixr 2 <~!

(?=!) :: MonadState s m => ASetter s s a (Maybe b) -> b -> m ()
l ?=! b = l .=! (b `seq` Just b)
{-# INLINE (?=!) #-}

infix 4 ?=!

(%%=!) :: MonadState s m => LensLike ((,) r) s s a b -> (a -> (r, b)) -> m r
l %%=! f = do
    (r, s) <- gets (l f)
    put $! s
    return r
{-# INLINE (%%=!) #-}

infix 4 %%=!

(<%=!) :: MonadState s m => LensLike ((,) b) s s a b -> (a -> b) -> m b
l <%=! f = l %%=! (\a -> (a, a)) . f
{-# INLINE (<%=!) #-}

infix 4 <%=!

(<<.=!) :: MonadState s m => LensLike ((,) a) s s a b -> b -> m a
l <<.=! b = l %%=! (\a -> (a, b))
{-# INLINE (<<.=!) #-}

infix 4 <<.=!

(<.=!) :: MonadState s m => LensLike ((,) b) s s a b -> b -> m b
l <.=! b = l <%=! const b
{-# INLINE (<.=!) #-}

infix 4 <.=!

-- * Strict sequence cons and snoc.

-- Data.Sequence is strict in its length, but there are no strict insertion functions in the library.
-- Since consing often leads to memory leaks with sequences we provide here strict insertion functions.

infixr 5 <|!
infixl 5 |>!

{-# INLINE (<|!) #-}
(<|!) :: a -> Seq.Seq a -> Seq.Seq a
(!x) <|! xs = x Seq.<| xs

{-# INLINE (|>!) #-}
(|>!) :: Seq.Seq a -> a -> Seq.Seq a
xs |>! (!x) = xs Seq.|> x

{-# INLINE singleton' #-}
singleton' :: a -> Seq.Seq a
singleton' !x = Seq.singleton x

-- *Strict list insertions.
{-# INLINE cons' #-}
cons' :: a -> [a] -> [a]
cons' !x = (x :)

-- *Strict functions on pairs.

-- |Force the evaluation of the components of the pair.
($!!) :: ((a, b) -> c) -> (a, b) -> c
f $!! (!x, !y) = f (x, y)
{-# INLINE ($!!) #-}

-- * Helper lenses

nonEmpty :: (Monoid (f v), Foldable f) => Lens' (Maybe (f v)) (f v)
nonEmpty afb s = f <$> afb (fromMaybe mempty s)
  where
    f y = if null y then Nothing else Just y
{-# INLINE nonEmpty #-}

-- * Monadic conditionals

whenM :: (Monad m) => m Bool -> m () -> m ()
whenM t a = t >>= \r -> when r a

-- * Misc
whenAddToSet :: (Ord v, MonadState s m) => v -> Lens' s (Set.Set v) -> m () -> m ()
whenAddToSet val setLens act = do
    theSet <- use setLens
    unless (val `Set.member` theSet) $ do
        setLens .= Set.insert val theSet
        act

-- * Misc helper functions

-- |Convert the first character of a string to lowercase.
-- (This is used in Template Haskell for generating JSON serialization code.)
firstLower :: String -> String
firstLower [] = []
firstLower (c : cs) = toLower c : cs

-- | In the 'Left' case of an 'Either', transform the error using the given function and
-- "rethrow" it in the current 'MonadError'.
embedErr :: MonadError e m => Either e' a -> (e' -> e) -> m a
embedErr (Left x) f = throwError (f x)
embedErr (Right a) _ = return a
