{-# LANGUAGE BangPatterns, RankNTypes, LambdaCase #-}
module Concordium.Utils where

import qualified Data.HashMap.Strict as H
import Data.Hashable
import qualified Data.Map.Strict as M
import qualified Data.Sequence as Seq
import Lens.Micro.Internal
import Lens.Micro.Platform

import Control.Monad.State.Class

-- |Strict version of `At`.
--
-- The implementations should be fairly similar to the implementation in `micro-platforms` but values
-- must be evaluated with bang patterns for removing laziness.
class (Ixed m) => At' m where
  at' :: Index m -> Lens' m (Maybe (IxValue m))

instance (Hashable k, Eq k) => At' (H.HashMap k v) where
  at' = flip H.alterF
  {-# INLINE at' #-}

instance Ord k => At' (M.Map k v) where
  at' = flip M.alterF
  {-# INLINE at' #-}


-- *Strict versions of monadic state lenses.

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
l ?=! b = b `seq` l .= Just b
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
cons' !x = (x:)
