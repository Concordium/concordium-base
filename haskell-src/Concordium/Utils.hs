{-# LANGUAGE BangPatterns, RankNTypes, LambdaCase #-}
module Concordium.Utils (
  At'(at')
  ) where

import Data.HashMap.Strict as H
import Data.Hashable
import Data.Map.Strict as M
import Data.Functor
import Lens.Micro.Internal
import Lens.Micro.Platform

-- |Strict version of `At`.
--
-- The implementations should be fairly similar to the implementation in `micro-platforms` but values
-- must be evaluated with bang patterns for removing laziness.
class (Ixed m) => At' m where
  at' :: Index m -> Lens' m (Maybe (IxValue m))

instance (Hashable k, Eq k) => At' (HashMap k v) where
  at' = at'' H.lookup H.delete H.insert

instance Ord k => At' (Map k v) where
  at' = at'' M.lookup M.delete M.insert

at'' :: Functor f =>
       (k -> m -> Maybe v)       -- ^lookup function
     -> (k -> m -> m)             -- ^delete function
     -> (k -> v -> m -> m)         -- ^insert function
     -> k                       -- ^index
     -> (Maybe v -> f (Maybe v)) -- ^functor
     -> m                       -- ^collection
     -> f m
at'' look del ins k f m = let !mv = look k m
                              !v1 = f mv in
    v1 <&> (\case
               Nothing -> let !v = maybe m (const (del k m)) mv in v
               Just v' -> let !v = ins k v' m in v)
