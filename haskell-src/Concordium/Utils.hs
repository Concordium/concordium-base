{-# LANGUAGE BangPatterns, RankNTypes, LambdaCase #-}
module Concordium.Utils (
  At'(at')
  ) where

import Data.HashMap.Strict as H
import Data.Hashable
import Data.Map.Strict as M
import Lens.Micro.Internal
import Lens.Micro.Platform

-- |Strict version of `At`.
--
-- The implementations should be fairly similar to the implementation in `micro-platforms` but values
-- must be evaluated with bang patterns for removing laziness.
class (Ixed m) => At' m where
  at' :: Index m -> Lens' m (Maybe (IxValue m))

instance (Hashable k, Eq k) => At' (HashMap k v) where
  at' = flip H.alterF
  {-# INLINE at' #-}

instance Ord k => At' (Map k v) where
  at' = flip M.alterF
  {-# INLINE at' #-}
