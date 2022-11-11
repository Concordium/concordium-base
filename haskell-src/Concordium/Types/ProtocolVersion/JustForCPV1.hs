{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}

-- |Implementation of a maybe GADT which contains a value for chain parameter versions >= 1
-- and nothing for chain parameter version 0.  This is used to handle chain parameters that
-- were introduced at ChainParametersV1 (i.e. protocol version P4).
module Concordium.Types.ProtocolVersion.JustForCPV1 (
    JustForCPV1 (..),
    justForCPV1,
    justForCPV1A,
    unJustForCPV1,
    maybeForCPV1,
) where

import Data.Serialize

import Concordium.Types.ProtocolVersion

-- |A value for chain parameter versions >= 1 and nothing for chain parameter version 0.
-- The type is a 'Functor', 'Foldable' and 'Traversable' so that standard operations are available.
data JustForCPV1 (cpv :: ChainParametersVersion) a where
    NothingForCPV1 :: JustForCPV1 'ChainParametersV0 a
    JustForCPV1 :: !a -> JustForCPV1 'ChainParametersV1 a

deriving instance Eq a => Eq (JustForCPV1 cpv a)
deriving instance Show a => Show (JustForCPV1 cpv a)

-- |Build a 'JustForCPV'. If chain parameter version 0, then 'NothingForCPV1' otherwise
-- 'JustForCPV1' with @a@.
justForCPV1 :: forall cpv a. IsChainParametersVersion cpv => a -> JustForCPV1 cpv a
justForCPV1 a =
    case chainParametersVersion @cpv of
        SCPV0 -> NothingForCPV1
        SCPV1 -> JustForCPV1 a

-- |Build a 'JustForCPV' inside an 'Applicative' functor.
-- If chain parameter version 0, then 'NothingForCPV1' otherwise 'JustForCPV1' with @a@.
justForCPV1A ::
    forall cpv f a.
    (Applicative f, IsChainParametersVersion cpv) =>
    f a ->
    f (JustForCPV1 cpv a)
justForCPV1A a =
    case chainParametersVersion @cpv of
        SCPV0 -> pure NothingForCPV1
        SCPV1 -> JustForCPV1 <$> a

-- |Project the value from @JustForCPV1 'ChainParametersV1 a@.
unJustForCPV1 :: JustForCPV1 'ChainParametersV1 a -> a
unJustForCPV1 (JustForCPV1 a) = a

-- |Elimination rule for 'JustForCPV1'. Maps to @b@ when nothing and applies function when just.
maybeForCPV1 :: b -> (a -> b) -> JustForCPV1 cpv a -> b
maybeForCPV1 b _ NothingForCPV1 = b
maybeForCPV1 _ f (JustForCPV1 a) = f a

instance Functor (JustForCPV1 cpv) where
    fmap _ NothingForCPV1 = NothingForCPV1
    fmap f (JustForCPV1 a) = JustForCPV1 (f a)

instance Foldable (JustForCPV1 cpv) where
    foldr _ b NothingForCPV1 = b
    foldr f b (JustForCPV1 a) = f a b

    foldl _ b NothingForCPV1 = b
    foldl f b (JustForCPV1 a) = f b a

    foldMap _ NothingForCPV1 = mempty
    foldMap f (JustForCPV1 a) = f a

instance Traversable (JustForCPV1 cpv) where
    traverse _ NothingForCPV1 = pure NothingForCPV1
    traverse f (JustForCPV1 a) = JustForCPV1 <$> f a

instance
    (Serialize a, IsChainParametersVersion cpv) =>
    Serialize (JustForCPV1 cpv a)
    where
    put NothingForCPV1 = return ()
    put (JustForCPV1 a) = put a

    get = case chainParametersVersion @cpv of
        SCPV0 -> return NothingForCPV1
        SCPV1 -> JustForCPV1 <$> get
