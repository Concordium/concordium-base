{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}

-- |Implementation of a maybe GADT which contains a value for chain parameter versions >= 1
-- and nothing for chain parameter version 0.
module Concordium.Types.ProtocolVersion.JustForCPV1 (
    JustForCPV1 (..),
    justForCPV1,
    maybeForCPV1
) where

import Data.Serialize

import qualified Concordium.Crypto.SHA256 as SHA256
import Concordium.Types.HashableTo
import Concordium.Types.ProtocolVersion

-- |A value for chain parameter versions >= 1 and nothing for chain parameter version 0.
data JustForCPV1 (cpv :: ChainParametersVersion) a where
    NothingForCPV1 :: forall a. JustForCPV1 'ChainParametersV0 a
    JustCPV1ForCPV1 :: forall a. !a -> JustForCPV1 'ChainParametersV1 a

deriving instance Eq a => Eq (JustForCPV1 cpv a)
deriving instance Show a => Show (JustForCPV1 cpv a)

-- |Project the value from @JustForCPV1 'ChainParametersV1 a@.
justForCPV1 :: JustForCPV1 'ChainParametersV1 a -> a
justForCPV1 (JustCPV1ForCPV1 a) = a

maybeForCPV1 :: b -> (a -> b) -> JustForCPV1 cpv a -> b
maybeForCPV1 b _ NothingForCPV1 = b
maybeForCPV1 _ f (JustCPV1ForCPV1 a) = f a

instance Functor (JustForCPV1 cpv) where
    fmap _ NothingForCPV1 = NothingForCPV1
    fmap f (JustCPV1ForCPV1 a) = JustCPV1ForCPV1 (f a)

instance Foldable (JustForCPV1 cpv) where
    foldr _ b NothingForCPV1 = b
    foldr f b (JustCPV1ForCPV1 a) = f a b

    foldl _ b NothingForCPV1 = b
    foldl f b (JustCPV1ForCPV1 a) = f b a

    foldMap _ NothingForCPV1 = mempty
    foldMap f (JustCPV1ForCPV1 a) = f a

instance Traversable (JustForCPV1 cpv) where
    traverse _ NothingForCPV1 = pure NothingForCPV1
    traverse f (JustCPV1ForCPV1 a) = JustCPV1ForCPV1 <$> f a

instance
    (Serialize a, IsChainParametersVersion cpv) =>
    Serialize (JustForCPV1 cpv a)
    where
    put NothingForCPV1 = return ()
    put (JustCPV1ForCPV1 a) = put a

    get = case chainParametersVersion @cpv of
        SCPV0 -> return NothingForCPV1
        SCPV1 -> JustCPV1ForCPV1 <$> get

instance HashableTo SHA256.Hash a => HashableTo SHA256.Hash (JustForCPV1 cpv a) where
    getHash NothingForCPV1 = SHA256.hash "NothingForCPV1"
    getHash (JustCPV1ForCPV1 a) = SHA256.hashOfHashes (SHA256.hash "JustCPV1ForCPV1") (getHash a)

instance MHashableTo m SHA256.Hash a => MHashableTo m SHA256.Hash (JustForCPV1 cpv a) where
    getHashM NothingForCPV1 =
        return $ SHA256.hash "NothingForCPV1"
    getHashM (JustCPV1ForCPV1 a) =
        SHA256.hashOfHashes (SHA256.hash "JustCPV1ForCPV1") <$> getHashM a
