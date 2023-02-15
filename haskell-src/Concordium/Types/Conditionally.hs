{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |This module provides the 'Conditionally' type, which is parametrised by a type-level 'Bool',
-- and wraps a value if the parameter is 'True' and unit if the parameter is 'False'.
-- This can be seen as like 'Maybe', except the type can constrain whether the value is present
-- or not. (Unlike 'Just', however, 'CTrue' is strict in its argument.)
module Concordium.Types.Conditionally where

import Data.Bool.Singletons
import Data.Serialize
import Data.Singletons
import Lens.Micro.Platform

-- |A @Conditionally b a@ is an @a@ if @b ~ 'True@, and @()@ otherwise.
data Conditionally (b :: Bool) a where
    CFalse :: Conditionally 'False a
    CTrue :: !a -> Conditionally 'True a

instance Functor (Conditionally b) where
    fmap _ CFalse = CFalse
    fmap f (CTrue v) = CTrue (f v)

instance Foldable (Conditionally b) where
    foldr _ b CFalse = b
    foldr f b (CTrue a) = f a b

    foldl _ b CFalse = b
    foldl f b (CTrue a) = f b a

    foldMap _ CFalse = mempty
    foldMap f (CTrue a) = f a

instance Traversable (Conditionally b) where
    traverse _ CFalse = pure CFalse
    traverse f (CTrue a) = CTrue <$> f a

instance (Eq a) => Eq (Conditionally b a) where
    CFalse == CFalse = True
    CTrue a == CTrue b = a == b

instance (Ord a) => Ord (Conditionally b a) where
    compare CFalse CFalse = EQ
    compare (CTrue x) (CTrue y) = compare x y

instance (Show a) => Show (Conditionally b a) where
    show CFalse = "<CFalse>"
    show (CTrue v) = "<CTrue> " ++ show v

instance (Serialize a, SingI b) => Serialize (Conditionally b a) where
    put CFalse = return ()
    put (CTrue a) = put a

    get = case sing @b of
        SFalse -> pure CFalse
        STrue -> CTrue <$> get

-- |Wrap a value in a 'Conditionally' depending on the supplied 'SBool'.
conditionally :: SBool b -> a -> Conditionally b a
conditionally SFalse _ = CFalse
conditionally STrue a = CTrue a

-- |Perform an action conditionally on the supplied 'SBool'.
-- This is typically used for monadic actions.
-- The action is not performed in the 'SFalse' case.
conditionallyA :: (Applicative f) => SBool b -> f a -> f (Conditionally b a)
conditionallyA SFalse _ = pure CFalse
conditionallyA STrue m = CTrue <$> m

-- |A lens for accessing the contents of a 'Conditionally' when the guard is known to be 'True'.
unconditionally :: Lens (Conditionally 'True a) (Conditionally 'True b) a b
unconditionally f (CTrue a) = CTrue <$> f a

-- |Unwrap a conditionally when the guard is 'True'.
uncond :: Conditionally 'True a -> a
uncond (CTrue a) = a
