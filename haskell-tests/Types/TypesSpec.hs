{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections, OverloadedStrings, LambdaCase #-}
module Types.TypesSpec where

import Types.CoreAllGen

import Concordium.Types
import Concordium.Types.Acorn.Core

import Test.Hspec
import Test.QuickCheck

import Data.Word

repeatSubst :: [Type annot origin]
            -> Type annot origin
            -> Type annot origin
repeatSubst [] t = t
repeatSubst (t:tys) (TForall body) = repeatSubst tys (substTy body t)
repeatSubst _ _ = error "Should not occur. Test input incorrect."

substSpec :: Property
substSpec = forAll (listOf genType) $
            \subst -> forAll (arbitrary :: Gen Word32) $
            \lift -> forAll genType $
            \body -> let n = length subst
                         closed = last . take (fromIntegral n + 1) . iterate TForall $ body
                     in checkTyEqWithSubst (fromIntegral lift) subst closed (repeatSubst subst (liftFreeBy (fromIntegral lift) closed))

liftedSpec :: Property
liftedSpec = forAll genType $
             \ty -> forAll (arbitrary :: Gen Word32) $
             \n -> checkLiftedTyEq (fromIntegral n) 0 ty (liftFreeBy (fromIntegral n) ty)
                   && checkLiftedTyEq 0 (fromIntegral n) (liftFreeBy (fromIntegral n) ty) ty


nestedTest :: Bool
nestedTest =                                         
    let t :: Type UA ModuleRef
        t = TForall (TVar (BTV 0))
        subst = [t, TVar (BTV 0)]
        goalTy = TVar (BTV 0)
    in checkTyEqWithSubst 0 subst t goalTy

tests :: Spec
tests = describe "Substitution + equality testing." $ do
  specify "Substitution with top-level foralls" (withMaxSuccess 10000 substSpec)
  specify "Lifted type equality check" (withMaxSuccess 10000 liftedSpec)
  specify "Nested foralls unit test" nestedTest

