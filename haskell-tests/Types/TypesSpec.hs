{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections, OverloadedStrings, LambdaCase #-}
module Types.TypesSpec where

import Types.CoreAllGen

import Concordium.Types
import Concordium.Types.Acorn.Core

import qualified Data.Vector as Vec

import Test.Hspec
import Test.QuickCheck

import Control.Monad
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

applySpec :: Property
applySpec = forAll (arbitrary :: Gen Word8) $
            \n -> forAll (replicateM (fromIntegral n) genType) $
            \inst -> forAll (genTypeBounded (fromIntegral n)) $
            \t -> forAll (arbitrary :: Gen Word8) $
            \lift -> let closed = applyTy (map (liftFreeBy (fromIntegral lift)) inst) t
                     in checkAppliedLiftedTyEq (fromIntegral lift) (Vec.fromList inst) t closed

applyTyTests :: Spec
applyTyTests =
  describe "applyTy" $ do
    let appTy :: [Type UA ModuleRef] -> Type UA ModuleRef -> Type UA ModuleRef
        appTy = applyTy
    -- Nothing to substitute
    specify "A1" $ appTy
      [TArr (TVar $ BTV 2) (TVar $ BTV 2)]
      (TForall $ TForall $ TArr (TVar $ BTV 0) (TVar $ BTV 1))
      `shouldBe`
      (TForall $ TForall $ TArr (TVar $ BTV 0) (TVar $ BTV 1))
    -- Substitute without lifting
    specify "A2" $ appTy
      [TBase TInt64]
      (TForall $ TArr (TVar $ BTV 0) (TVar $ BTV 1))
      `shouldBe`
      (TForall $ TArr (TVar $ BTV 0) (TBase TInt64))
    -- Substitute with lifting
    specify "A3" $ appTy
      [TArr (TVar $ BTV 2) (TVar $ BTV 2)]
      (TForall $ TArr (TVar $ BTV 0) (TVar $ BTV 1))
      `shouldBe`
      (TForall $ TArr (TVar $ BTV 0) (TArr (TVar $ BTV 3) (TVar $ BTV 3)))
    let s4 = TForall $ TArr (TVar $ BTV 0) $ TArr (TVar $ BTV 1) $
               TForall $ TArr (TVar $ BTV 0) $ TArr (TVar $ BTV 1) $ (TVar $ BTV 2)
    specify "A4a" $ appTy
      [TVar $ BTV 0]
      s4
      `shouldBe`
      (TForall $ TArr (TVar $ BTV 0) $ TArr (TVar $ BTV 1) $
        TForall $ TArr (TVar $ BTV 0) $ TArr (TVar $ BTV 1) $ (TVar $ BTV 2))
    specify "A4b" $ appTy
      [TVar $ BTV 1]
      s4
      `shouldBe`
      (TForall $ TArr (TVar $ BTV 0) $ TArr (TVar $ BTV 2) $
        TForall $ TArr (TVar $ BTV 0) $ TArr (TVar $ BTV 1) $ (TVar $ BTV 3))
    -- Apply multiple
    specify "A5" $ appTy
      [TBase TInt64, TBase TInt128]
      (TArr (TVar $ BTV 0) (TVar $ BTV 1))
      `shouldBe`
      (TArr (TBase TInt64) (TBase TInt128))

substTyTests :: Spec
substTyTests =
  describe "substTy" $ do
    let substTy' :: Type UA ModuleRef -> Type UA ModuleRef -> Type UA ModuleRef
        substTy' = substTy
    -- Nothing to substitute, but renaming
    specify "S1" $ substTy'
      (TArr (TVar $ BTV 2) (TVar $ BTV 2))
      (TForall $ TForall $ TArr (TVar $ BTV 0) (TVar $ BTV 1))
      `shouldBe`
      (TArr (TVar $ BTV 1) (TVar $ BTV 1))
    -- Nothing to substitute or rename
    specify "S2" $ substTy'
      (TForall $ TForall $ TArr (TVar $ BTV 0) (TVar $ BTV 1))
      (TArr (TVar $ BTV 2) (TVar $ BTV 2))
      `shouldBe`
      (TForall $ TForall $ TArr (TVar $ BTV 0) (TVar $ BTV 1))
    -- Substitute without lifting or rename
    specify "S3" $ substTy'
      (TForall $ TArr (TVar $ BTV 0) (TVar $ BTV 1))
      (TBase TInt64)
      `shouldBe`
      (TForall $ TArr (TVar $ BTV 0) (TBase TInt64))
    -- Substitute with lifting but otherwise no rename
    specify "S4" $ substTy'
      (TForall $ TArr (TVar $ BTV 0) (TVar $ BTV 1))
      (TArr (TVar $ BTV 2) (TVar $ BTV 2))
      `shouldBe`
      (TForall $ TArr (TVar $ BTV 0) (TArr (TVar $ BTV 3) (TVar $ BTV 3)))
    -- Substitute with lifting but otherwise no rename
    let s4 = TForall $ TArr (TVar $ BTV 0) $ TArr (TVar $ BTV 1) $
              TForall $ TArr (TVar $ BTV 0) $ TArr (TVar $ BTV 1) $ (TVar $ BTV 2)
    specify "S5a" $ substTy'
      s4
      (TVar $ BTV 0)
      `shouldBe`
      (TForall $ TArr (TVar $ BTV 0) $ TArr (TVar $ BTV 1) $
        TForall $ TArr (TVar $ BTV 0) $ TArr (TVar $ BTV 1) $ (TVar $ BTV 2))
    specify "S5b" $ substTy'
      s4
      (TVar $ BTV 1)
      `shouldBe`
      (TForall $ TArr (TVar $ BTV 0) $ TArr (TVar $ BTV 2) $
        TForall $ TArr (TVar $ BTV 0) $ TArr (TVar $ BTV 1) $ (TVar $ BTV 3))
    -- Substitute with lifting and rename of other free variables
    let s5 = TForall $ TArr (TVar $ BTV 0) $ TArr (TVar $ BTV 1) $ (TVar $ BTV 2)
    specify "S6a" $ substTy'
      s5
      (TVar $ BTV 0)
      `shouldBe`
      (TForall $ TArr (TVar $ BTV 0) $ TArr (TVar $ BTV 1) $ (TVar $ BTV 1))
    specify "S6b" $ substTy'
      s5
      (TVar $ BTV 1)
      `shouldBe`
      (TForall $ TArr (TVar $ BTV 0) $ TArr (TVar $ BTV 2) $ (TVar $ BTV 1))


tests :: Spec
tests = describe "Substitution + equality testing." $ do
  specify "Substitution with top-level foralls" (withMaxSuccess 10000 substSpec)
  specify "Lifted type equality check" (withMaxSuccess 10000 liftedSpec)
  specify "Nested foralls unit test" nestedTest
  specify "Type instantiation with lifting" applySpec
  applyTyTests
  substTyTests

