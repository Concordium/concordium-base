{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE DeriveFoldable #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveGeneric #-}
{-# OPTIONS_GHC -Wall #-}
module Concordium.Types.Acorn.Core(module Concordium.Types.Acorn.Core,
                                   ModuleRef(..))
where

import GHC.Types(Constraint)
import Data.Data(Typeable, Data)
import Data.Void

import Data.ByteString.Char8(ByteString)
import qualified Data.ByteString.Char8 as BS

import GHC.Generics

import Prelude hiding (mod)

import qualified Data.Serialize.Put as P
import qualified Data.Serialize.Get as G
import qualified Data.Serialize as S

import Data.Hashable(Hashable)

import Control.Monad

import Data.Int
import Data.Bits
import qualified Data.Vector as Vec
import Data.Word
import qualified Concordium.Types.Acorn.NumericTypes as NumTys

import qualified Concordium.Crypto.SHA256 as SHA256
import Concordium.Types

type family ExprAnnot a
type family PatternAnnot a
type family TypeAnnot a

data UA -- used to express a term/pattern/type is unannotated
  deriving(Data, Typeable)

type instance ExprAnnot UA = Void
type instance TypeAnnot UA = Void
type instance PatternAnnot UA = Void

type AnnotContext (c :: * -> Constraint) (a :: *) =
  (c (ExprAnnot a),
   c (PatternAnnot a),
   c (TypeAnnot a))

-- Basic literals supported by the language.
-- TODO: Will need to be modified based on experience with examples.
data Literal =
  Str !ByteString
  | Int32 !Int32
  | Int64 !Int64
  | Int128 !NumTys.Int128
  | Int256 !Integer -- TODO adapt when implementing Int256
  | Word32 !Word32
  | Word64 !Word64
  | Word128 !NumTys.Word128
  | Word256 !Integer -- TODO adapt when implementing Word256
  | ByteStr32 !ByteString
  | CAddress !ContractAddress
  | AAddress !AccountAddress
  deriving (Show, Eq, Generic, Typeable, Data)

instance Hashable Literal

-- |Allowed names are only 32-bit unsigned integers. The reason for not having strings as
-- variable names is that that makes the cost of certain operations during
-- type-checking more complex. For instance we cannot assume that string
-- comparison is constant time, nor can we use ordinary hash maps since a
-- program could be crafted so that it causes quadratic time lookup. Of course
-- we could use a different hash-function for strings, but that will be slower,
-- and again, it is another thing to consider in the implementation, and thus we
-- rather avoid it.
newtype Name = Name Word32
    deriving(Show, Eq, Generic, Hashable, Real, Integral, Enum, Ord, Num, Typeable, Data)

newtype BoundVar = BV Word32
    deriving(Show, Eq, Generic, Hashable, Real, Integral, Enum, Ord, Num, Typeable, Data)

newtype BoundTyVar = BTV Word32
    deriving(Show, Eq, Generic, Hashable, Real, Integral, Enum, Ord, Num, Typeable, Data)

data Variable boundvar name origin =
  -- |Variables bound by lambda abstractions.
  BoundVar !boundvar
  -- |Variables referring to local definitions.
  | LocalDef !name
  -- |Variables referring to imported definitions.
  | Imported !name !origin
    deriving (Show, Eq, Generic, Functor, Foldable, Traversable, Typeable, Data)

instance (Hashable a, Hashable b, Hashable c) => Hashable (Variable a b c)

-- |Values needed to express let-normal form of expressions.
data Atom origin =
  Literal !Literal
  | Var !(Variable BoundVar Name origin)
  deriving (Eq, Show, Functor, Foldable, Traversable, Typeable, Data)

data Expr annot origin
  = 
  -- |Basic literals and variables.
  Atom !(Atom origin)
  -- |An anonymous function with type of its argument. We use the de-bruijn
  -- representation of bound variables, hence no variable name.
  | Lambda !(Type annot origin) !(Expr annot origin)
  -- |Type abstraction term (big lambda). Again with de-bruijn convention. Note
  -- that type and term variables are different classes, so going under a type
  -- binder only increases De-Bruijn level of type variables.
  | TLambda !(Expr annot origin)
  -- |Application of an expression to a list of atoms.
  -- We use a list to be able to reduce the number of intermediate annotations needed.
  | App !(Atom origin) ![Atom origin]
  -- |Local let binding, non-recursive (Let e e') is let e in e' (we use
  -- De-Bruijn convention here as well).
  | Let !(Type annot origin) !(Expr annot origin) !(Expr annot origin)
  -- |Mutually recursive let. The list of binders can be empty. In the example
  -- 
  -- @
  --    letrec [(tdom1, e1, tcod1), (tdom2, e2, tcod2)] ebody
  -- @
  -- 
  --   * in expressions @e1@ and @e2@ DeBruijn index 0 refers to the local variable
  --     and indices 1 and 2 refer to the functions defined by @e2@ and @e1@ respectively
  --   * in expression @ebody@ DeBruijn index 0 refers to (the functions defined by) @e2@ and 1 to @e1@
  | LetRec ![(Type annot origin, Expr annot origin, Type annot origin)] !(Expr annot origin)
  -- |Case expression, the list of alternatives should be non-empty. In bodies
  -- of branches we again use the De-Bruijn convention. The type is the result type of all the branches.
  | Case !(Atom origin) ![(Pattern annot origin, Expr annot origin)]
  -- |Type application (instantiation of universally qualified term) with a list of types.
  -- We use a list of types in order to reduce the need for typing annotations for intermediate applications.
  -- The list can be empty, in which case the term is equivalent to the first one.
  | TypeApp !(Atom origin) ![Type annot origin]
  -- |Free-form annotation. The field is strict so that setting annot=Data.Void
  -- we can disable this constructor.
  | EAnnot !(ExprAnnot annot) !(Expr annot origin)
  deriving (Generic, Functor, Foldable, Traversable)

deriving instance (AnnotContext Eq annot, Eq origin) => Eq (Expr annot origin)
deriving instance (AnnotContext Show annot, Show origin) => Show (Expr annot origin)
deriving instance (AnnotContext Typeable annot, Data origin) => Typeable (Expr annot origin)
deriving instance (AnnotContext Data annot, Data origin, Data annot) => Data (Expr annot origin)

-- TODO: We could simply merge PCtor and PVar into one and just use variable for
-- everything.

-- |We do not allow nested patterns since checking incompleteness is NP-hard,
-- which we cannot allow for security reasons.
data Pattern annot origin =
  -- |We do not need to give it a name because we are using De-Bruijn convention for bound variables.
  PVar
  -- |Fully instantiated constructor. Constructor can be either locally declared or imported.
  | PCtor !(CTorName origin) ![Type annot origin]
  -- |And finally we can match on literals.
  -- NB:FIXME:This will probably need to be narrowed since matching 128-byte
  -- strings is quite different than matching ints, and we probably do not want
  -- to allow matching on all literals.
  | PLiteral !Literal
  | PAnnot !(PatternAnnot annot) !(Pattern annot origin)
  deriving (Generic, Functor, Foldable, Traversable)

deriving instance (AnnotContext Eq annot, Eq origin) => Eq (Pattern annot origin)
deriving instance (AnnotContext Show annot, Show origin) => Show (Pattern annot origin)
deriving instance (AnnotContext Typeable annot, Data origin) => Typeable (Pattern annot origin)
deriving instance (AnnotContext Data annot, Data origin, Data annot) => Data (Pattern annot origin)

data CTorName origin = LocalCTor {ctorName :: !Name}
                     | ImportedCTor {ctorName :: !Name
                                    ,ctorOrigin :: !origin
                                    }
  deriving (Eq, Show, Generic, Functor, Foldable, Traversable, Typeable, Data)

instance Hashable origin => Hashable (CTorName origin)

data TBase =
           TInt32
           | TInt64
           | TInt128
           | TInt256
           | TWord32
           | TWord64
           | TWord128
           | TWord256
           | TByteString
           | TByteStr32
           | TCAddress  -- contract address 
           | TAAddress  -- account address
    deriving (Show, Eq, Generic, Typeable, Data)

-- |To be able to know whether a set of patterns is exhaustive we need to know how many inhabitants there are of a particular type.
numInhab :: TBase -> Maybe Integer
numInhab TInt32 = Just $ 2^(32 :: Int)
numInhab TInt64 = Just $ 2^(64 :: Int)
numInhab TWord32 = Just $ 2^(32 :: Int)
numInhab TWord64 = Just $ 2^(64 :: Int)
numInhab _ = Nothing -- infinity for the purposes of typechecking.


instance Hashable TBase 

-- |Equivalent to Name, but separated for sanity checking.
newtype TyName = TyName Word32
    deriving(Show, Eq, Generic, Hashable, Real, Integral, Enum, Ord, Num, Typeable, Data)

data DataTyName origin = LocalDataTy {dataTyName :: !TyName}
                       | ImportedDataTy {dataTyName :: !TyName
                                        ,dataTyOrigin :: !origin
                                        }
  deriving (Eq, Show, Generic, Functor, Foldable, Traversable, Typeable, Data)

instance Hashable origin => Hashable (DataTyName origin)

-- |NB: Eq is alpha equality because we are using DeBruijn indices. This is only
-- true if the 'TAnnot' node cannot be constructed or if equality on @annot@
-- is total.
data Type annot origin =
  -- |Polymorphic quantification. Using De-Bruijn representation.
  TForall !(Type annot origin)
  -- |Function types.
  | TArr !(Type annot origin) !(Type annot origin)
  -- |Bound type variables. Note that namespaces for bound type and term variables are distinct.
  | TVar !BoundTyVar
  -- |Type application, i.e., List Int. This will always be "declared datatype applied to types".
  | TApp !(DataTyName origin) ![(Type annot origin)]
  -- |Base types.
  | TBase !TBase
  | TAnnot !(TypeAnnot annot) !(Type annot origin)
  deriving (Generic, Functor, Foldable, Traversable)

deriving instance (AnnotContext Show annot, Show origin) => Show (Type annot origin)
deriving instance (AnnotContext Typeable annot) => Typeable (Type annot origin)
deriving instance (AnnotContext Data annot, Data origin, Data annot) => Data (Type annot origin)

-- |The Eq instance ignores annotations.
instance Eq origin => Eq (Type annot origin) where
    {-# INLINE (==) #-}
    (==) = alphaEq

alphaEq :: Eq origin => Type annot origin -> Type annot origin -> Bool
alphaEq = go
  where go (TForall t1) (TForall t2) = go t1 t2
        go (TArr t1 t1') (TArr t2 t2') = go t1 t2 && go t1' t2'
        go (TVar v) (TVar v') = v == v'
        go (TApp n tys) (TApp n' tys') =
          n == n' &&
          length tys == length tys' &&
          (and $ zipWith go tys tys')
        go (TBase b) (TBase b') = b == b'
        go (TAnnot _ t) t' = go t t'
        go t (TAnnot _ t') = go t t'
        go _ _ = False

eraseAnnot :: Type annot origin -> Type annot' origin
eraseAnnot = go
    where go :: Type annot origin -> Type annot' origin
          go (TForall t1) = TForall (go t1)
          go (TArr t1 t1') = TArr (go t1) (go t1')
          go (TVar v) = TVar v
          go (TApp n tys) = TApp n (map go tys)
          go (TBase b) = TBase b
          go (TAnnot _ t) = go t

-- | A data constructor has a name, and an arity.
-- For instance, the arity of polymorphic list Cons is going to be [α, List α]
-- and the variable α must be listed in the type variables of DataType below.
-- Since we are using DeBruijn indices this concretely means that α < dtParams.
data DataCon annot origin = DataCon {dcName :: !Name
                                    , dcArity :: ![Type annot origin] }
  deriving (Generic, Functor, Traversable, Foldable)

deriving instance (AnnotContext Eq annot, Eq origin) => Eq (DataCon annot origin)
deriving instance (AnnotContext Show annot, Show origin) => Show (DataCon annot origin)
deriving instance (AnnotContext Typeable annot, Typeable v) => Typeable (DataCon annot v)
deriving instance (AnnotContext Data annot, Data annot, Data v) => Data (DataCon annot v)


-- | A datatype declaration is a name, plus the number of type parameters, plus
-- a non-empty list of constructors.
data DataType annot origin =
  DataType {
  dtVis :: !DataTyVisibility
  , dtName :: !TyName
  , dtParams :: !Word32 -- ^The number of parameters. Use DeBruijn to refer to them.
  , dtCons :: ![DataCon annot origin]
  }
  deriving (Generic, Functor, Traversable, Foldable)

deriving instance (AnnotContext Eq annot, Eq origin) => Eq (DataType annot origin)
deriving instance (AnnotContext Show annot, Show origin) => Show (DataType annot origin)
deriving instance (AnnotContext Typeable annot, Typeable v) => Typeable (DataType annot v)
deriving instance (AnnotContext Data annot, Data annot, Data v) => Data (DataType annot v)

-- |The parameter v in 'Sender' and 'Getter' are going to be instantiated with
-- Type in 'ConstraintDecl' and with 'Expr' in 'ConstraintImpl'.
data Sender v = Sender { 
                       sName :: !Name
                       , sVal :: !v
                       }
    deriving (Show, Eq, Generic, Functor, Foldable, Traversable, Typeable, Data)

data Getter v = Getter {
                       gName :: !Name
                       , gVal :: !v
                       }
    deriving (Show, Eq, Generic, Functor, Foldable, Traversable, Typeable, Data)

data ConstraintDecl annot v
    = ConstraintDecl
      {
      constraintName :: !TyName
      -- |Senders of a constraint are methods which can be used to send messages to
      -- other contracts. They should be of type (and will be typechecked to be)
      -- Instance(n) -> t -> Amount -> Transaction where Instance(n) is the contraint
      -- type introduced by this declaration.
      , senders   :: ![Sender (Type annot v)] 
      -- |Getters of a constraint are methods which can be used to access the state
      -- of any instance implementing this class. They should be of type (and will be
      -- typechecked to be) Instance(n) -> t where Instance(n) is the contraint
      -- type introduce by this declaration.
      , getters   :: ![Getter (Type annot v)] 
      }
    deriving (Generic, Functor, Foldable, Traversable)

deriving instance (AnnotContext Eq annot, Eq origin) => Eq (ConstraintDecl annot origin)
deriving instance (AnnotContext Show annot, Show origin) => Show (ConstraintDecl annot origin)
deriving instance (AnnotContext Typeable annot, Typeable v) => Typeable (ConstraintDecl annot v)
deriving instance (AnnotContext Data annot, Data annot, Data v) => Data (ConstraintDecl annot v)

-- |Canonical reference to a constraint.
data ConstraintRef origin = ImportedCR {crName :: !TyName, crMod :: !origin}
                          | LocalCR { crName :: !TyName }
  deriving(Show, Eq, Ord, Generic, Foldable, Functor, Traversable, Typeable, Data)

instance Hashable a => Hashable (ConstraintRef a)

data ConstraintImpl annot origin
    = ConstraintImpl
      {
      constraintNameImpl :: ConstraintRef origin
      , sendersImpl   :: ![Sender (Expr annot origin)] 
      , gettersImpl   :: ![Getter (Expr annot origin)] 
      }
    deriving (Generic, Functor, Foldable, Traversable)

deriving instance (AnnotContext Eq annot, Eq origin) => Eq (ConstraintImpl annot origin)
deriving instance (AnnotContext Show annot, Show origin) => Show (ConstraintImpl annot origin)
deriving instance (AnnotContext Typeable annot, Typeable origin) => Typeable (ConstraintImpl annot origin)
deriving instance (AnnotContext Data annot, Data origin, Data annot) => Data (ConstraintImpl annot origin)

-- |A contract has a name, an init method, and a receive method. The type of
-- local state is inferred from the type of the init method, and the type of
-- messages the contract can receive is inferred from the type of the receive
-- method. Moreover, the contract can "implement" or be an instance of a number
-- of constraints (by name).
data Contract annot a = Contract {
  cName :: !TyName
  , cInit :: !(Expr annot a)
  , cReceive :: !(Expr annot a)
  , cInstances :: ![ConstraintImpl annot a]
  }
  deriving(Generic)

deriving instance (AnnotContext Eq annot, Eq origin) => Eq (Contract annot origin)
deriving instance (AnnotContext Show annot, Show origin) => Show (Contract annot origin)
deriving instance (AnnotContext Typeable annot, Typeable origin) => Typeable (Contract annot origin)
deriving instance (AnnotContext Data annot, Data origin, Data annot) => Data (Contract annot origin)

-- * Utility functions used during typechecking.

-- |Apply a type to a list of types: If n is the length of the list, replace the
-- first n free type variables in the type by the corresponding types in the
-- list. Concretely, if the type is @TApp c [BTV 0, BTV 1]@ list is @[Int64,
-- Word64]@ then the resulting type is @TApp c [Int64, Word64]@.
-- Binders are accounted for by lifting (i.e., substitution is capture avoiding).
-- For instance, if the type is @TForall (BTV 1)@
-- and the list is @[BTV 3]@ the resulting type will be @TForall (BTV 4)@.
-- 
-- If n is the length of the list then only free variables 0..n-1 are updated.
-- The rest are not changed.
-- 
-- This function can be used to instantiate the arity arguments of datatype
-- constructors.
-- 
-- NOTE: This should not be used during typechecking since it can be very costly
-- in relation to term size.
applyTy :: [Type annot origin] -> Type annot origin -> Type annot origin
applyTy ts t = go t 0
  where len :: Int
        len = length ts

        go s@(TBase _) _ = s
        go (TApp t1 t2) n = TApp t1 (map (flip go n) t2)
        go (TArr t1 t2) n = TArr (go t1 n) (go t2 n)
        go (TForall t1) n = TForall (go t1 (n+1))
        go ta@(TVar v) n | fromIntegral v >= n && fromIntegral v - n < len =
                           liftFreeBy (fromIntegral n) (ts !! (fromIntegral v - n))
                         | otherwise = ta -- in well-formed types this case only happen for bound variables ( v < n )
        go (TAnnot a ty) n = TAnnot a (go ty n)

-- |'substTy' τ₁ τ₂ replaces the first free type variable (the one with the
-- lowest De-Bruijn index) in τ₁ with τ₂. This includes lifting in τ₂ to avoid
-- variable capture.
-- Moreover any remaining free variables are decreased. This is because this function is
-- meant to be used when the type being substituted into starts as ∀ α . τ and we substitute
-- for the variable α, removing a binder. This means that all variables in τ that point beyond
-- α must now be decreased.
-- 
-- Thus @substTy (0→1) 1 = 1→0@ and @substTy (∀(0→1)) (∀(0→1)) = ∀(0→(∀(0→2)))@.
-- 
-- NOTE: This should not be used during typechecking since it can cause
-- exponential blow up (by repeated use) in term size when we blindly substitute.
substTy :: Type annot origin -> Type annot origin -> Type annot origin
substTy t t' = go (fromIntegral (0::Word32)) t
  where go _ ty@(TBase _) = ty
        go n (TApp t1 t2) = TApp t1 (map (go n) t2)
        go n (TArr t1 t2) = TArr (go n t1) (go n t2)
        go n (TForall t1) = TForall (go (n+1) t1)
        -- FIXME: It is not clear that fromIntegral is always correct here.
        -- Documentation states it preserves representation, not sign.
        go n ta@(TVar v) | v == n = liftTy 0 n t'
                         | v > n = TVar (v-1) -- we have removed a binder, so must decrease the pointer
                         | otherwise = ta
        go n (TAnnot a ty) = TAnnot a (go n ty)

        liftTy _ _ ty@(TBase _) = ty
        liftTy l n (TApp t1 t2) = TApp t1 (map (liftTy l n) t2)
        liftTy l n (TArr t1 t2) = TArr (liftTy l n t1) (liftTy l n t2)
        liftTy l n (TForall t1) = TForall (liftTy (l+1) n t1)
        -- FIXME: It is not clear that fromIntegral is always correct here.
        -- Documentation states it preserves representation, not sign.
        liftTy l n ta@(TVar v) | v >= l = TVar (v + n)
                               | otherwise = ta
        liftTy l n (TAnnot a ty) = TAnnot a (liftTy l n ty)

-- |Given a list of types and a type of the shape ∀α₁⋯∀αₙ.τ, check
-- whether applying τ to the list of types results in the goal type.
-- This includes lifting in the to be applied types to avoid capturing as well as
-- correcting the names of free variables.
--
-- There is a complication this function must address and why it is not entirely straightforward.
-- Suppose we are instantiating the type ∀α.α with the list of [∀α.α, Int64].
-- The result should be Int64.
-- 
-- This function is equivalent to first repeatedly stripping a ∀ and using
-- 'substTy' to substitute the types and then using 'checkLiftedTyEq'.
{-# SPECIALIZE checkTyEqWithSubst :: BoundTyVar -> [Type UA ModuleRef] -> Type UA ModuleRef -> Type UA ModuleRef -> Bool #-}
checkTyEqWithSubst
  :: forall origin annot . Eq origin
  => BoundTyVar
  -- ^The number of levels the source type should be lifted by.
  -> [Type annot origin]
  -- ^The types to be applied to the source type. These can contain free type variables.
  -> Type annot origin
  -- ^The source type of the shape ∀α₁⋯∀αₙ.τ the given list of types is to be applied to. It can contain
  -- free type variables.
  -> Type annot origin
  -- ^The goal type the applied type is checked to be equal to. It can contain free type variables.
  -> Bool
checkTyEqWithSubst toLift subst ty goalTy =
  case getBody 0 0 subst ty of
    Nothing -> False
    Just (start, body) ->
      if start == 0 then process 0 (fromIntegral toLift) True 0 0 body goalTy
      else process (fromIntegral start) 0 True 0 0 body goalTy

  where getBody start _ [] body = Just (start, body)
        getBody start n (_:rest) (TForall body) = getBody start (n+1) rest body
        getBody start n (_:rest) (TVar v) | v < n =
          -- note that unsafeIndex here is safe because we maintain the invariant
          -- start + n < len
          let tyIdx = fromIntegral (start + fromIntegral (n - v))
          in getBody (tyIdx + 1) 0 rest (Vec.unsafeIndex vec tyIdx)
        getBody _ _ _ _ = Nothing

        vec = Vec.fromList subst

        len :: Int
        len = Vec.length vec

        isEqVar v (TVar v') = v == v'
        isEqVar _ _ = False

        process
          :: Int -- Location in 'vec' in which the substitution starts.
          -> Int -- How much to lift the top-level.
          -> Bool -- Whether we are the top-level and have to decrease vars due to removed binders.
          -> Int -- How much the variables ought to have been lifted in the left type.
          -> Int -- How many binders we are currently under.
          -> Type annot origin
          -> Type annot origin
          -> Bool
        process start iToLift = go
          where go remove lift binders (TApp t tys) (TApp t' tys')
                    | t == t' = allPairs (go remove lift binders) tys tys'
                    | otherwise = False
                go remove lift binders (TArr t1 t2) (TArr t1' t2') =
                    go remove lift binders t1 t1' && go remove lift binders t2 t2'
                go _ _ _ (TBase tb) (TBase tb') = tb == tb'
                go remove lift binders (TForall t1) (TForall t2) = go remove lift (binders + 1) t1 t2
                go remove lift binders (TVar v) t =
                  if v < fromIntegral binders then isEqVar v t
                  else if remove then -- we are at the top-level
                    if fromIntegral v - binders < len - start then
                      let testLevel = len - 1 - (start + fromIntegral v - binders)
                      in go False binders 0 (Vec.unsafeIndex vec testLevel) t
                    else isEqVar (fromIntegral (fromIntegral v - (len - start) + iToLift)) t
                  else
                    let correctLevel = v + fromIntegral lift in
                      isEqVar correctLevel t
                go remove lift binders (TAnnot _ t) t' = go remove lift binders t t'
                go remove lift binders t (TAnnot _ t') = go remove lift binders t t'
                go _ _ _ _ _ = False

-- |Apply the predicate to all pairs of values.
-- If the lists differ in length return @False@.
allPairs :: (a -> b -> Bool) -> [a] -> [b] -> Bool
allPairs p = go
  where go (x:xs) (y:ys) = 
          if p x y then go xs ys
          else False
        go [] [] = True
        go _ _ = False

-- |Check that two types, each lifted by a certain level, are equal.
-- Equivalent to @liftFreeBy l1 t1 == liftedFreeBy l2 t2@.
checkLiftedTyEq :: Eq origin => BoundTyVar -> BoundTyVar -> Type annot origin -> Type annot origin -> Bool
checkLiftedTyEq l1 l2 = go 0
  where go n (TApp t tys) (TApp t' tys') = t == t' && allPairs (go n) tys tys'
        go n (TArr t1 t2) (TArr t1' t2') = go n t1 t1' && go n t2 t2'
        go n (TAnnot _ t) t' = go n t t'
        go n t (TAnnot _ t') = go n t t'
        go _ (TBase tb) (TBase tb') = tb == tb'
        go n (TForall t) (TForall t') = go (n+1) t t'
        go n (TVar v) (TVar v')
            | v < n = v == v' -- bound variables
            | otherwise = v' >= n && v + l1 == v' + l2 -- free variables are lifted
        go _ _ _ = False

-- |Check whether a type applied to some types equals a given type. This
-- includes lifting in the to be applied types to avoid variable capture but
-- further free variables are not renamed. Equivalent to first using 'applyTy'
-- to substitute the types and then using 'checkLiftedTyEq'.
checkAppliedLiftedTyEq
  :: Eq origin
  => BoundTyVar
  -- ^The number of levels the source type should be lifted by.
  -> Vec.Vector (Type annot origin)
  -- ^The types to be applied to the source type. These can contain free type variables.
  -> Type annot origin
  -- ^The source type the given vector of types is to be applied to. It should
  -- have at most as many free type variables as the length n of the given
  -- vector of types (the function is still safe otherwise, and returns False).
  -- Up to n free type variables in τ are replaced by the corresponding types in
  -- the list (the one with the lowest De-Bruijn index with the first type in
  -- the list etc.).
  -> Type annot origin
  -- ^The goal type the applied type is checked to be equal to.
  -> Bool
checkAppliedLiftedTyEq lift inst = go 0
  where ninst = fromIntegral (length inst)

        go _ (TBase tb) (TBase tb') = tb == tb'
        go n (TArr t1 t2) (TArr t1' t2') = go n t1 t1' && go n t2 t2'
        go n (TAnnot _ t) t' = go n t t'
        go n t (TAnnot _ t') = go n t t'
        go n (TForall t1) (TForall t2) = go (n+1) t1 t2
        go n (TApp t tys) (TApp t' tys') = t == t' && allPairs (go n) tys tys'
        go n (TVar v) t
            | v < n =
              case t of
                TVar v' -> v == v'
                _ -> False
            | v - n < ninst =
                checkLiftedTyEq (lift + fromIntegral n) 0 (Vec.unsafeIndex inst (fromIntegral (v - n))) t
            -- The following case (a free variable with no type to substitute for) does not occur when the
            -- first given type has at most as many free variables as the length of the given vector of types.
            | otherwise = False
        go _ _ _ = False

-- |Lift all free variables by 1 (to be used when going under type lambda in typechecking terms).
liftFree :: Type annot origin -> Type annot origin
liftFree = liftFreeBy 1

-- |Lift all free variables by k (to be used when going under type lambda in typechecking terms).
liftFreeBy :: BoundTyVar -> Type annot origin -> Type annot origin
liftFreeBy k = if k == 0 then id else go 0
  where go _ ty@(TBase _) = ty
        go n (TApp t1 t2) = TApp t1 (map (go n) t2)
        go n (TArr t1 t2) = TArr (go n t1) (go n t2)
        go n (TForall t1) = TForall (go (n+1) t1)
        go n ta@(TVar v) | v >= n = TVar (v+k)
                         | otherwise = ta
        go n (TAnnot a t) = TAnnot a (go n t)

-- *The notion of a module.

-- | A module import "import Foo as bar". The reason for having this is to
-- reduce space usage and so that it is easy to determine which modules to look
-- up up front. Foo will be a unique id of the module deployed on the chain
-- (currently defined as a 32-byte hash of the serialized module content) and
-- ModuleName is a short 4-byte identifier local to the module.
data Import = Import {iModule :: ModuleRef
                     ,iAs :: ModuleName
                     }
  deriving(Show, Eq, Generic, Typeable, Data)

data Definition annot origin = Definition {
  dVis :: !Visibility
  , dName :: !Name
  , dType :: !(Type annot origin)
  , dExpr :: !(Expr annot origin)
  }
  deriving (Generic, Functor, Foldable, Traversable)

deriving instance (AnnotContext Eq annot, Eq origin) => Eq (Definition annot origin)
deriving instance (AnnotContext Show annot, Show origin) => Show (Definition annot origin)
deriving instance (AnnotContext Typeable annot, Typeable origin) => Typeable (Definition annot origin)
deriving instance (AnnotContext Data annot, Data origin, Data annot) => Data (Definition annot origin)

-- |Name, but differentiated for sanity checking. But in practice there can never be a confusion between module names and term and type names.
newtype ModuleName = ModuleName { moduleName :: Word32 }
    deriving(Show, Eq, Ord, Enum, Generic, Hashable, Num, Real, Integral, Typeable, Data)

-- Version of the environment the contract is valid for. Should probably be something more structured than a word.
type Version = Word32

-- |This is the unit that can be deployed on the chain. The module should not be
-- empty, so there should be either a non-empty list of constracts, constraints, or contracts.
data Module annot =
  Module { 
         mImports :: ![Import]
         , mDataTypes :: ![DataType annot ModuleName]
         , mConstraintDecls :: ![ConstraintDecl annot ModuleName]
         -- |List of pure functions provided by the module. These should not have any "effectful" operations, such as
         -- reading state of the blockchain, or sending messages, etc. This is part of a well-formedness check.
         , mDefs :: ![Definition annot ModuleName]
         -- |A possibly empty list of contracts.
         , mContracts :: ![Contract annot ModuleName]
         -- |Version number of this module, i.e., which language version it corresponds to.
         , mVersion :: !Version
         }
  deriving (Generic)

deriving instance (AnnotContext Eq annot) => Eq (Module annot)
deriving instance (AnnotContext Show annot) => Show (Module annot)
deriving instance (AnnotContext Typeable annot) => Typeable (Module annot)
deriving instance (AnnotContext Data annot, Data annot) => Data (Module annot)

-- |Visibility of a definition or type from within another module
-- (only public definitions and types can be accessed from other modules).
data Visibility = Public | Private
  deriving (Show, Eq, Generic, Typeable, Data)

-- |'Visibility' of a datatype's type and its constructors.
data DataTyVisibility = None -- ^ Both type and constructors are private.
                      | OnlyType -- ^ Only the type is public, the constructors are private.
                      | All -- ^ Both type and constructors are public.
  deriving(Show, Eq, Generic, Typeable, Data)

-- plays the role of the prim module. Invalid otherwise.
emptyModule :: Module annot
emptyModule = Module {
  mImports =  []
  , mDataTypes = []
  , mConstraintDecls = []
  , mDefs = []
  , mContracts = []
  , mVersion = 1
  }

-- * Expression and module serialization
-- The annotations on types/terms/patterns are completely ignored in
-- serialization.

instance S.Serialize Literal where
  get = getLit
  put = putLit

instance S.Serialize BoundVar where
  get = getBoundVar
  put = putBoundVar

instance S.Serialize origin => S.Serialize (Expr a origin) where
    get = getExpr
    put = putExpr

instance S.Serialize origin => S.Serialize (Type a origin) where
  get = getType
  put = putType

instance S.Serialize (Module annot) where
  get = getModule
  put = putModule

instance S.Serialize ModuleName where
  get = getModuleName
  put = putModuleName

instance S.Serialize Name where
  get = getName
  put = putName

instance S.Serialize TyName where
  get = getTyName
  put = putTyName

instance S.Serialize origin => S.Serialize (ConstraintDecl annot origin) where
  get = getConstraintDecl
  put = putConstraintDecl

putAtom :: S.Serialize origin => P.Putter (Atom origin)
putAtom (Literal l) =
  P.putWord8 0 <>
  putLit l
putAtom (Var at) =
  case at of
    BoundVar bv ->
      P.putWord8 1 <>
      putBoundVar bv
    LocalDef l ->
      P.putWord8 2 <>
      putName l
    Imported l orig ->
      P.putWord8 3 <>
      putName l <>
      S.put orig

putExpr :: S.Serialize origin => P.Putter (Expr annot origin)
putExpr (Atom a) =
  P.putWord8 0 <>
  putAtom a
putExpr (EAnnot _ e) = putExpr e
putExpr (Lambda ty body) =
  P.putWord8 1 <>
  putType ty <>
  putExpr body
putExpr (TLambda body) =
  P.putWord8 2 <>
  putExpr body
putExpr (App e1 e2) =
  P.putWord8 3 <>
  putAtom e1 <>
  putLength e2 <>
  mapM_ putAtom e2
putExpr (Let ty e1 e2) =
  P.putWord8 4 <>
  putType ty <>
  putExpr e1 <>
  putExpr e2
putExpr (LetRec fs e) =
  P.putWord8 5 <>
  putLength fs <>
  mapM_ (\(t, expr, t') -> putType t >> putExpr expr >> putType t') fs <>
  putExpr e
putExpr (Case e cases) =
  P.putWord8 6 <>
  putAtom e <>
  putLength cases <>
  mapM_ (\(p, expr) -> putPat p >> putExpr expr) cases
putExpr (TypeApp a tys) =
  P.putWord8 7 <>
  putAtom a <>
  putLength tys <>
  mapM_ putType tys

putPat :: S.Serialize origin => P.Putter (Pattern annot origin)
putPat PVar = P.putWord8 0
putPat (PCtor ctor tys) =
  let hd = case ctor of
             LocalCTor cname ->
                 P.putWord8 1 <>
                 putName cname
             ImportedCTor cname origin ->
               P.putWord8 2 <>
               putName cname <>
               S.put origin
  in hd <> putLength tys <> mapM_ putType tys

putPat (PLiteral lit) = do
  P.putWord8 3
  putLit lit
putPat (PAnnot _ p) = putPat p -- NB: Annotation is ignored.

putLit :: P.Putter Literal
putLit l =
  case l of
    Str bs -> do P.putWord8 0
                 P.putWord32be (fromIntegral . BS.length $ bs)
                 P.putByteString bs
    Int32 i -> P.putWord8 1 <> P.putInt32be i
    Int64 i -> P.putWord8 2 <> P.putInt64be i
    Int128 i -> P.putWord8 3 <> putInt128be i
    Int256 i -> P.putWord8 4 <> putInt256be i
    Word32 i -> P.putWord8 5 <> P.putWord32be i
    Word64 i -> P.putWord8 6 <> P.putWord64be i
    Word128 i -> P.putWord8 7 <> putWord128be i
    Word256 i -> P.putWord8 8 <> putWord256be i
    ByteStr32 bs -> P.putWord8 9 <> P.putByteString bs
    CAddress addr -> P.putWord8 10 <> putCAddress addr
    AAddress addr -> P.putWord8 11 <> putAAddress addr

putCAddress :: P.Putter ContractAddress
putCAddress = S.put

putAAddress :: P.Putter AccountAddress
putAAddress = S.put

putDataTyName :: S.Serialize t => P.Putter (DataTyName t)
putDataTyName n = case n of
  LocalDataTy ln -> do P.putWord8 0
                       putTyName ln
  ImportedDataTy ln mname -> do P.putWord8 1
                                putTyName ln
                                S.put mname



putType :: S.Serialize origin => P.Putter (Type annot origin)
putType (TForall t) =
  P.putWord8 0 <>
  putType t
putType (TArr t1 t2) =
  P.putWord8 1 <>
  putType t1 <>
  putType t2
putType (TVar at) =
  P.putWord8 2 <>
  putBoundTyVar at
putType (TApp t1 t2) =
  P.putWord8 3 <>
  putDataTyName t1 <>
  putLength t2 <>
  mapM_ putType t2
putType (TAnnot _ t) = putType t -- NB: annotation is ignored
putType (TBase tbase) = case tbase of
  TInt32 -> P.putWord8 4
  TInt64 -> P.putWord8 5
  TInt128 -> P.putWord8 6
  TInt256 -> P.putWord8 7
  TWord32 -> P.putWord8 8
  TWord64 -> P.putWord8 9
  TWord128 -> P.putWord8 10
  TWord256 -> P.putWord8 11
  TByteStr32 -> P.putWord8 12
  TByteString -> P.putWord8 13
  TCAddress -> P.putWord8 14
  TAAddress -> P.putWord8 15

putLength :: [a] -> P.Put
putLength = P.putWord32be . fromIntegral . length

putModuleName :: P.Putter ModuleName
putModuleName = P.putWord32be . fromIntegral

putBoundVar :: P.Putter BoundVar
putBoundVar = P.putWord32be . fromIntegral

putBoundTyVar :: P.Putter BoundTyVar
putBoundTyVar = P.putWord32be . fromIntegral

putName :: P.Putter Name
putName = P.putWord32be . fromIntegral

putTyName :: P.Putter TyName
putTyName = P.putWord32be . fromIntegral

putDataType :: P.Putter (DataType annot ModuleName)
putDataType DataType{..} = do
  putTyName dtName
  P.putWord32be dtParams
  putDtVisibility dtVis
  putLength dtCons
  mapM_ putDataCons dtCons

putDtVisibility :: P.Putter DataTyVisibility
putDtVisibility None = P.putWord8 0
putDtVisibility OnlyType = P.putWord8 1
putDtVisibility All = P.putWord8 2

putVisibility :: P.Putter Visibility
putVisibility Private = P.putWord8 0
putVisibility Public = P.putWord8 1

putDataCons :: P.Putter (DataCon annot ModuleName)
putDataCons DataCon{..} = do
  putName dcName
  putLength dcArity
  mapM_ putType dcArity


putConstraintDecl :: S.Serialize t => P.Putter (ConstraintDecl annot t)
putConstraintDecl ConstraintDecl{..} = do
  putTyName constraintName
  putLength senders
  mapM_ (\Sender{..} -> putName sName >> putType sVal) senders
  putLength getters
  mapM_ (\Getter{..} -> putName gName >> putType gVal) getters

putContract :: P.Putter (Contract annot ModuleName)
putContract Contract{..} = do
  putTyName cName
  putExpr cInit
  putExpr cReceive
  putLength cInstances
  mapM_ putConstraintImpl cInstances

putConstraintImpl :: P.Putter (ConstraintImpl annot ModuleName)
putConstraintImpl ConstraintImpl{..} = do
  putConstraintRef constraintNameImpl
  putLength sendersImpl
  mapM_ (\Sender{..} -> putName sName >> putExpr sVal) sendersImpl
  putLength gettersImpl
  mapM_ (\Getter{..} -> putName gName >> putExpr gVal) gettersImpl

putConstraintRef :: P.Putter (ConstraintRef ModuleName)
putConstraintRef (LocalCR cname) = P.putWord8 0 >> putTyName cname
putConstraintRef (ImportedCR cname origin) = P.putWord8 1 >> putTyName cname >> putModuleName origin

putModule :: P.Putter (Module annot)
putModule Module{..} = do
  putLength mImports
  mapM_ (\Import{..} -> putModuleRef iModule >> putModuleName iAs) mImports
  putLength mDataTypes
  mapM_ putDataType mDataTypes
  putLength mConstraintDecls
  mapM_ putConstraintDecl mConstraintDecls
  putLength mDefs
  mapM_ (\Definition{..} -> putName dName <> putVisibility dVis <> putType dType <> putExpr dExpr) mDefs
  putLength mContracts
  mapM_ putContract mContracts
  P.putWord32be mVersion


-- * Deserialization.
getName :: G.Get Name
getName = Name <$> G.getWord32be

getTyName :: G.Get TyName
getTyName = TyName <$> G.getWord32be

getBoundVar :: G.Get BoundVar
getBoundVar = BV <$> G.getWord32be

getBoundTyVar :: G.Get BoundTyVar
getBoundTyVar = BTV <$> G.getWord32be

getModuleName :: G.Get ModuleName
getModuleName = ModuleName <$> G.getWord32be


getDataTyName :: S.Serialize a => G.Get (DataTyName a)
getDataTyName = do
  h <- G.getWord8
  case h of
    0 -> LocalDataTy <$> getTyName
    1 -> ImportedDataTy <$> getTyName <*> S.get
    _ -> fail "Not a valid data type name."

getType :: S.Serialize origin => S.Get (Type annot origin)
getType = do h <- G.getWord8
             case h of
               0 -> TForall <$> getType
               1 -> liftM2 TArr getType getType
               2 -> TVar <$> getBoundTyVar
               3 -> do dataTyName <- getDataTyName
                       l <- getLength
                       args <- replicateM l getType
                       return $ TApp dataTyName args
               4 -> return $ TBase TInt32
               5 -> return $ TBase TInt64
               6 -> return $ TBase TInt128
               7 -> return $ TBase TInt256
               8 -> return $ TBase TWord32
               9 -> return $ TBase TWord64
               10 -> return $ TBase TWord128
               11 -> return $ TBase TWord256
               12 -> return $ TBase TByteStr32
               13 -> return $ TBase TByteString
               14 -> return $ TBase TCAddress
               15 -> return $ TBase TAAddress
               _ -> fail "Not a valid type."

getLength :: G.Get Int
getLength = fromIntegral <$> G.getWord32be

getCAddress :: G.Get ContractAddress
getCAddress = S.get

getAAddress :: G.Get AccountAddress
getAAddress = S.get


getPat :: S.Serialize origin => G.Get (Pattern annot origin)
getPat = do h <- G.getWord8
            case h of
              0 -> return $ PVar
              1 -> PCtor . LocalCTor <$> getName <*> (getLength >>= flip replicateM getType)
              2 -> PCtor <$> liftM2 ImportedCTor getName S.get <*> (getLength >>= flip replicateM getType)
              3 -> PLiteral <$> getLit
              _ -> fail "Not a valid pattern."

getLit :: G.Get Literal
getLit = do h <- G.getWord8
            case h of
              0 -> Str <$> (G.getByteString =<< getLength)
              1 -> Int32 <$> G.getInt32be
              2 -> Int64 <$> G.getInt64be
              3 -> Int128 <$> getInt128be
              4 -> Int256 <$> getInt256be
              5 -> Word32 <$> G.getWord32be
              6 -> Word64 <$> G.getWord64be
              7 -> Word128 <$> getWord128be
              8 -> Word256 <$> getWord256be
              9 -> ByteStr32 <$> G.getByteString 32
              10 -> CAddress <$> getCAddress
              11 -> AAddress <$> getAAddress
              _ -> fail "Not a valid literal."

getAtom :: S.Serialize origin => G.Get (Atom origin)
getAtom = 
  G.getWord8 >>= \case
    0 -> Literal <$> getLit
    1 -> Var . BoundVar <$> getBoundVar
    2 -> Var . LocalDef <$> getName
    3 -> Var <$> (Imported <$> getName <*> S.get)
    _ -> fail "Not a valid atom."

getExpr :: S.Serialize origin => G.Get (Expr annot origin)
getExpr = do h <- G.getWord8
             case h of
               0 -> Atom <$> getAtom
               1 -> Lambda <$> getType <*> getExpr
               2 -> TLambda <$> getExpr
               3 -> do
                 atom <- getAtom
                 l <- getLength
                 atoms <- replicateM l getAtom 
                 return $! App atom atoms
               4 -> Let <$> getType <*> getExpr <*> getExpr
               5 -> do l <- getLength
                       tms <- replicateM l $ do
                         tdom <- getType
                         expr <- getExpr
                         tcod <- getType
                         return (tdom, expr, tcod)
                       body <- getExpr
                       return $ LetRec tms body
               6 -> do e <- getAtom
                       l <- getLength
                       cases <- replicateM l $ liftM2 (,) getPat getExpr
                       return $ Case e cases
               7 -> do
                 a <- getAtom
                 l <- getLength
                 tys <- replicateM l getType
                 return $! TypeApp a tys
               _ -> fail "Not a valid expression."

getConstraintRef :: G.Get (ConstraintRef ModuleName)
getConstraintRef = do h <- G.getWord8
                      case h of
                        0 -> LocalCR <$> getTyName
                        1 -> liftM2 ImportedCR getTyName S.get
                        _ -> fail "Not a valid constraint reference."

getConstraintImpl :: G.Get (ConstraintImpl annot ModuleName)
getConstraintImpl = do
  constraintNameImpl <- getConstraintRef
  ls <- getLength
  sendersImpl <- replicateM ls $ liftM2 Sender getName getExpr
  lg <- getLength
  gettersImpl <- replicateM lg $ liftM2 Getter getName getExpr
  return $ ConstraintImpl{..}

getConstraintDecl :: S.Serialize a => S.Get (ConstraintDecl annot a)
getConstraintDecl = do
  constraintName <- getTyName
  ls <- getLength
  senders <- replicateM ls $ liftM2 Sender getName getType
  lg <- getLength
  getters <- replicateM lg $ liftM2 Getter getName getType
  return $ ConstraintDecl{..}
  
getDataCons :: G.Get (DataCon annot ModuleName)
getDataCons = do
  dcName <- getName
  l <- getLength
  dcArity <- replicateM l getType
  return $ DataCon{..}


getDtVisibility :: G.Get DataTyVisibility
getDtVisibility = do h <- G.getWord8
                     case h of
                       0 -> return None
                       1 -> return OnlyType
                       2 -> return All
                       _ -> fail "Not a valid datatype visibility."

getDataType :: G.Get (DataType annot ModuleName)
getDataType = do
  dtName <- getTyName
  dtParams <- G.getWord32be
  dtVis <- getDtVisibility
  l <- getLength
  dtCons <- replicateM l getDataCons
  return $ DataType{..}

getImport :: G.Get Import
getImport = do
  iModule <- getModuleRef
  iAs <- getModuleName
  return $ Import{..}

getVisibility :: G.Get Visibility
getVisibility = do h <- G.getWord8
                   case h of
                     0 -> return Private
                     1 -> return Public
                     _ -> fail "Not a valid visibility annotation."

getDefinition :: G.Get (Definition annot ModuleName)
getDefinition = do
  dName <- getName
  dVis <- getVisibility
  dType <- getType
  dExpr <- getExpr
  return $ Definition{..}

getContract :: G.Get (Contract annot ModuleName)
getContract = do
  cName <- getTyName
  cInit <- getExpr
  cReceive <- getExpr
  l <- getLength
  cInstances <- replicateM l getConstraintImpl
  return $ Contract{..}

getModule :: G.Get (Module annot)
getModule = do
  lIm <- getLength
  mImports <- replicateM lIm getImport
  ldt <- getLength
  mDataTypes <- replicateM ldt getDataType
  lcd <- getLength
  mConstraintDecls <- replicateM lcd getConstraintDecl
  ldefs <- getLength
  mDefs <- replicateM ldefs getDefinition
  lcont <- getLength
  mContracts <- replicateM lcont getContract
  mVersion <- G.getWord32be
  return $ Module{..}

-- * Deriving module reference from serialization
-- |Hash of a serialization of a module, encoded into base16
moduleHash :: Module annot -> ModuleRef
moduleHash =  ModuleRef . SHA256.hash . P.runPut . putModule 

--
bit128ToPair :: Integer -> (Word64, Word64)
bit128ToPair i = (hi', low)
  where ai = abs i
        low = fromIntegral ai
        hi = fromIntegral (ai `shiftR` 64)
        hi' = if i < 0 then setBit hi 63 else hi

int128ToPair :: NumTys.Int128 -> (Word64, Word64)
int128ToPair (NumTys.Int128 i) = bit128ToPair i

word128ToPair :: NumTys.Word128 -> (Word64, Word64)
word128ToPair (NumTys.Word128 i) = bit128ToPair i

-- TODO adapt/split when implementing Int256/Word256
int256ToQuad :: Integer -> (Word64, Word64, Word64, Word64)
int256ToQuad i = (hi', left, right, low)
  where ai = abs i
        low = fromIntegral ai
        t1 = ai `shiftR` 64
        right = fromIntegral t1
        t2 = t1 `shiftR` 64
        left = fromIntegral t2
        hi = fromIntegral (t2 `shiftR` 64)
        hi' = if i < 0 then setBit hi 63 else hi

putInt128be :: P.Putter NumTys.Int128
putInt128be i = let (hi, low) = int128ToPair i
                in P.putWord64be hi *> P.putWord64be low

putWord128be :: P.Putter NumTys.Word128
putWord128be i = let (hi, low) = word128ToPair i
                 in P.putWord64be hi *> P.putWord64be low

-- TODO adapt when implementing Int256
putInt256be :: P.Putter Integer
putInt256be i = let (hi, left, right, low) = int256ToQuad i
                in P.putWord64be hi *> P.putWord64be left *> P.putWord64be right *> P.putWord64be low

-- TODO adapt when implementing Word256
putWord256be :: P.Putter Integer
putWord256be i = let (hi, left, right, low) = int256ToQuad i
                 in P.putWord64be hi *> P.putWord64be left *> P.putWord64be right *> P.putWord64be low

getInt128be :: G.Get NumTys.Int128
getInt128be = do
  hi <- G.getWord64be
  low <- G.getWord64be
  let res = toInteger (clearBit hi 63) `shiftL` 64 + toInteger low
  if testBit hi 63 then
    return $ NumTys.Int128 (if res == 0 then -(2^(127 :: Int)) else -res) else return $ NumTys.Int128 res

getWord128be :: G.Get NumTys.Word128
getWord128be = do
  hi <- G.getWord64be
  low <- G.getWord64be
  return $ NumTys.Word128 $ toInteger hi `shiftL` 64 + toInteger low

-- TODO adapt when implementing Int256
getInt256be :: G.Get Integer
getInt256be = do
  hi <- G.getWord64be
  left <- G.getWord64be
  right <- G.getWord64be
  low <- G.getWord64be
  let res = toInteger (clearBit hi 63) `shiftL` 192
            + toInteger left `shiftL` 128
            + toInteger right `shiftL` 64
            + toInteger low
  if testBit hi 63 then return $ (if res == 0 then - (2^(255 :: Int)) else -res) else return res

-- TODO adapt when implementing Word256
getWord256be :: G.Get Integer
getWord256be = do
  hi <- G.getWord64be
  left <- G.getWord64be
  right <- G.getWord64be
  low <- G.getWord64be
  return $ toInteger hi `shiftL` 192
           + toInteger left `shiftL` 128
           + toInteger right `shiftL` 64
           + toInteger low
