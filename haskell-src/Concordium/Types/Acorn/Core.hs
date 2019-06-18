{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE DeriveFoldable #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveGeneric #-}
{-# OPTIONS_GHC -Wall #-}
module Concordium.Types.Acorn.Core(module Concordium.Types.Acorn.Core,
                                   ModuleRef(..))
where

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
import Data.Word
import qualified Concordium.Types.Acorn.NumericTypes as NumTys

import qualified Concordium.Crypto.SHA256 as SHA256
import Concordium.Types


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
  deriving (Show, Eq, Generic)

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
    deriving(Show, Eq, Generic, Hashable, Real, Integral, Enum, Ord, Num)

newtype BoundVar = BV Word32
    deriving(Show, Eq, Generic, Hashable, Real, Integral, Enum, Ord, Num)

newtype BoundTyVar = BTV Word32
    deriving(Show, Eq, Generic, Hashable, Real, Integral, Enum, Ord, Num)

data Variable boundvar name origin =
  -- |Variables bound by lambda abstractions.
  BoundVar !boundvar
  -- |Variables referring to local definitions.
  | LocalDef !name
  -- |Variables referring to imported definitions.
  | Imported !name !origin
    deriving (Show, Eq, Generic, Functor, Foldable, Traversable)

instance (Hashable a, Hashable b, Hashable c) => Hashable (Variable a b c)

data Expr origin
  = 
  -- |Basic literals.
    Literal !Literal           
  -- |Variables. Include constructors, imported definitions, but also bound variables.
  | Atom !(Variable BoundVar Name origin)
  -- |An anonymous function with type of its argument. We use the de-bruijn
  -- representation of bound variables, hence no variable name.
  | Lambda !(Type origin) !(Expr origin)
  -- |Type abstraction term (big lambda). Again with de-bruijn convention. Note
  -- that type and term variables are different classes, so going under a type
  -- binder only increases De-Bruijn level of type variables.
  | TLambda !(Expr origin)
  -- |Application of an expression, includes term and type applications.
  | App !(Expr origin) !(Expr origin)
  -- |Local let binding, non-recursive (Let e e') is let e in e' (we use
  -- De-Bruijn convention here as well).
  | Let !(Expr origin) !(Expr origin)
  -- |Mutually recursive let. The list of binders can be empty. In the example
  -- 
  -- @
  --    letrec [(tdom1, e1, tcod1), (tdom2, e2, tcod2)] ebody
  -- @
  -- 
  --   * in expressions @e1@ and @e2@ DeBruijn index 0 refers to the local variable
  --     and indices 1 and 2 refer to the functions defined by @e2@ and @e1@ respectively
  --   * in expression @ebody@ DeBruijn index 0 refers to (the functions defined by) @e2@ and 1 to @e1@
  | LetRec ![(Type origin, Expr origin, Type origin)] !(Expr origin)
  -- |Case expression, the list of alternatives should be non-empty. In bodies
  -- of branches we again use the De-Bruijn convention.
  | Case !(Expr origin) ![(Pattern origin, Expr origin)]
  -- |Types are also expressions (since we have explicit type application)
  | Type !(Type origin)
  deriving (Eq, Show, Generic, Functor, Foldable, Traversable)

-- TODO: We could simply merge PCtor and PVar into one and just use variable for
-- everything.

-- | We do not allow nested patterns since checking incompleteness is NP-hard,
-- which we cannot allow for security reasons.
data Pattern origin =
  -- |We do not need to give it a name because we are using De-Bruijn convention for bound variables.
  PVar 
  -- |Fully instantiated constructor. Constructor can be either locally declared or imported.
  | PCtor !(CTorName origin)
  -- And finally we can match on literals.
  -- NB:FIXME:This will probably need to be narrowed since matching 128-byte
  -- strings is quite different than matching ints, and we probably do not want
  -- to allow matching on all literals.
  | PLiteral !Literal                 -- Matching a literal.
  deriving (Eq, Show, Generic, Functor, Foldable, Traversable)

data CTorName origin = LocalCTor {ctorName :: !Name}
                     | ImportedCTor {ctorName :: !Name
                                    ,ctorOrigin :: !origin
                                    }
  deriving (Eq, Show, Generic, Functor, Foldable, Traversable)

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
    deriving (Show, Eq, Generic)

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
    deriving(Show, Eq, Generic, Hashable, Real, Integral, Enum, Ord, Num)

data DataTyName origin = LocalDataTy {dataTyName :: !TyName}
                       | ImportedDataTy {dataTyName :: !TyName
                                        ,dataTyOrigin :: !origin
                                        }
  deriving (Eq, Show, Generic, Functor, Foldable, Traversable)

instance Hashable origin => Hashable (DataTyName origin)

data Type origin =
  -- |Polymorphic quantification. Using De-Bruijn representation.
  TForall !(Type origin)
  -- |Function types.
  | TArr !(Type origin) !(Type origin)     
  -- |Type variables, but also imported or defined types.
  | TVar !BoundTyVar
  -- |Type application, i.e., List Int. This will always be "declared datatype applied to types".
  | TApp !(DataTyName origin) ![(Type origin)]
  -- |Base types.
  | TBase !TBase
  deriving (Show, Eq, Generic, Functor, Foldable, Traversable)
-- NB: Eq is alpha equality because we are using DeBruijn indices

-- | A data constructor has a name, and an arity.
-- For instance, the arity of polymorphic list Cons is going to be [α, List α]
-- and the variable α must be listed in the type variables of DataType below.
-- Since we are using DeBruijn indices this concretely means that α < dtParams.
data DataCon origin = DataCon {dcName :: !Name
                              , dcArity :: ![Type origin] }
  deriving (Show, Eq, Generic, Functor, Traversable, Foldable)

-- | A datatype declaration is a name, plus the number of type parameters, plus
-- a non-empty list of constructors.
data DataType origin = DataType {
                                dtVis :: !DataTyVisibility
                                , dtName :: !TyName
                                , dtParams :: !Word32 -- ^The number of parameters. Use DeBruijn to refer to them.
                                , dtCons :: ![DataCon origin]
                                }
  deriving (Show, Eq, Generic, Functor, Traversable, Foldable)

-- |The parameter v in 'Sender' and 'Getter' are going to be instantiated with
-- Type in 'ConstraintDecl' and with 'Expr' in 'ConstraintImpl'.
data Sender v = Sender { 
                       sName :: !Name
                       , sVal :: !v
                       }
    deriving (Show, Eq, Generic, Functor, Foldable, Traversable)

data Getter v = Getter {
                       gName :: !Name
                       , gVal :: !v
                       }
    deriving (Show, Eq, Generic, Functor, Foldable, Traversable)

data ConstraintDecl v
    = ConstraintDecl
      {
      constraintName :: !TyName
      -- |Senders of a constraint are methods which can be used to send messages to
      -- other contracts. They should be of type (and will be typechecked to be)
      -- ref C -> T -> Transaction where ref C is address of contracts
      -- implementing interface/class C.
      , senders   :: ![Sender (Type v)] 
      -- |Getters of a constraint are methods which can be used to access the state
      -- of any instance implementing this class. They are of type ref C -> T.
      , getters   :: ![Getter (Type v)] 
      }
    deriving (Show, Eq, Generic, Functor, Foldable, Traversable)

-- |Canonical reference to a constraint.
data ConstraintRef origin = ImportedCR {crName :: !TyName, crMod :: !origin}
                          | LocalCR { crName :: !TyName }
  deriving(Show, Eq, Ord, Generic, Foldable, Functor, Traversable)

instance Hashable a => Hashable (ConstraintRef a)

data ConstraintImpl origin
    = ConstraintImpl
      {
      constraintNameImpl :: ConstraintRef origin
      , sendersImpl   :: ![Sender (Expr origin)] 
      , gettersImpl   :: ![Getter (Expr origin)] 
      }
    deriving (Show, Eq, Generic, Functor, Foldable, Traversable)

-- |A contract has a name, an init method, and a receive method. The type of
-- local state is inferred from the type of the init method, and the type of
-- messages the contract can receive is inferred from the type of the receive
-- method. Moreover, the contract can "implement" or be an instance of a number
-- of constraints (by name).
data Contract a = Contract {
  cName :: !TyName
  , cInit :: !(Expr a)
  , cReceive :: !(Expr a)
  , cInstances :: ![ConstraintImpl a]
  }
  deriving(Show, Eq, Generic)


-- * Utility functions used during typechecking.

-- |Apply a type of the form forall .... to a list of types.
-- Used to instantiate the arity arguments of datatype constructors during typechecking.
applyTy :: [Type origin] -> Type origin -> Type origin
applyTy ts t = go t 0
  where len :: Int
        len = length ts

        go s@(TBase _) _ = s
        go (TApp t1 t2) n = TApp t1 (map (flip go n) t2)
        go (TArr t1 t2) n = TArr (go t1 n) (go t2 n)
        go (TForall t1) n = TForall (go t1 (n+1))
        -- FIXME: It is not clear that fromIntegral is always correct here. Documentation states it preserves representation, not sign.
        go ta@(TVar v) n | fromIntegral v >= n && fromIntegral v - n < len = ts !! (fromIntegral v - n)
                         | otherwise = liftFreeBy (fromIntegral n) ta

-- TODO: FIXME: We should not use this during typechecking since it can cause
-- exponential blow up in term size when we blindly substitute.
-- |'substTy' t₁ t₂ replaces the variable "0" in t₁ with t₂
-- Substitution is capture avoiding.
substTy :: Type a -> Type a -> Type a
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

        liftTy _ _ ty@(TBase _) = ty
        liftTy l n (TApp t1 t2) = TApp t1 (map (liftTy l n) t2)
        liftTy l n (TArr t1 t2) = TArr (liftTy l n t1) (liftTy l n t2)
        liftTy l n (TForall t1) = TForall (liftTy (l+1) n t1)
        -- FIXME: It is not clear that fromIntegral is always correct here.
        -- Documentation states it preserves representation, not sign.
        liftTy l n ta@(TVar v) | v >= l = TVar (v + n)
                               | otherwise = ta

-- |Lift all free variables by 1 (to be used when going under type lambda in typechecking terms).
liftFree :: Type a -> Type a
liftFree = liftFreeBy 1

-- |Lift all free variables by k (to be used when going under type lambda in typechecking terms).
liftFreeBy :: BoundTyVar -> Type origin -> Type origin
liftFreeBy k = if k == 0 then id else go 0
  where go _ ty@(TBase _) = ty
        go n (TApp t1 t2) = TApp t1 (map (go n) t2)
        go n (TArr t1 t2) = TArr (go n t1) (go n t2)
        go n (TForall t1) = TForall (go (n+1) t1)
        go n ta@(TVar v) | v >= n = TVar (v+k)
                         | otherwise = ta


-- *The notion of a module.

-- | A module import "import Foo as bar". The reason for having this is to
-- reduce space usage and so that it is easy to determine which modules to look
-- up up front. Foo will be a unique id of the module deployed on the chain
-- (currently defined as a 32-byte hash of the serialized module content) and
-- ModuleName is a short 4-byte identifier local to the module.
data Import = Import {iModule :: ModuleRef
                     ,iAs :: ModuleName
                     }
  deriving(Show, Eq, Generic)

data Definition a = Definition {
  dVis :: !Visibility
  , dName :: !Name
  , dExpr :: !(Expr a)
  }
  deriving (Show, Eq, Generic, Functor, Foldable, Traversable)

-- |Name, but differentiated for sanity checking. But in practice there can never be a confusion between module names and term and type names.
newtype ModuleName = ModuleName { moduleName :: Word32 }
    deriving(Show, Eq, Ord, Enum, Generic, Hashable, Num, Real, Integral)

-- Version of the environment the contract is valid for. Should probably be something more structured than a word.
type Version = Word32

-- |This is the unit that can be deployed on the chain. The module should not be
-- empty, so there should be either a non-empty list of constracts, constraints, or contracts.
data Module =
  Module { 
         mImports :: ![Import]
         , mDataTypes :: ![DataType ModuleName]
         , mConstraintDecls :: ![ConstraintDecl ModuleName]
         -- |List of pure functions provided by the module. These should not have any "effectful" operations, such as
         -- reading state of the blockchain, or sending messages, etc. This is part of a well-formedness check.
         , mDefs :: ![Definition ModuleName]
         -- |A possibly empty list of contracts.
         , mContracts :: ![Contract ModuleName]
         -- |Version number of this module, i.e., which language version it corresponds to.
         , mVersion :: !Version
         }
  deriving (Eq, Show, Generic)

-- |Whether a definition can be called from other modules or not.
data Visibility = Public | Private
  deriving (Show, Eq, Generic)

-- |Whether a datatype is exported or not.
data DataTyVisibility = None | OnlyType | All
    deriving(Show, Eq, Generic)

-- plays the role of the prim module. Invalid otherwise.
emptyModule :: Module
emptyModule = Module {
  mImports =  []
  , mDataTypes = []
  , mConstraintDecls = []
  , mDefs = []
  , mContracts = []
  , mVersion = 1
  }

-- * Expression and module serialization

instance S.Serialize Literal where
  get = getLit
  put = putLit

instance S.Serialize BoundVar where
  get = getBoundVar
  put = putBoundVar

instance S.Serialize a => S.Serialize (Expr a) where
    get = getExpr
    put = putExpr

instance S.Serialize a => S.Serialize (Type a) where
  get = getType
  put = putType

instance S.Serialize Module where
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

instance S.Serialize a => S.Serialize (ConstraintDecl a) where
  get = getConstraintDecl
  put = putConstraintDecl

putExpr :: S.Serialize t => P.Putter (Expr t)
putExpr (Literal l) = do P.putWord8 10
                         putLit l
putExpr (Atom at) = case at of
                        BoundVar bv -> do P.putWord8 0
                                          putBoundVar bv
                        LocalDef l -> do P.putWord8 1
                                         putName l
                        Imported l orig -> do P.putWord8 2
                                              putName l
                                              S.put orig
putExpr (Lambda ty body) = do
  P.putWord8 3
  putType ty
  putExpr body
putExpr (TLambda body) = do
  P.putWord8 4
  putExpr body
putExpr (App e1 e2) = do
  P.putWord8 5
  putExpr e1
  putExpr e2
putExpr (Let e1 e2) = do
  P.putWord8 6
  putExpr e1
  putExpr e2
putExpr (LetRec fs e) = do
  P.putWord8 7
  putLength fs
  mapM_ (\(t, expr, t') -> putType t >> putExpr expr >> putType t') fs
  putExpr e
putExpr (Case e cases) = do
  P.putWord8 8
  putExpr e
  putLength cases
  mapM_ (\(p, expr) -> putPat p >> putExpr expr) cases
putExpr (Type ty) = do
  P.putWord8 9
  putType ty

putPat :: S.Serialize t => P.Putter (Pattern t)
putPat PVar = do
  P.putWord8 0
putPat (PCtor ctor) = case ctor of
                          LocalCTor cname -> do P.putWord8 1
                                                putName cname
                          ImportedCTor cname origin -> do
                            P.putWord8 2
                            putName cname
                            S.put origin

putPat (PLiteral lit) = do
  P.putWord8 3
  putLit lit

putLit :: P.Putter Literal
putLit l = case l of
             Str bs -> do P.putWord8 0
                          P.putWord32be (fromIntegral . BS.length $ bs)
                          P.putByteString bs
             Int32 i -> P.putWord8 1 *> P.putInt32be i
             Int64 i -> P.putWord8 2 *> P.putInt64be i
             Int128 i -> P.putWord8 3 *> putInt128be i
             Int256 i -> P.putWord8 4 *> putInt256be i
             Word32 i -> P.putWord8 5 *> P.putWord32be i
             Word64 i -> P.putWord8 6 *> P.putWord64be i
             Word128 i -> P.putWord8 7 *> putWord128be i
             Word256 i -> P.putWord8 8 *> putWord256be i
             ByteStr32 bs -> P.putWord8 9 *> P.putByteString bs
             CAddress addr -> P.putWord8 10 *> putCAddress addr
             AAddress addr -> P.putWord8 11 *> putAAddress addr

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



putType :: S.Serialize t => P.Putter (Type t)
putType (TForall t) = do P.putWord8 0
                         putType t
putType (TArr t1 t2) = do P.putWord8 1
                          putType t1
                          putType t2
putType (TVar at) = do P.putWord8 2
                       putBoundTyVar at
putType (TApp t1 t2) = do P.putWord8 3
                          putDataTyName t1
                          putLength t2
                          mapM_ putType t2
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

putDataType :: P.Putter (DataType ModuleName)
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

putDataCons :: P.Putter (DataCon ModuleName)
putDataCons DataCon{..} = do
  putName dcName
  putLength dcArity
  mapM_ putType dcArity


putConstraintDecl :: S.Serialize t => P.Putter (ConstraintDecl t)
putConstraintDecl ConstraintDecl{..} = do
  putTyName constraintName
  putLength senders
  mapM_ (\Sender{..} -> putName sName >> putType sVal) senders
  putLength getters
  mapM_ (\Getter{..} -> putName gName >> putType gVal) getters

putContract :: P.Putter (Contract ModuleName)
putContract Contract{..} = do
  putTyName cName
  putExpr cInit
  putExpr cReceive
  putLength cInstances
  mapM_ putConstraintImpl cInstances

putConstraintImpl :: P.Putter (ConstraintImpl ModuleName)
putConstraintImpl ConstraintImpl{..} = do
  putConstraintRef constraintNameImpl
  putLength sendersImpl
  mapM_ (\Sender{..} -> putName sName >> putExpr sVal) sendersImpl
  putLength gettersImpl
  mapM_ (\Getter{..} -> putName gName >> putExpr gVal) gettersImpl

putConstraintRef :: P.Putter (ConstraintRef ModuleName)
putConstraintRef (LocalCR cname) = P.putWord8 0 >> putTyName cname
putConstraintRef (ImportedCR cname origin) = P.putWord8 1 >> putTyName cname >> putModuleName origin

putModule :: P.Putter Module
putModule Module{..} = do
  putLength mImports
  mapM_ (\Import{..} -> putModuleRef iModule >> putModuleName iAs) mImports
  putLength mDataTypes
  mapM_ putDataType mDataTypes
  putLength mConstraintDecls
  mapM_ putConstraintDecl mConstraintDecls
  putLength mDefs
  mapM_ (\Definition{..} -> putName dName >> putVisibility dVis >> putExpr dExpr) mDefs
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

getType :: S.Serialize a => S.Get (Type a)
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


getPat :: S.Serialize a => G.Get (Pattern a)
getPat = do h <- G.getWord8
            case h of
              0 -> return $ PVar
              1 -> PCtor . LocalCTor <$> getName
              2 -> PCtor <$> liftM2 ImportedCTor getName S.get
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

getExpr :: S.Serialize a => G.Get (Expr a)
getExpr = do h <- G.getWord8
             case h of
               10 -> Literal <$> getLit
               0 -> Atom . BoundVar <$> getBoundVar
               1 -> Atom . LocalDef <$> getName
               2 -> Atom <$> liftM2 Imported getName S.get
               3 -> liftM2 Lambda getType getExpr
               4 -> TLambda <$> getExpr
               5 -> liftM2 App getExpr getExpr
               6 -> liftM2 Let getExpr getExpr
               7 -> do l <- getLength
                       tms <- replicateM l $ do tdom <- getType
                                                expr <- getExpr
                                                tcod <- getType
                                                return (tdom, expr, tcod)
                       body <- getExpr
                       return $ LetRec tms body
               8 -> do e <- getExpr
                       l <- getLength
                       cases <- replicateM l $ liftM2 (,) getPat getExpr
                       return $ Case e cases
               9 -> Type <$> getType
               _ -> fail "Not a valid expression."

getConstraintRef :: G.Get (ConstraintRef ModuleName)
getConstraintRef = do h <- G.getWord8
                      case h of
                        0 -> LocalCR <$> getTyName
                        1 -> liftM2 ImportedCR getTyName S.get
                        _ -> fail "Not a valid constraint reference."

getConstraintImpl :: G.Get (ConstraintImpl ModuleName)
getConstraintImpl = do
  constraintNameImpl <- getConstraintRef
  ls <- getLength
  sendersImpl <- replicateM ls $ liftM2 Sender getName getExpr
  lg <- getLength
  gettersImpl <- replicateM lg $ liftM2 Getter getName getExpr
  return $ ConstraintImpl{..}

getConstraintDecl :: S.Serialize a => S.Get (ConstraintDecl a)
getConstraintDecl = do
  constraintName <- getTyName
  ls <- getLength
  senders <- replicateM ls $ liftM2 Sender getName getType
  lg <- getLength
  getters <- replicateM lg $ liftM2 Getter getName getType
  return $ ConstraintDecl{..}
  
getDataCons :: G.Get (DataCon ModuleName)
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

getDataType :: G.Get (DataType ModuleName)
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

getDefinition :: G.Get (Definition ModuleName)
getDefinition = do
  dName <- getName
  dVis <- getVisibility
  dExpr <- getExpr
  return $ Definition{..}

getContract :: G.Get (Contract ModuleName)
getContract = do
  cName <- getTyName
  cInit <- getExpr
  cReceive <- getExpr
  l <- getLength
  cInstances <- replicateM l getConstraintImpl
  return $ Contract{..}

getModule :: G.Get Module
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
moduleHash :: Module -> ModuleRef
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
