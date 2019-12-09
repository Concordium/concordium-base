{-# LANGUAGE TupleSections #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE QuantifiedConstraints #-}
{-# OPTIONS_GHC -Wall #-}

module Concordium.Types.Acorn.Interfaces where

import GHC.Generics(Generic)

import Data.Vector(Vector)
import qualified Data.Vector as Vector
import Data.Hashable(Hashable)
import Data.HashMap.Strict(HashMap)
import qualified Data.HashMap.Strict as Map
import qualified Data.Sequence as Seq
import Data.Int
import Data.Word
import Data.Maybe(fromJust)
import Control.Monad.Trans.Maybe
import Control.Monad.Except

import qualified Data.Serialize.Put as P
import qualified Data.Serialize.Get as G
import qualified Data.Serialize as S

import Concordium.Types
import qualified Concordium.Types.Acorn.Core as Core

-- * Datatypes involved in typechecking, and any other operations involving types.

type Type = Core.Type

-- |Interface of a datatype.
data DataTypeInterface annot = DataTypeInterface
  { -- | The number of type parameters.
    dtiParams :: !Int
    -- | The datatype's constructors: a map of constructor names to their arity.
  , dtiCtors :: !(HashMap Core.Name [Type annot Core.ModuleRef])
    -- | The constructors' visibility (for a module interface: 'Core.Public' if
    -- the constructors are exported)
  , dtiCtorsVis :: !Core.Visibility
  }
  deriving(Eq, Generic)

deriving instance Core.AnnotContext Show annot => Show (DataTypeInterface annot)

-- |Interface of a contract.
data ContractInterface annot = ContractInterface
    { paramTy :: !(Type annot Core.ModuleRef) -- ^Type of the parameter of the init method.
    , msgTy :: !(Type annot Core.ModuleRef) -- ^Type of messages the receive method can handle.
    }
  deriving(Eq, Generic)

deriving instance Core.AnnotContext Show annot => Show (ContractInterface annot)


-- |Interface derived from a module. This is used in typechecking other modules.
-- Lists public functions which can be called, and types of methods.
-- The following invariants are assumed:
--   * All 'Type's are well-formed in the context of imported modules.
--   * 'exportedTerms' includes the constructors of a datatype if and only if
--     they are declared to be public in the corresponding 'DataTypeInterface'.
data Interface annot = Interface
    { uniqueName :: !Core.ModuleRef
    , iSize :: Word64
    , importedModules :: !(HashMap Core.ModuleName Core.ModuleRef)
    -- | The datatypes the module exports.
    , exportedTypes :: !(HashMap Core.TyName (DataTypeInterface annot))
    -- | The terms the module exports.
    , exportedTerms :: !(HashMap Core.Name (Type annot Core.ModuleRef))
    , exportedContracts :: !(HashMap Core.TyName (ContractInterface annot))
    , exportedConstraints :: !(HashMap Core.TyName (Core.ConstraintDecl annot Core.ModuleRef))
    }
  deriving (Generic)

deriving instance Core.AnnotContext Show annot => Show (Interface annot)
deriving instance Core.AnnotContext Eq annot => Eq (Interface annot)

emptyInterface :: Core.ModuleRef -> Interface annot
emptyInterface mref = Interface mref 0 Map.empty Map.empty Map.empty Map.empty Map.empty

type ModuleInterfaces annot = HashMap Core.ModuleRef (Interface annot)

data InternalizeError = ModuleNotImported !Core.ModuleName
    deriving(Eq, Show)

-- |Errors which can occur during typechecking. Used for local development only.
data TypingError annot =
                 -- |The module with the given name (referred to from an expression)
                 -- is not imported (not part of the given interface's import map).
                 InternalizeFailed !InternalizeError
                 -- |A declared datatype is instantiated with
                 -- a wrong number of arguments (too few or too many). The first
                 -- argument is the number of given parameters, the second the
                 -- expected number.
                 | IncorrectNumberOfTypeParameters Int Int
                 -- |In an application for terms, the given term cannot be applied to
                 -- an argument because the term (atom) is not of a function type
                 -- but of the given type.
                 | NotAFunctionType (Core.Type annot ModuleRef)
                 -- |The type of the discriminee in a case expression is not
                 -- fully instantiated.
                 | NonFullyInstantiatedTypeAsCaseArgument -- NOTE: Could add name of declared datatype
                 -- |The type of the discriminee in a case expression is a base
                 -- type not supported for pattern matching.
                 | UnsupportedBaseTypeInCaseArgument (Core.TBase)
                 -- |The type of the discriminee in a case expression is a function type.
                 | FunctionAsCaseArgument
                 -- |The discriminee in a case expression is a type variable.
                 | TypeVariableAsCaseArgument
                 -- |A case expression has no alternatives.
                 | CaseWithoutAlternatives
                 -- |A pattern in a case expression is redundant: a redundant variable,
                 -- literal (if the type of the discriminee is a base type) or data type
                 -- constructor (if the type of the discriminee is a declared
                 -- datatype).
                 | PatternRedundant (Core.Pattern annot Core.ModuleRef)
                 -- |The patterns in a case expression are not exhaustive.
                 | PatternsNonExhaustive
                 -- |A pattern in a case expression does not have the correct type.
                 -- The first argument is the actual type, the second the expected type.
                 | UnexpectedPatternType (Core.Type annot ModuleRef) (Core.Type annot ModuleRef)
                 -- |A more specific case of 'UnexpectedPatternType'. The constructor used in the
                 -- pattern is not a type constructor of the discriminee type.
                 | UnexpectedTypeConstructorInPattern (Core.CTorName Core.ModuleRef)
                 -- |The number of type annotations given by a constructor pattern
                 -- does not match the number of arguments of the corresponding constructor.
                 -- The first argument is the number of given type annotations, the second
                 -- the number of arguments the constructor has.
                 | IncorrectNumberOfConstructorArgumentsInPattern Int Int
                 -- |A more specific case of 'UnexpectedPatternType'. A constructor pattern occurs
                 -- at a place where the discriminee has a base type.
                 | TypeConstructorWhereLiteralOrVariableExpected (Core.CTorName Core.ModuleRef)
                 -- |A more specific case of 'UnexpectedPatternType'. A litreal occurs at a place
                 -- where the discriminee has a declared datatype.
                 | LiteralWhereTypeConstructorExpected Core.Literal
                 -- |A variable used in an expression is not bound.
                 | UndefinedVariable Core.BoundVar
                 -- |A free type variable occurs in an expression.
                 | FreeTypeVariable Core.BoundTyVar
                 -- |The data type with the given name is not defined in the
                 -- current module.
                 | UndefinedLocalDatatype Core.TyName
                 -- |The data type with the given name is not defined in the
                 -- given module.
                 | UndefinedQualifiedDatatype Core.ModuleRef Core.TyName
                 -- |The referenced local definition does not exist in the current module.
                 | LocalNameNotInScope Core.Name
                 -- |The referenced imported definition does not exist in the given module.
                 | QualifiedNameNotInScope Core.ModuleRef Core.Name
                 -- |A module with the given reference does not exist. This is thrown when
                 -- trying to type-check an imported definition from a non-existing module.
                 | ModuleNotExists Core.ModuleRef
                 -- |The given name is already bound but is attempted to be
                 -- redefined.
                 | RedefinitionOfTerm Core.Name
                 -- |The given type name is already bound but is attempted to be redefined.
                 | RedefinitionOfType Core.TyName
                 -- |The contract with the given name has already been defined but
                 -- is attempted to be redefined.
                 | RedefinitionOfContract Core.TyName
                 -- |Attempting to declare a data type (with the given name) without constructors.
                 | DataTypeWithoutConstructors Core.TyName
                 -- |The contract's message type as specified by the receive
                 -- method is not a storable type. The first argument is the
                 -- name of the contract this error refers to, the second the
                 -- given message type.
                 | ContractMessageTypeNotStorable Core.TyName (Core.Type annot ModuleRef)
                 -- |The contract's parameter type as specified by the init
                 -- method is not a storable type. The first argument is the
                 -- name of the contract this error refers to, the second the
                 -- given parameter type.
                 | ContractParameterTypeNotStorable Core.TyName (Core.Type annot ModuleRef)
                 -- |The model type of the contract (as specified by the init
                 -- and receive methods) is not a storable type. The first
                 -- argument is the name of the contract this error refers to,
                 -- the second the given model type.
                 | ContractModelTypeNotStorable Core.TyName (Core.Type annot ModuleRef)
                 -- |The contract's message type as specified by the receive
                 -- method is not a public type. The first argument is the
                 -- name of the contract this error refers to, the second the
                 -- given message type.
                 | ContractMessageTypeNotPublic Core.TyName (Core.Type annot ModuleRef)
                 -- |The contract's parameter type as specified by the init
                 -- method is not a public type. The first argument is the
                 -- name of the contract this error refers to, the second the
                 -- given parameter type.
                 | ContractParameterTypeNotPublic Core.TyName (Core.Type annot ModuleRef)
                 -- |The model type of the contract (as specified by the init
                 -- and receive methods) is not a public type. The first
                 -- argument is the name of the contract this error refers to,
                 -- the second the given model type.
                 | ContractModelTypeNotPublic Core.TyName (Core.Type annot ModuleRef)
                 -- |A contract attempts to implement a local constraint that does
                 -- not exist. The first argument is the contract this error refers to,
                 -- the second the name which does not refer to a local constraint.
                 | LocalConstraintNotExists Core.TyName Core.TyName
                 -- |A contract attempts to implement an imported constraint that does
                 -- not exist. The first argument is the contract this error refers to,
                 -- the second the reference of the module the constraint should be
                 -- imported from and the third the name which does not refer to a
                 -- constraint in that module.
                 | ImportedConstraintNotExists Core.TyName Core.ModuleRef Core.TyName
                 -- |The contract's number of implementations of getter methods
                 -- does not match the number specified in the respective
                 -- constraint. The first argument is the name of the contract
                 -- this error refers to, the second the name of the constraint.
                 | ContractIncorrectNumberOfGetterImplementations Core.TyName (Core.ConstraintRef Core.ModuleRef)
                 -- |The contract's number of implementations of sender methods
                 -- does not match the number specified in the respective
                 -- constraint. The first argument is the name of the contract
                 -- this error refers to, the second the name of the constraint.
                 | ContractIncorrectNumberOfSenderImplementations Core.TyName (Core.ConstraintRef Core.ModuleRef)
                 -- |An implementation of a getter method in a contract does not
                 -- match the expected method to be implemented at that position.
                 -- The first and second arguments are the name of the contract and the
                 -- constraint this error refers to, the third the name of the
                 -- method that is implemented and the fourth the name of the
                 -- method that is expected to be implemented.
                 | ContractUnexpectedGetterImplementation
                   Core.TyName (Core.ConstraintRef Core.ModuleRef) Core.Name Core.Name
                 -- |An implementation of a sender method in a contract does not
                 -- match the expected method to be implemented at that position.
                 -- The first and second arguments are the name of the contract and the
                 -- constraint this error refers to, the third the name of the
                 -- method that is implemented and the fourth the name of the
                 -- method that is expected to be implemented.
                 | ContractUnexpectedSenderImplementation
                   Core.TyName (Core.ConstraintRef Core.ModuleRef) Core.Name Core.Name
                 -- |The public definition (explicit definition or datatype constructor)
                 -- with the given name has a private type.
                 | PublicDefinitionWithPrivateType Core.Name (Core.Type annot ModuleRef)
                 -- |A (sub)expression to be type checked has not the type specified
                 -- as the expected type. The first argument is the type encountered,
                 -- the second is the expected type.
                 | UnexpectedType (Core.Type annot ModuleRef) (Core.Type annot ModuleRef)
                 -- |Type application failed or the resulting type is not the expected type.
                 -- The first argument is the type the list of types in the second argument
                 -- is to be applied to, the third argument the expected resulting type.
                 | UnexpectedTypeOrFailureInTypeApplication
                   (Core.Type annot ModuleRef) [Core.Type annot ModuleRef] (Core.Type annot ModuleRef)
                 -- |Like 'UnexpectedType' but where the actual type is not calculated.
                 -- The first argument is the type of wrong shape which might not even
                 -- be a well-formed type.
                 | UnexpectedShapeOfType (Core.Type annot ModuleRef)
    deriving (Generic)

deriving instance Core.AnnotContext Eq annot => Eq (TypingError annot)
deriving instance Core.AnnotContext Show annot => Show (TypingError annot)

-- |Run a computation (i.e., typechecker), but in case of an error hide the
-- actual error and only report that a failure occurred via a 'Maybe'.
typeHidingErrors :: MaybeT m a -> m (Maybe a)
typeHidingErrors c = runMaybeT c

-- * Datatypes involved in execution of terms.

-- | The type of values used by the interpreter. 
data Value annot = 
             VClosure !Int !(RTEnv annot) !(LinkedExpr annot) -- ^Functions evaluate to closures.
             | VRecClosure !(RTEnv annot) !Int !(Vector (LinkedExpr annot)) -- ^Recursive functions evaluate to recursive closures.
             | VLiteral !Core.Literal    -- ^Base literals.
             | VConstructor !Core.Name !(Seq.Seq (Value annot)) -- ^Constructors applied to arguments.
             -- FIXME: Should use sequence instead of list here as well since it is usually built by appending to the back.
             | VInstance { vinstance_ls :: !(Value annot) -- ^Local state of the instance.
                         , vinstance_caddr :: !ContractAddress -- ^Address of the instance.
                         , vinstance_implements :: !(LinkedImplementsValue annot) -- ^All constraints this instance implements.
                         }
  deriving(Show, Eq)

putSeqLength :: S.Putter (Seq.Seq a)
putSeqLength l = P.putWord32be (fromIntegral (Seq.length l))

-- |The serialization instances for values are only for storable values.
-- If you try to serialize with a value which is not storable the methods will fail.
putStorable :: P.Putter (Value annot)
putStorable (VLiteral l) = P.putWord8 0 <> Core.putLit l
putStorable (VConstructor n vals) = do
  P.putWord8 1
  Core.putName n
  putSeqLength vals
  mapM_ putStorable vals
putStorable _ = error "FATAL: Trying to serialize a non-storable value. This should not happen."

getStorable :: G.Get (Value annot)
getStorable = do
  h <- G.getWord8
  case h of
    0 -> VLiteral <$> Core.getLit
    1 -> do
      name <- Core.getName
      l <- Core.getLength
      vals <- Seq.replicateM l getStorable
      return $ VConstructor name vals
    _ -> fail "Serialization failure. Unknown node."

data RTEnv annot = RTEnv {
  localStack :: !(Seq.Seq (Value annot)),
  foreignStack :: !(Seq.Seq (Value annot))
  }
  deriving(Show, Eq)

{-# INLINE singletonLocalStack #-}
singletonLocalStack :: Value annot -> RTEnv annot
singletonLocalStack v = RTEnv { localStack = Seq.singleton v, foreignStack = Seq.empty }

{-# INLINE pushToStack #-}
-- |NB: It is quite crucial that this method is strict in the value. If not then
-- the interpreter can leak memory because a closure that is pushed onto the
-- environment retains references to elements which are not longer reachable.
pushToStack :: RTEnv annot -> Value annot -> RTEnv annot
pushToStack env !v = env { localStack = v Seq.<| localStack env }

{-# INLINE pushToStackForeign #-}
-- |NB: It is quite crucial that this method is strict in the value. If not then
-- the interpreter can leak memory because a closure that is pushed onto the
-- environment retains references to elements which are not longer reachable.
pushToStackForeign :: RTEnv annot -> Value annot -> RTEnv annot
pushToStackForeign env !v = env { foreignStack = v Seq.<| foreignStack env }

{-# INLINE pushAllToStack #-}
pushAllToStack :: RTEnv annot -> Seq.Seq (Value annot) -> RTEnv annot
pushAllToStack env v = foldl pushToStack env v

emptyStack :: RTEnv annot
emptyStack = RTEnv Seq.empty Seq.empty

-- |NB: This method is unsafe and will raise an error if the stack is empty.
{-# INLINE peekStack #-}
peekStack :: RTEnv annot -> Value annot
peekStack env = localStack env `Seq.index` 0

-- |NB: This method is unsafe and will raise an error if the stack is empty.
{-# INLINE peekStack' #-}
peekStack' :: RTEnv annot -> Value annot
peekStack' env = localStack env `Seq.index` 1

{-# INLINE peekStack'' #-}
peekStack'' :: RTEnv annot -> Value annot
peekStack'' env = localStack env `Seq.index` 2

{-# INLINE peekStack''' #-}
peekStack''' :: RTEnv annot -> Value annot
peekStack''' env = localStack env `Seq.index` 3

{-# INLINE peekStackK #-}
peekStackK :: RTEnv annot -> Reference -> Value annot
peekStackK env (Reference k) | k >= 0 = localStack env `Seq.index` k
                             | otherwise = foreignStack env `Seq.index` (- k - 1)


-- |Continuations of the CEK machine. These correspond to evaluation context in the on-paper presentation
data Kont annot = Done  -- empty evaluation context
          | EvalFun (Seq.Seq (Value annot)) (Kont annot)  -- the context E[- v1 v2 ... vn] (right to left evaluation)
          | EvalLet (LinkedExpr annot) (RTEnv annot) (Kont annot) -- the context E[let x = - in e]
          | EvalLetForeign (LinkedExpr annot) (RTEnv annot) (Kont annot) -- the context E[let x = - in e]
  deriving(Eq, Show)

-- this can be done more efficiently by splitting the map into two, one for constructors which should be named 0, 1, ... n-1
-- and another one for literals
-- but barring constant factors the complexity is the same (assuming HashMap has constant lookup)
data JumpTable linked annot =
  JumpTable { jumpTable :: !(HashMap (Either Core.Literal Core.Name) (Expr linked annot))
            , defaultCase :: !(Maybe (Expr linked annot))}
    deriving(Functor)

putJumpTable :: S.Putter (Expr linked annot) -> S.Putter (JumpTable linked annot)
putJumpTable pe JumpTable{..} = do
        P.putWord32be (fromIntegral $ Map.size jumpTable)
        mapM_ putBranch (Map.toList jumpTable)
        case defaultCase of
            Nothing -> P.putWord8 0
            Just e -> P.putWord8 1 >> pe e
    where
        putBranch (pat, e) = S.put pat >> pe e

getJumpTable :: S.Get (Expr linked annot) -> S.Get (JumpTable linked annot)
getJumpTable ge = do
        nbranches <- G.getWord32be
        jumpTable <- Map.fromList <$> replicateM (fromIntegral nbranches) getBranch
        defaultCase <- G.getWord8 >>= \case
            0 -> return Nothing
            1 -> Just <$> ge
            _ -> fail "Serialization failure: invalid jump table"
        return JumpTable{..}
    where
        getBranch = (,) <$> S.get <*> ge


deriving instance (v ~ linked (Expr linked annot), Show v, Show annot) => Show (JumpTable linked annot)
deriving instance (v ~ linked (Expr linked annot), Eq v, Eq annot) => Eq (JumpTable linked annot)

{-# INLINE jumpDefault #-}                                
jumpDefault :: JumpTable linked annot -> Expr linked annot
jumpDefault = fromJust . defaultCase

{-# INLINE jumpCtor #-}                                
jumpCtor :: Core.Name -> JumpTable linked annot -> Maybe (Expr linked annot)
jumpCtor n (JumpTable jt _) = Map.lookup (Right n) jt

{-# INLINE jumpLit #-}                                
jumpLit :: Core.Literal -> JumpTable linked annot -> Maybe (Expr linked annot)
jumpLit n (JumpTable jt _) = Map.lookup (Left n) jt

-- |Reference. Positive means reference to locally bound (let, pattern, lambda),
-- negative means result bound with LetForeign (and off-by-one since we start with -1)
newtype Reference = Reference Int
    deriving(Eq, Show, Num, Ord, Enum, Real, Integral, S.Serialize)


data Atom =
  Literal !Core.Literal
  | BoundVar !Reference
  deriving (Show, Eq)

instance S.Serialize Atom where
    put (Literal l) = P.putWord8 0 <> S.put l
    put (BoundVar ref) = P.putWord8 1 <> S.put ref
    get = G.getWord8 >>= \case
        0 -> Literal <$> S.get
        1 -> BoundVar <$> S.get
        _ -> fail "Serialization failure: unknown Atom"

-- |Untyped terms with all external references replaced by links to other linked code.
data Expr linked annot =
  -- |Variables, literals. Include constructors, imported definitions, but also bound variables.
  Atom !Atom
  -- |An anonymous function. We use the de-bruijn representation of bound
  -- variables, hence no variable name. Moreover this lambda can capture
  -- multiple variables at the same time which avoids allocation of intermediate
  -- closures.
  | Lambda !Int !(Expr linked annot)
  | App !Reference !(Vector Atom)
  | Let !(Expr linked annot) !(Expr linked annot)
  -- |Binding of a top-level definition. Does not have to capture context since
  -- top-level definitions don't capture any variables.
  | LetForeign !Foreign !(linked (Expr linked annot)) !(Expr linked annot)
  | LetRec !(Vector (Expr linked annot)) !(Expr linked annot)
  -- |Case expression, the list of alternatives should be non-empty. In bodies
  -- of branches we again use the De-Bruijn convention.
  | Case !Atom !(JumpTable linked annot)
  -- |Read local state of another contract.
  | Read !Core.Name
  -- |Make a message to another contract (the message is then sent by the execution engine).
  | Send !Core.Name
  -- |Try to cast an address to an instance (returning Nothing if this fails).
  | Cast !(Core.ModuleRef, Core.TyName)
  -- |Extract an address from the instance.
  | UnCast
  -- |A primitive function. The first argument is the identifier (index in the
  -- @primitives@ table), the second is the arity of the function.
  | PrimFun !Int64
  -- |We need to tag constructors as special terms.
  | Constructor !Core.Name
  -- |Annotation to be used during debugging. Using the empty type as the annotation type
  -- will disable this node.
  | Annotate !annot !(Expr linked annot)
  deriving (Generic, Functor)

-- |Serialize an 'Expr'.  Annotations are dropped.
putExpr :: S.Putter (linked (Expr linked annot)) -> S.Putter (Expr linked annot)
putExpr pl = pe
    where
        pe (Atom a) = P.putWord8 0 >> S.put a
        pe (Lambda n e) = P.putWord8 1 >> S.put n >> pe e
        pe (App ref vec) = P.putWord8 2 >> S.put ref >> S.put (Vector.toList vec)
        pe (Let e1 e2) = P.putWord8 3 >> pe e1 >> pe e2
        pe (LetForeign fref link e) = P.putWord8 4 >> S.put fref >> pl link >> pe e
        pe (LetRec vec e) = P.putWord8 5 >> P.putWord32be (fromIntegral $ Vector.length vec) >> mapM_ pe vec >> pe e
        pe (Case a jt) = P.putWord8 6 >> S.put a >> putJumpTable pe jt
        pe (Read n) = P.putWord8 7 >> S.put n
        pe (Send n) = P.putWord8 8 >> S.put n
        pe (Cast c) = P.putWord8 9 >> S.put c
        pe (UnCast) = P.putWord8 10
        pe (PrimFun f) = P.putWord8 11 >> S.put f
        pe (Constructor n) = P.putWord8 12 >> S.put n
        pe (Annotate _ e) = pe e

-- |Deserialize an 'Expr'.
getExpr :: S.Get (linked (Expr linked annot)) -> S.Get (Expr linked annot)
getExpr gl = ge
    where
        ge = G.getWord8 >>= \case
            0 -> Atom <$> S.get
            1 -> Lambda <$> S.get <*> ge
            2 -> App <$> S.get <*> (Vector.fromList <$> S.get)
            3 -> Let <$> ge <*> ge
            4 -> LetForeign <$> S.get <*> gl <*> ge
            5 -> do
                n <- G.getWord32be
                vec <- Vector.fromList <$> replicateM (fromIntegral n) ge
                LetRec vec <$> ge
            6 -> Case <$> S.get <*> getJumpTable ge
            7 -> Read <$> S.get
            8 -> Send <$> S.get
            9 -> Cast <$> S.get
            10 -> return UnCast
            11 -> PrimFun <$> S.get
            12 -> Constructor <$> S.get
            _ -> fail "Serialization failure: unknown Expr"

instance (forall a. S.Serialize a => S.Serialize (linked a)) => S.Serialize (Expr linked annot) where
    put = putExpr S.put
    get = getExpr S.get


deriving instance (v ~ linked (Expr linked annot), Show v, Show annot) => Show (Expr linked annot)
deriving instance (v ~ linked (Expr linked annot), Eq v, Eq annot) => Eq (Expr linked annot)

-- |TODO: Manually define the serialize instance similar to how it is defined for Acorn expressions.

data ImplementsValue linked annot = ImplementsValue
    {
    -- |The list of sender methods for a particular constraint this contract implements.
    ivSenders :: !(Vector (SenderTy linked annot, Word64)),
    -- |The list of getter methods for a particular constraint this contract implements.
    ivGetters :: !(Vector (GetterTy linked annot, Word64))
    } deriving(Functor)

deriving instance (v ~ linked (Expr linked annot), Show v, Show annot) => Show (ImplementsValue linked annot)
deriving instance (v ~ linked (Expr linked annot), Eq v, Eq annot) => Eq (ImplementsValue linked annot)

instance (forall a. S.Serialize a => S.Serialize (linked a)) => S.Serialize (ImplementsValue linked annot) where
    put (ImplementsValue{..}) = S.put (Vector.toList ivSenders) >> S.put (Vector.toList ivGetters)
    get = ImplementsValue <$> (Vector.fromList <$> S.get) <*> (Vector.fromList <$> S.get)

type LinkedImplementsValue = ImplementsValue Linked

data Unlinked a = Unlinked
    deriving(Eq, Show, Functor)

instance S.Serialize (Unlinked a) where
    put _ = return ()
    get = return Unlinked

type UnlinkedExpr = Expr Unlinked

newtype Linked a = Linked a
    deriving(Eq, Show, Functor, S.Serialize)

type LinkedExpr annot = Expr Linked annot

data LinkedExprWithDeps annot = LinkedExprWithDeps {
  -- |The actual linked expression.
  leExpr :: !(LinkedExpr annot),
  -- |List of dependencies with sizes.
  leDeps :: !(HashMap (Core.ModuleRef, Core.Name) Word64)
  } deriving(Eq, Show, Functor)

data Foreign =
  Local !Core.Name
  |Imported !Core.ModuleRef !Core.Name
  deriving(Eq, Show, Generic, Ord)

instance S.Serialize Foreign

instance Hashable Foreign

-- |aliases for the types of init and update/receive methods.
type InitMethod = Expr
type ReceiveMethod = Expr 

type SenderTy = Expr
type GetterTy = Expr

type LinkedInitMethod annot = LinkedExpr annot
type LinkedReceiveMethod annot = LinkedExpr annot

-- |A 'ContractValue' is what a contract evaluates to. It contains the code of the init and receive methods.
data ContractValue linked annot = ContractValue
    {
      -- |The compiled initilization method.
      cvInitMethod :: !(InitMethod linked annot, Word64),
      -- |The compiled receive method.
      cvReceiveMethod :: !(ReceiveMethod linked annot, Word64),
      -- |A map of all the implemented constraints.
      cvImplements :: !(HashMap (Core.ModuleRef, Core.TyName) (ImplementsValue linked annot)) 
    } deriving(Generic, Functor)

type LinkedContractValue = ContractValue Linked
type UnlinkedContractValue = ContractValue Unlinked

deriving instance (v ~ linked (Expr linked annot), Show v, Show annot) => Show (ContractValue linked annot)
deriving instance (v ~ linked (Expr linked annot), Eq v, Eq annot) => Eq (ContractValue linked annot)

instance (forall a. S.Serialize a => S.Serialize (linked a)) => S.Serialize (ContractValue linked annot) where
    put ContractValue{..} = S.put cvInitMethod >> S.put cvReceiveMethod >> putHashMap cvImplements
    get = ContractValue <$> S.get <*> S.get <*> getHashMap

-- |A mapping of identifiers to values, e.g., definitions to values, and of contract identifiers to their
-- respective initialization functions and receive functions.
-- A module evalutes to a value of this type.
data ValueInterface linked annot = ValueInterface {
  -- |Compiled top-level definitions.
  -- Private and public (since at runtime a public definition might depend on the private one).
  -- We also record the sizes of terms.
  viDefs :: !(HashMap Core.Name (Expr linked annot, Word64)),
  -- |Exported contracts with their init and receive methods.
  viContracts :: !(HashMap Core.TyName (ContractValue linked annot))
  } deriving(Functor)

deriving instance (v ~ linked (Expr linked annot), Show v, Show annot) => Show (ValueInterface linked annot)

type LinkedValueInterface = ValueInterface Linked
type UnlinkedValueInterface = ValueInterface Unlinked

instance (forall a. S.Serialize a => S.Serialize (linked a)) => S.Serialize (ValueInterface linked annot) where
    put ValueInterface{..} = putHashMap viDefs >> putHashMap viContracts
    get = ValueInterface <$> getHashMap <*> getHashMap

-- |Empty value interface
emptyValueInterface :: ValueInterface linked annot
emptyValueInterface = ValueInterface Map.empty Map.empty

-- * Serialization instances for interfaces.
-- $serialization
-- NB: The format is not designed with
-- efficiency in mind for now, and should be fixed if we need to use it in a
-- performance critical way.

instance S.Serialize (ContractInterface annot)

putHashMap :: (S.Serialize a, S.Serialize b) => HashMap a b -> S.Put
putHashMap = S.put . Map.toList

getHashMap :: (Eq a, Hashable a, S.Serialize a, S.Serialize b) => S.Get (HashMap a b)
getHashMap = Map.fromList <$> S.get

instance S.Serialize (DataTypeInterface annot) where
  put (DataTypeInterface{..}) =
    S.put dtiParams <>
    putHashMap dtiCtors <>
    Core.putVisibility dtiCtorsVis

  get = do
    dtiParams <- S.get
    dtiCtors <- getHashMap
    dtiCtorsVis <- Core.getVisibility
    return DataTypeInterface{..}

instance S.Serialize (Interface annot) where
  put (Interface{..}) =
    S.put uniqueName <>
    P.putWord64be iSize <>
    putHashMap importedModules <>
    putHashMap exportedTypes <>
    putHashMap exportedTerms <>
    putHashMap exportedContracts <>
    putHashMap exportedConstraints

  get = do
    uniqueName <- S.get
    iSize <- G.getWord64be
    importedModules <- getHashMap
    exportedTypes <- getHashMap
    exportedTerms <- getHashMap
    exportedContracts <- getHashMap
    exportedConstraints <- getHashMap
    return Interface{..}

type AbsoluteConstraintRef = (Core.ModuleRef, Core.TyName)

-- * Monads needed for various parts of the interpreter.
-- The monads provide the context needed to lookup other modules or contract states.
class Monad m => InterpreterMonad annot m | m -> annot where
  -- |Try to look up the contract state at the given address. If a contract
  -- exists then return the constraints it implements and its current local state.
  getCurrentContractState :: ContractAddress -> m (Maybe (HashMap AbsoluteConstraintRef (LinkedImplementsValue annot), Value annot))

class Monad m => LinkerMonad annot m | m -> annot where
  getExprInModule :: Core.ModuleRef -> Core.Name -> m (Maybe (UnlinkedExpr annot, Word64))

  tryGetLinkedExpr :: Core.ModuleRef -> Core.Name -> m (Maybe (LinkedExprWithDeps annot))

  putLinkedExpr :: Core.ModuleRef -> Core.Name -> LinkedExprWithDeps annot -> m ()

class Monad m => TypecheckerMonad annot m | m -> annot where
  typingError :: TypingError annot -> m a
  default typingError :: MonadError (TypingError annot) m => TypingError annot -> m a
  typingError = throwError

  getExportedTermType :: Core.ModuleRef -> Core.Name -> m (Maybe (Type annot Core.ModuleRef))
  getExportedType :: Core.ModuleRef -> Core.TyName -> m (Maybe (DataTypeInterface annot))
  getExportedConstraints :: Core.ModuleRef -> Core.TyName -> m (Maybe (Core.ConstraintDecl annot Core.ModuleRef))

  -- |Only for logging. On chain all the domain types are void so these cannot be used.
  logExprAnnot :: Core.ExprAnnot annot -> m ()
  logPatternAnnot :: Core.PatternAnnot annot -> m ()
  logTypeAnnot :: Core.TypeAnnot annot -> m ()

  -- |Default instances for unannotated terms.
  default logExprAnnot :: annot ~ Core.UA => Core.ExprAnnot annot -> m ()
  logExprAnnot = Core.absurd
  {-# INLINE logExprAnnot #-}
  default logPatternAnnot :: annot ~ Core.UA => Core.PatternAnnot annot -> m ()
  logPatternAnnot = Core.absurd
  {-# INLINE logPatternAnnot #-}
  default logTypeAnnot :: annot ~ Core.UA => Core.TypeAnnot annot -> m ()
  logTypeAnnot = Core.absurd
  {-# INLINE logTypeAnnot #-}

-- |The ability to retrieve static information, static meaning no local state of
-- contracts, nor amounts. This is sufficient for typechecking and compiling
-- modules and is used by the scheduler.
class Monad m => StaticEnvironmentMonad annot m | m -> annot where
  -- |Get chain metadata that is needed for contract execution.
  getChainMetadata :: m ChainMetadata

  -- |Return a module interface needed for typechecking.
  getModuleInterfaces :: Core.ModuleRef -> m (Maybe (Interface annot, UnlinkedValueInterface (Core.ExprAnnot annot)))

  getInterface :: Core.ModuleRef -> m (Maybe (Interface annot))
  getInterface mref = do
    getModuleInterfaces mref >>= \case
      Just (mres, _) -> return (Just mres)
      Nothing -> return Nothing

-- |Add safe exception handling to the environment monad.
instance StaticEnvironmentMonad annot m => StaticEnvironmentMonad annot (ExceptT (TypingError annot) m) where
  getChainMetadata = lift getChainMetadata
  getModuleInterfaces = lift . getModuleInterfaces

instance StaticEnvironmentMonad annot m => StaticEnvironmentMonad annot (MaybeT m) where
  getChainMetadata = lift getChainMetadata
  getModuleInterfaces = lift . getModuleInterfaces


-- |This can only be used with unannotated terms. It is therefore meant for on-chain use.
-- For local use one should implement a custom instance of the typechecker monad which
-- has custom behaviour for different (custom) annotations.
instance (StaticEnvironmentMonad annot m, annot ~ Core.UA) => TypecheckerMonad annot (ExceptT (TypingError annot) m) where
  {-# INLINE getExportedTermType #-}
  getExportedTermType mref n = 
    getInterface mref >>=
      \case Nothing -> throwError $ ModuleNotExists mref
            Just iface -> return $ Map.lookup n (exportedTerms iface)

  {-# INLINE getExportedType #-}
  getExportedType mref n = 
    getInterface mref >>=
      \case Nothing -> throwError $ ModuleNotExists mref
            Just iface -> return $ Map.lookup n (exportedTypes iface)

  {-# INLINE getExportedConstraints #-}
  getExportedConstraints mref n = 
    getInterface mref >>=
      \case Nothing -> throwError $ ModuleNotExists mref
            Just iface -> return $ Map.lookup n (exportedConstraints iface)

instance (StaticEnvironmentMonad annot m, annot ~ Core.UA) => TypecheckerMonad annot (MaybeT m) where
  {-# INLINE typingError #-}
  typingError _ = mzero

  {-# INLINE getExportedTermType #-}
  getExportedTermType mref n =
    getInterface mref >>=
      \case Nothing -> mzero
            Just iface -> return $ Map.lookup n (exportedTerms iface)

  {-# INLINE getExportedType #-}
  getExportedType mref n =
    getInterface mref >>=
      \case Nothing -> mzero
            Just iface -> return $ Map.lookup n (exportedTypes iface)

  {-# INLINE getExportedConstraints #-}
  getExportedConstraints mref n =
    getInterface mref >>=
      \case Nothing -> mzero
            Just iface -> return $ Map.lookup n (exportedConstraints iface)
