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
{-# OPTIONS_GHC -Wall #-}

module Concordium.Types.Acorn.Interfaces where

import GHC.Generics(Generic)

import Data.Vector(Vector)
import Data.Hashable(Hashable)
import Data.HashMap.Strict(HashMap)
import qualified Data.HashMap.Strict as Map
import qualified Data.Sequence as Seq
import Data.Int
import Data.Maybe(fromJust)
import Data.Foldable
import Control.Monad.Trans.Maybe
import Control.Monad.Except

import qualified Data.Serialize.Put as P
import qualified Data.Serialize.Get as G
import qualified Data.Serialize as S

import Concordium.Types
import qualified Concordium.Types.Acorn.Core as Core

import Data.Void(absurd)

-- * Datatypes involved in typechecking, and any other operations involving types.

type Type = Core.Type 

-- |Interface of a contract.
data ContractInterface annot = ContractInterface
    { paramTy :: !(Type annot Core.ModuleRef) -- ^Type of the parameter of the init method.
    , msgTy :: !(Type annot Core.ModuleRef) -- ^Type of messages the receive method can handle.
    }
  deriving(Eq, Generic)

deriving instance Core.AnnotContext Show annot => Show (ContractInterface annot)

-- |Interface derived from a module. This is used in typechecking other modules.
-- Lists public functions which can be called, and types of methods.
data Interface annot = Interface
    { uniqueName :: !Core.ModuleRef
    , importedModules :: !(HashMap Core.ModuleName Core.ModuleRef)
    , exportedTypes :: !(HashMap Core.TyName (Int, HashMap Core.Name [Type annot Core.ModuleRef]))
    , exportedTerms :: !(HashMap Core.Name (Type annot Core.ModuleRef))
    , exportedContracts :: !(HashMap Core.TyName (ContractInterface annot))
    , exportedConstraints :: !(HashMap Core.TyName (Core.ConstraintDecl annot Core.ModuleRef))
    }
  deriving (Generic)

deriving instance Core.AnnotContext Show annot => Show (Interface annot)
deriving instance Core.AnnotContext Eq annot => Eq (Interface annot)

emptyInterface :: Core.ModuleRef -> Interface annot
emptyInterface mref = Interface mref Map.empty Map.empty Map.empty Map.empty Map.empty

type ModuleInterfaces annot = HashMap Core.ModuleRef (Interface annot)

-- |Errors which can occur during typechecking.
data TypingError annot =
                 -- |A declared datatype is instantiated with
                 -- a wrong number of arguments (too few or too many). The first
                 -- argument is the number of given parameters, the second the
                 -- expected number.
                   IncorrectNumberOfTypeParameters Int Int
                 -- |A type abstraction is applied to a term which is not a type.
                 | TypeAbstractionNotAppliedToType (Core.Expr annot Core.ModuleRef)
                 -- |A type appears where a term is expected.
                 | TypeWhereTermExpected (Core.Type annot ModuleRef)
                 -- |A term is applied which is neither of a function type, nor
                 -- universal type. The first argument is the term to be
                 -- applied, the second its type.
                 | OnlyAbstractionsCanBeApplied (Core.Expr annot Core.ModuleRef) (Core.Type annot ModuleRef)
                 -- |The type of an argument given to a function does not match
                 -- the function's definition. The first argument is the actual
                 -- type, the second the expected type.
                 | UnexpectedArgumentType (Core.Type annot ModuleRef) (Core.Type annot ModuleRef)
                 -- |The result type of a defined function (e.g. in a letrec)
                 -- does not match the specified result type. The first argument
                 -- is the actual type, the second the specified type.
                 | ResultTypeNotAsSpecified (Core.Type annot ModuleRef) (Core.Type annot ModuleRef)
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
                 -- |A more specific case of 'UnexpectedPatternType'. A constructor pattern occurs
                 -- at a place where the discriminee has a base type.
                 | TypeConstructorWhereLiteralOrVariableExpected (Core.CTorName Core.ModuleRef)
                 -- |A more specific case of 'UnexpectedPatternType'. A litreal occurs at a place
                 -- where the discriminee has a declared datatype.
                 | LiteralWhereTypeConstructorExpected Core.Literal
                 -- |The body of a case alternative does not have
                 -- the correct type. The first argument is the actual type, the
                 -- second is the expected type.
                 | UnexpectedCaseAlternativeResultType (Core.Type annot ModuleRef) (Core.Type annot ModuleRef)
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
                 -- |The module with the given name (referred to from an expression)
                 -- is not imported (not part of the given interface's import map).
                 | ModuleNotImported Core.ModuleName
                 -- |The referenced local definition does not exist in the current module.
                 | LocalNameNotInScope Core.Name
                 -- |The referenced imported definition does not exist in the given module.
                 | QualifiedNameNotInScope Core.ModuleRef Core.Name
                 -- |A module with the given reference does not exist. Raised when
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
                 -- |The init method of a contract is not of the correct type.
                 -- The argument is the name of the contract this error refers to.
                 | ContractInitMethodHasIncorrectType Core.TyName
                 -- |The receive method of a contract is not of the correct
                 -- type (in the context of the types specified by the init
                 -- method). The argument is the name of the contract this error refers to.
                 | ContractReceiveMethodHasIncorrectType Core.TyName
                 -- |A more specific case of 'ContractReceiveMethodHasIncorrectType'
                 -- where the result type is not as required. The first
                 -- argument is the name of the contract this error refers to
                 -- and the second is the result type of the receive method.
                 | ContractReceiveMethodHasIncorrectResultType Core.TyName (Core.Type annot ModuleRef)
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
                 | ContractUnexpectedGetterImplementation Core.TyName (Core.ConstraintRef Core.ModuleRef) Core.Name Core.Name
                 -- |An implementation of a sender method in a contract does not
                 -- match the expected method to be implemented at that position.
                 -- The first and second arguments are the name of the contract and the
                 -- constraint this error refers to, the third the name of the
                 -- method that is implemented and the fourth the name of the
                 -- method that is expected to be implemented.
                 | ContractUnexpectedSenderImplementation Core.TyName (Core.ConstraintRef Core.ModuleRef) Core.Name Core.Name
                 -- |An implementation of a getter method in a contract does not
                 -- have the correct type. The first and second arguments are
                 -- the name of the contract and the constraint this error
                 -- refers to, the third the incorrect type of the implementation.
                 | ContractUnexpectedGetterType Core.TyName (Core.ConstraintRef Core.ModuleRef) (Core.Type annot ModuleRef)
                 -- |An implementation of a sender method in a contract does not
                 -- have the correct type. The first and second arguments are
                 -- the name of the contract and the constraint this error
                 -- refers to, the third the incorrect type of the
                 -- implementation.
                 | ContractUnexpectedSenderType Core.TyName (Core.ConstraintRef Core.ModuleRef) (Core.Type annot ModuleRef)
                 -- |The public definition (explicit definition or datatype constructor)
                 -- with the given name has a private type.
                 | PublicDefinitionWithPrivateType Core.Name (Core.Type annot ModuleRef)
                 -- |An expression to be type checked has not the type specified
                 -- as the expected type. The first argument is the type encountered,
                 -- the second is the expected type.
                 | UnexpectedType (Core.Type annot ModuleRef) (Core.Type annot ModuleRef)

deriving instance Core.AnnotContext Eq annot => Eq (TypingError annot)
deriving instance Core.AnnotContext Show annot => Show (TypingError annot)

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
    deriving(Eq, Show, Num, Ord, Enum, Real, Integral)

data Atom =
  Literal !Core.Literal
  | BoundVar !Reference
  deriving (Show, Eq)

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

deriving instance (v ~ linked (Expr linked annot), Show v, Show annot) => Show (Expr linked annot)
deriving instance (v ~ linked (Expr linked annot), Eq v, Eq annot) => Eq (Expr linked annot)

-- |TODO: Manually define the serialize instance similar to how it is defined for Acorn expressions.

data ImplementsValue linked annot = ImplementsValue
    {
    -- |The list of sender methods for a particular constraint this contract implements.
    ivSenders :: !(Vector (SenderTy linked annot)),
    -- |The list of getter methods for a particular constraint this contract implements.
    ivGetters :: !(Vector (GetterTy linked annot))
    } deriving(Functor)

deriving instance (v ~ linked (Expr linked annot), Show v, Show annot) => Show (ImplementsValue linked annot)
deriving instance (v ~ linked (Expr linked annot), Eq v, Eq annot) => Eq (ImplementsValue linked annot)

type LinkedImplementsValue = ImplementsValue Linked

newtype Unlinked a = Unlinked ()
    deriving(Eq, Show, Functor)

type UnlinkedExpr = Expr Unlinked

newtype Linked a = Linked a
    deriving(Eq, Show, Functor)

type LinkedExpr annot = Expr Linked annot

data Foreign =
  Local !Core.Name
  |Imported !Core.ModuleRef !Core.Name
  deriving(Eq, Show, Generic)

instance Hashable Foreign

-- |aliases for the types of init and update/receive methods.
type InitMethod = Expr
type ReceiveMethod = Expr 

type SenderTy = Expr
type GetterTy = Expr

type LinkedInitMethod = UnlinkedExpr
type LinkedReceiveMethod = UnlinkedExpr 

-- |A 'ContractValue' is what a contract evaluates to. It contains the code of the init and receive methods.
data ContractValue linked annot = ContractValue
    {
      -- |The compiled initilization method.
      cvInitMethod :: !(InitMethod linked annot),
      -- |The compiled receive method.
      cvReceiveMethod :: !(ReceiveMethod linked annot),
      -- |A map of all the implemented constraints.
      cvImplements :: !(HashMap (Core.ModuleRef, Core.TyName) (ImplementsValue linked annot)) 
    } deriving(Generic, Functor)

type LinkedContractValue = ContractValue Linked
type UnlinkedContractValue = ContractValue Unlinked

deriving instance (v ~ linked (Expr linked annot), Show v, Show annot) => Show (ContractValue linked annot)
deriving instance (v ~ linked (Expr linked annot), Eq v, Eq annot) => Eq (ContractValue linked annot)

-- |A mapping of identifiers to values, e.g., definitions to values, and of contract identifiers to their
-- respective initialization functions and receive functions.
-- A module evalutes to a value of this type.
data ValueInterface linked annot = ValueInterface {
  -- |Compiled top-level definitions.
  -- Private and public (since at runtime a public definition might depend on the private one).
  viDefs :: !(HashMap Core.Name (Expr linked annot)),
  -- |Exported contracts with their init and receive methods.
  viContracts :: !(HashMap Core.TyName (ContractValue linked annot))
  } deriving(Functor)

deriving instance (v ~ linked (Expr linked annot), Show v, Show annot) => Show (ValueInterface linked annot)

type LinkedValueInterface = ValueInterface Linked
type UnlinkedValueInterface = ValueInterface Unlinked

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


putExportedTypes :: (S.Serialize a, S.Serialize b, S.Serialize c, S.Serialize d) => HashMap a (b, HashMap c d) -> S.Put
putExportedTypes = putHashMap . Map.map (\(i, m) -> (i, Map.toList m))

getExportedTypes :: (Eq a, Hashable a, Eq c, Hashable c, S.Serialize a, S.Serialize b, S.Serialize c, S.Serialize d) => S.Get (HashMap a (b, HashMap c d))
getExportedTypes = do
  Map.map (\(i, m) -> (i, Map.fromList m)) <$> getHashMap
  

instance S.Serialize (Interface annot) where
  put (Interface{..}) =
    S.put uniqueName <>
    putHashMap importedModules <>
    putExportedTypes exportedTypes <>
    putHashMap exportedTerms <>
    putHashMap exportedContracts <>
    putHashMap exportedConstraints

  get = do
    uniqueName <- S.get
    importedModules <- getHashMap
    exportedTypes <- getExportedTypes
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
  getExprInModule :: Core.ModuleRef -> Core.Name -> m (Maybe (UnlinkedExpr annot))

class Monad m => TypecheckerMonad annot m | m -> annot where
  getExportedTermType :: Core.ModuleRef -> Core.Name -> m (Maybe (Type annot Core.ModuleRef))
  getExportedType :: Core.ModuleRef -> Core.TyName -> m (Maybe (Int, HashMap Core.Name [Type annot Core.ModuleRef]))
  getExportedConstraints :: Core.ModuleRef -> Core.TyName -> m (Maybe (Core.ConstraintDecl annot Core.ModuleRef))

  -- |Only for logging. On chain all the domain types are void so these cannot be used.
  logExprAnnot :: Core.ExprAnnot annot -> m ()
  logPatternAnnot :: Core.PatternAnnot annot -> m ()
  logTypeAnnot :: Core.TypeAnnot annot -> m ()

  -- |Default instances for unannotated terms.
  default logExprAnnot :: annot ~ Core.UA => Core.ExprAnnot annot -> m ()
  logExprAnnot = absurd
  {-# INLINE logExprAnnot #-}
  default logPatternAnnot :: annot ~ Core.UA => Core.PatternAnnot annot -> m ()
  logPatternAnnot = absurd
  {-# INLINE logPatternAnnot #-}
  default logTypeAnnot :: annot ~ Core.UA => Core.TypeAnnot annot -> m ()
  logTypeAnnot = absurd
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


instance (annot ~ Core.ExprAnnot tannot, StaticEnvironmentMonad tannot m) => LinkerMonad annot (MaybeT m) where
  {-# INLINE getExprInModule #-}
  getExprInModule mref n =
    getModuleInterfaces mref >>=
      \case Nothing -> return Nothing
            Just (_, viface) -> return (Map.lookup n (viDefs viface))
