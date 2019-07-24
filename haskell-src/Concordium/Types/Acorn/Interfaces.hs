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

import Data.Hashable(Hashable)
import Data.HashMap.Strict(HashMap)
import qualified Data.HashMap.Strict as Map
import qualified Data.Sequence as Seq
import Data.Int
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
             VClosure !(RTEnv annot) !(Expr annot) -- ^Functions evaluate to closures.
             | VRecClosure !(RTEnv annot) !Int ![Expr annot] -- ^Recursive functions evaluate to recursive closures.
             | VLiteral !Core.Literal    -- ^Base literals.
             | VConstructor !Core.Name ![Value annot] -- ^Constructors applied to arguments.
                                             -- FIXME: Should use sequence instead of list here as well since it is usually built by appending to the back.
             | VInstance { vinstance_ls :: !(Value annot)
                         , vinstance_caddr :: !ContractAddress
                         , vinstance_implements :: !(ImplementsValue annot)
                         }
  deriving(Show, Eq)


-- |The serialization instances for values are only for storable values.
-- If you try to serialize with a value which is not storable the methods will fail.
putStorable :: P.Putter (Value annot)
putStorable (VLiteral l) = P.putWord8 0 <> Core.putLit l
putStorable (VConstructor n vals) = do
  P.putWord8 1
  Core.putName n
  Core.putLength vals
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
      vals <- replicateM l getStorable
      return $ VConstructor name vals
    _ -> fail "Serialization failure. Unknown node."

newtype RTEnv annot = RTEnv { localStack :: (Seq.Seq (Value annot)) }
  deriving(Show, Eq)

{-# INLINE singletonLocalStack #-}
singletonLocalStack :: Value annot -> RTEnv annot
singletonLocalStack v = RTEnv { localStack = Seq.singleton v }

{-# INLINE pushToStack #-}
-- |NB: It is quite crucial that this method is strict in the value. If not then
-- the interpreter can leak memory because a closure that is pushed onto the
-- environment retains references to elements which are not longer reachable.
pushToStack :: RTEnv annot -> Value annot -> RTEnv annot
pushToStack env !v = env { localStack = v Seq.<| localStack env }

{-# INLINE pushAllToStack #-}
pushAllToStack :: RTEnv annot -> Seq.Seq (Value annot) -> RTEnv annot
pushAllToStack env v = env { localStack = v Seq.>< localStack env }

emptyStack :: RTEnv annot
emptyStack = RTEnv Seq.empty

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
peekStackK :: RTEnv annot -> Int -> Value annot
peekStackK env k = localStack env `Seq.index` k


-- |Continuations of the CEK machine. These correspond to evaluation context in the on-paper presentation
data Kont annot = Done  -- empty evaluation context
          | EvalArg (Expr annot) (RTEnv annot) (Kont annot)  -- the context E[e -] (right to left evaluation)
          | EvalFun (Value annot) (Kont annot)  -- the context E[- v] (right to left evaluation)
          | EvalCase !(JumpTable annot) (RTEnv annot) (Kont annot) -- the context E[case - of pats]
          | EvalLet (Expr annot) (RTEnv annot) (Kont annot) -- the context E[let x = - in e]
  deriving(Eq, Show)

-- this can be done more efficiently by splitting the map into two, one for constructors which should be named 0, 1, ... n
-- and another one for literals
-- but barring constant factors the complexity is the same (assuming HashMap has constant lookup)
data JumpTable annot =
  JumpTable { jumpTable :: !(HashMap (Either Core.Literal Core.Name) (Expr annot))
            , defaultCase :: !(Maybe (Expr annot))}
    deriving(Show, Eq, Functor)

{-# INLINE jumpDefault #-}                                
jumpDefault :: JumpTable annot -> Expr annot
jumpDefault = fromJust . defaultCase

{-# INLINE jumpCtor #-}                                
jumpCtor :: Core.Name -> JumpTable annot -> Maybe (Expr annot)
jumpCtor n (JumpTable jt _) = Map.lookup (Right n) jt

{-# INLINE jumpLit #-}                                
jumpLit :: Core.Literal -> JumpTable annot -> Maybe (Expr annot)
jumpLit n (JumpTable jt _) = Map.lookup (Left n) jt

-- |Untyped terms with all external references replaced by links to other linked code.
data Expr annot
  = 
    Literal !Core.Literal           
  -- |Variables. Include constructors, imported definitions, but also bound variables.
  | BoundVar !Core.BoundVar
  -- |An anonymous function with type of its argument. We use the de-bruijn
  -- representation of bound variables, hence no variable name.
  | Lambda !(Expr annot)
  | App !(Expr annot) !(Expr annot)
  | Let !(Expr annot) !(Expr annot)
  | LetRec ![Expr annot] !(Expr annot)
  -- |Case expression, the list of alternatives should be non-empty. In bodies
  -- of branches we again use the De-Bruijn convention.
  | Case !(Expr annot) !(JumpTable annot)
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
  -- |Constructor.
  | Constructor !Core.Name
  -- |Annotation to be used during debugging. Using the empty type as the annotation type
  -- will disable this node.
  | Annotate !annot !(Expr annot)
  deriving (Show, Eq, Generic, Functor)

-- |TODO: Manually define the serialize instance similar to how it is defined for Acorn expressions.

-- t -> msgty of the contract
type SenderTy = Expr
-- just a state view function, stateTy of the contract -> specified type
type GetterTy = Expr

-- |aliases for the types of init and update/receive methods.
type InitType = Expr
type UpdateType = Expr

data ImplementsValue annot = ImplementsValue
    {
    -- |The list of sender methods for a particular constraint this contract implements.
    senderImpls :: !(Seq.Seq (SenderTy annot))
    -- |The list of getter methods for a particular constraint this contract implements.
    ,getterImpls :: !(Seq.Seq (GetterTy annot))
    } deriving(Eq, Show, Functor)

-- |A 'ContractValue' is what a contract evaluates to. It contains the code of the init and receive methods in a ready-to-execute form.
data ContractValue annot = ContractValue
    { -- |The compiled initilization method.
      initMethod :: !(InitType annot)
    -- |The compiled receive method.
    ,updateMethod :: !(UpdateType annot)
    -- |A map of all the implemented constraints.
    ,implements :: !(HashMap (Core.ModuleRef, Core.TyName) (ImplementsValue annot)) 
    } deriving(Show, Generic, Functor)

-- |A mapping of identifiers to values, e.g., definitions to values, and of contract identifiers to their
-- respective initialization functions and receive functions.
-- A module evalutes to a value of this type.
data ValueInterface annot = ValueInterface
    {exportedDefsVals :: !(HashMap Core.Name (Expr annot)) -- exported definitions, e.g., the library
    ,exportedDefsConts :: !(HashMap Core.TyName (ContractValue annot))  -- exported contracts with their init and update methods
    }
    deriving(Show, Functor)

-- |Empty value interface
emptyValueInterface :: ValueInterface annot
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


-- * Monads needed for various parts of the interpreter.
-- The monads provide the context needed to lookup other modules or contract states.
class Monad m => InterpreterMonad annot m | m -> annot where
  getCurrentContractState :: ContractAddress -> m (Maybe (HashMap (Core.ModuleRef, Core.TyName) (ImplementsValue annot), Value annot))

class Monad m => LinkerMonad annot m | m -> annot where
  getExprInModule :: Core.ModuleRef -> Core.Name -> m (Maybe (Expr annot))

class Monad m => TypecheckerMonad annot m | m -> annot where
  getExportedTermType :: Core.ModuleRef -> Core.Name -> m (Maybe (Type annot Core.ModuleRef))
  getExportedType :: Core.ModuleRef -> Core.TyName -> m (Maybe (Int, HashMap Core.Name [Type annot Core.ModuleRef]))
  getExportedConstraints :: Core.ModuleRef -> Core.TyName -> m (Maybe (Core.ConstraintDecl annot Core.ModuleRef))

-- |The ability to retrieve static information, static meaning no local state of
-- contracts, nor amounts. This is sufficient for typechecking and compiling
-- modules and is used by the scheduler.
class Monad m => StaticEnvironmentMonad annot m | m -> annot where
  -- |Get chain metadata that is needed for contract execution.
  getChainMetadata :: m ChainMetadata

  -- |Return a module interface needed for typechecking.
  getModuleInterfaces :: Core.ModuleRef -> m (Maybe (Interface annot, ValueInterface (Core.ExprAnnot annot)))

  getInterface :: Core.ModuleRef -> m (Maybe (Interface annot))
  getInterface mref = do
    mres <- getModuleInterfaces mref
    return (fst <$> mres)

-- |Add safe exception handling to the environment monad.
instance StaticEnvironmentMonad annot m => StaticEnvironmentMonad annot (ExceptT (TypingError annot) m) where
  getChainMetadata = lift getChainMetadata
  getModuleInterfaces = lift . getModuleInterfaces

instance StaticEnvironmentMonad annot m => StaticEnvironmentMonad annot (MaybeT m) where
  getChainMetadata = lift getChainMetadata
  getModuleInterfaces = lift . getModuleInterfaces


instance StaticEnvironmentMonad annot m => TypecheckerMonad annot (ExceptT (TypingError annot) m) where
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
            Just (_, viface) -> return $ Map.lookup n (exportedDefsVals viface)
