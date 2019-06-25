{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections, OverloadedStrings, LambdaCase #-}
module Types.CoreAllGen where

import qualified Data.ByteString as BS

import Control.Monad

import Concordium.Types
import Concordium.Types.Acorn.Core
import Types.NumericTypes()
import Data.FixedByteString as FBS

import qualified Concordium.Crypto.SHA256 as SHA256

import Test.QuickCheck

genName :: Gen Name
genName = Name <$> arbitrary

genTyName :: Gen TyName
genTyName = TyName <$> arbitrary

genBoundVar :: Gen BoundVar
genBoundVar = BV <$> arbitrary

genBoundTyVar :: Gen BoundTyVar
genBoundTyVar = BTV <$> arbitrary

genModuleName :: Gen ModuleName
genModuleName = ModuleName <$> arbitrary

genDataTyName :: Gen (DataTyName ModuleName)
genDataTyName = oneof [LocalDataTy <$> genTyName, ImportedDataTy <$> genTyName <*> genModuleName]

genType :: Gen (Type ModuleName)
genType = sized $ genType'
  where genType' n = oneof [genBaseType
                           ,TVar <$> genBoundTyVar
                           ,genArr n
                           ,genApp n
                           ,genForall n]
        genBaseType = TBase <$> elements [TInt128, TInt256, TInt32, TInt64, TWord128, TWord256, TWord32, TWord64, TByteStr32, TByteString, TCAddress, TAAddress]
        genAtom = flip TApp [] <$> genDataTyName
        basetys = [genBaseType, genAtom]
        genArr n | n > 0 = liftM2 TArr (genType' (n `div` 2)) (genType' (n `div` 2))
                 | otherwise = liftM2 TArr (oneof basetys) (oneof basetys)
        genApp n | n > 0 = do
                     l <- choose (0, n)
                     TApp <$> genDataTyName <*> vectorOf l (genType' (n `div` ((l+1) * (l+1))))
                 | otherwise = genAtom
        genForall n | n > 0 = TForall <$> (genType' (n-1))
                    | otherwise = TForall <$> oneof basetys

-- TODO remove?
-- minInt128 :: Integer
-- minInt128 = 2^127

-- TODO remove when implementing Int256
minInt256 :: Integer
minInt256 = 2^(255 :: Int)

genLit :: Gen Literal
genLit = oneof [Str . BS.pack <$> arbitrary
               ,Int256 . (flip (-) minInt256) . (`mod` 2^(256 :: Int)) . abs <$> arbitrary -- TODO adapt when implementing Int256
               -- ,Int128 . (flip (-) minInt128) . (`mod` 2^128) . abs <$> arbitrary
               ,Int128 <$> arbitrary -- TODO this should be fine?
               ,Int32 <$> arbitrary
               ,Int64 <$> arbitrary
               ,Word256 . (`mod` 2^(256 :: Int)) . abs <$> arbitrary -- TODO adapt when implementing Word256
               -- ,Word128 . (`mod` 2^128) . abs <$> arbitrary
               ,Word128 <$> arbitrary -- TODO this should be fine?
               ,Word32 <$> arbitrary
               ,Word64 <$> arbitrary
               ,ByteStr32 . BS.pack <$> (vector 32)
               ,AAddress <$> genAddress
               ,CAddress <$> genCAddress
               ]

genPat :: Gen (Pattern ModuleName)
genPat = oneof [return $ PVar
               ,PCtor . LocalCTor <$> genName
               ,PCtor <$> liftM2 ImportedCTor genName genModuleName
               ,PLiteral <$> genLit
               ]

genAddress :: Gen AccountAddress
genAddress = AccountAddress . FBS.fromByteString . BS.pack <$> (vector 21)

genCAddress :: Gen ContractAddress
genCAddress = ContractAddress <$> (ContractIndex <$> arbitrary) <*> (ContractSubindex <$> arbitrary)


genExpr :: Gen (Expr ModuleName)
genExpr = sized genExpr'
  where genExpr' n = oneof $ [atoms
                             ,genLambda n
                             ,genTLambda n
                             ,genApp n
                             ,genLet n
                             ,genLetRec n
                             ,genCase n
                             ,genTy n]
        atoms = oneof [Atom . BoundVar <$> genBoundVar
                      ,Atom . LocalDef <$> genName
                      ,Atom <$> liftM2 Imported genName genModuleName
                      ]

        genLambda n | n > 0 = liftM2 Lambda (genType' n) (genExpr' (n `div` 2))
                    | otherwise = liftM2 Lambda (genType' n) (atoms)
        genTLambda n | n > 0 = TLambda <$> (genExpr' (n - 1))
                     | otherwise = TLambda <$> atoms
        genApp n | n > 0 = liftM2 App (genExpr' (n `div` 2)) (genExpr' (n `div` 2))
                 | otherwise = liftM2 App (atoms) (atoms)
        genLet n | n > 0 = liftM2 Let (genExpr' (n `div` 2)) (genExpr' (n `div` 2))
                 | otherwise = liftM2 Let atoms atoms
        genTy n = resize (max 0 (n-1)) $ Type <$> (genType' n)
        genLetRec n | n > 0 = do l <- choose (0,n)
                                 cs <- vectorOf l (do tdom <- (genType' n)
                                                      texp <- genExpr' (n `div` (l+2))
                                                      tcod <- (genType' n)
                                                      return (tdom, texp, tcod))
                                 e <- if n > 0 then genExpr' (n `div` 2) else atoms
                                 return (LetRec cs e)
                    | otherwise = LetRec [] <$> atoms
        genCase n | n > 0 = do l <- choose (1,n)
                               e <- genExpr' (n `div` (l+1))
                               cs <- vectorOf l (do pat <- genPat
                                                    texp <- if n > 0 then genExpr' (n `div` 2) else atoms
                                                    return (pat, texp))
                               return (Case e cs)
                  | otherwise = do e <- atoms
                                   p <- genPat
                                   e' <- atoms
                                   return $ Case e [(p, e')]
        genType' n = resize n $ genType

genConstraintRef :: Gen (ConstraintRef ModuleName)
genConstraintRef = oneof [LocalCR <$> genTyName, liftM2 ImportedCR genTyName genModuleName]

genConstraintImpl :: Gen (ConstraintImpl ModuleName)
genConstraintImpl = sized $ \n -> do
  constraintNameImpl <- genConstraintRef
  ls <- choose (0, n)
  sendersImpl <- replicateM ls $ liftM2 Sender genName genExpr
  lg <- choose (0, n)
  gettersImpl <- replicateM lg $ liftM2 Getter genName genExpr
  return $ ConstraintImpl{..}


genConstraintDecl :: Gen (ConstraintDecl ModuleName)
genConstraintDecl = sized $ \n -> do
  constraintName <- genTyName
  ls <- choose (0, n)
  senders <- vectorOf ls $ liftM2 Sender genName genType
  lg <- choose (0, n)
  getters <- vectorOf lg $ liftM2 Getter genName genType
  return $ ConstraintDecl{..}

genDataCons :: Gen (DataCon ModuleName)
genDataCons = sized $ \n -> do
  dcName <- genName
  l <- choose (0, n)
  dcArity <- vectorOf l genType
  return $ DataCon{..}

genDtVisibility :: Gen DataTyVisibility
genDtVisibility = elements [None, OnlyType, All]

genDataType :: Gen (DataType ModuleName)
genDataType = sized $ \n -> do
  dtName <- genTyName
  dtParams <- arbitrary
  dtVis <- genDtVisibility
  l <- choose (0, n)
  dtCons <- vectorOf l genDataCons
  return $ DataType{..}

genModuleRef :: Gen ModuleRef
genModuleRef = ModuleRef . SHA256.hash . BS.pack <$> vector 32

genImport :: Gen Import
genImport = do
  iModule <- genModuleRef
  iAs <- genModuleName
  return $ Import{..}

genVisibility :: Gen Visibility
genVisibility = elements [Private,Public]

genDefinition :: Gen (Definition ModuleName)
genDefinition = do
  dName <- genName
  dVis <- genVisibility
  dExpr <- genExpr
  return $ Definition{..}

genContract :: Gen (Contract ModuleName)
genContract = sized $ \n -> do
  cName <- genTyName
  cInit <- genExpr
  cReceive <- genExpr
  l <- choose(0, n)
  cInstances <- vectorOf l genConstraintImpl
  return $ Contract{..}

genModule :: Gen Module
genModule = sized $ \n -> do
  lIm <- choose (0, n)
  mImports <- vectorOf lIm genImport
  ldt <- choose (0, n)
  mDataTypes <- vectorOf ldt genDataType
  lcd <- choose (0, n)
  mConstraintDecls <- vectorOf lcd (resize (n `div` (lcd+1)) genConstraintDecl)
  ldefs <- choose (0, n)
  mDefs <- vectorOf ldefs (resize (n `div` (ldefs + 1)) genDefinition)
  lcont <- choose (0, n)
  mContracts <- vectorOf lcont (resize (n `div` (lcont + 1)) genContract)
  mVersion <- arbitrary
  return $ Module{..}
