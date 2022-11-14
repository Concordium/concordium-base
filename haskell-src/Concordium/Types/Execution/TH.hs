{-# LANGUAGE TemplateHaskell #-}

module Concordium.Types.Execution.TH where

import Language.Haskell.TH.Lib
import Language.Haskell.TH.Syntax

import Control.Monad
import GHC.Generics

deriveEqShowGeneric :: DerivClauseQ
deriveEqShowGeneric = derivClause Nothing [conT ''Show, conT ''Eq, conT ''Generic]

-- NB: This only works for types without type parameters at the moment.
-- Given a type with a number of constructors with parameters it derives a new type
-- with the same constructors (prefixed with a chosen string) but without any arguments.
genEnumerationType :: Name -> String -> String -> String -> DecsQ
genEnumerationType name generatedName prefix funName = do
    TyConI dec <- reify name
    case dec of
        DataD _ n _ _ cs _ -> do
            cons <- mapM (fmap (flip normalC [] . deriveCName . fst) . getData) cs
            dataTy <- dataD (cxt []) (mkName generatedName) [] Nothing cons [deriveEqShowGeneric]
            let fName = mkName funName
            var <- newName "x"
            body <- caseE (varE var) <$> forM cs (fmap genMatchClause . getData)
            f <- funD fName [clause [varP var] (normalB body) []]
            sig <- sigD fName (appT (appT arrowT (conT n)) (conT (mkName generatedName)))
            return [dataTy, f, sig]
        _ -> fail $ "Unsupported declaration: " ++ show dec
  where
    getData (NormalC n xs) = return (n, length xs)
    getData (RecC n xs) = return (n, length xs)
    getData c = fail $ "Unsupported constructor type: " ++ show c

    deriveCName origName = mkName (prefix ++ nameBase origName)

    genMatchClause (n, len) = match (conP n (replicate len wildP)) (normalB (conE (deriveCName n))) []
