{-# LANGUAGE TemplateHaskell #-}

module Concordium.Types.ProtocolVersion.TH (onPV, casePV) where

import Language.Haskell.TH.Syntax

import Concordium.Types.ProtocolVersion

protocolVersionConstructors :: Q [Name]
protocolVersionConstructors =
    reify ''SProtocolVersion >>= \case
        TyConI (DataD _ _ _ _ cs _) -> mapM getCon cs
        _ -> f
  where
    f = fail "Could not resolve constructors of SProtocolVersion"
    getCon (GadtC [n] _ _) = return n
    getCon _ = f

onPV :: Q Exp -> Q Exp
onPV ce = do
    pvcs <- protocolVersionConstructors
    let fillPats _ [] = return []
        fillPats cs (m@(Match (ConP n _) _ _) : ms) = (m :) <$> fillPats (filter (/= n) cs) ms
        fillPats cs ((Match WildP b d) : ms) = return $ [Match (ConP c []) b d | c <- cs] ++ ms
        fillPats _ _ = fail "Unable to analyze pattern"
    ce >>= \case
        CaseE ex pats -> CaseE ex <$> fillPats pvcs pats
        LamCaseE pats -> LamCaseE <$> fillPats pvcs pats
        _ -> fail "Expected a case or \\case expression"

casePV :: Q Type -> Q Exp -> Q Exp
casePV pv ce = do
    pcvs <- protocolVersionConstructors
    pvt <- pv
    cee <- ce
    return (CaseE (AppTypeE (VarE 'protocolVersion) pvt) [Match (ConP c []) (NormalB cee) [] | c <- pcvs])
