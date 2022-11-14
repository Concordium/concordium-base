{-# LANGUAGE TemplateHaskell #-}

-- |Template Haskell functions for supporting polymorphism over protocol versions.
module Concordium.Types.ProtocolVersion.TH (onPV, casePV) where

import Language.Haskell.TH.Syntax

import Concordium.Types.ProtocolVersion

-- |Produces a list of the constructors of 'SProtocolVersion'.
protocolVersionConstructors :: Q [Name]
protocolVersionConstructors =
    reify ''SProtocolVersion >>= \case
        TyConI (DataD _ _ _ _ cs _) -> mapM getCon cs
        _ -> f
  where
    f = fail "Could not resolve constructors of SProtocolVersion"
    getCon (GadtC [n] _ _) = return n
    getCon _ = f

-- |Convenience macro for providing a default case in a pattern match on a protocol
-- version.  This must be applied to a (quoted) case-of or lambda-case expression
-- that discriminates on an @SProtocolVersion pv@ value. Any wild-card (i.e. @_@)
-- case will be replaced with specific patterns for each constructor of 'SProtocolVersion'
-- that is not already explicitly matched.
--
-- >    $(onPV [|case protocolVersion @pv of {SP1 -> foo; _ -> bar}|])
--
-- rewrites to:
--
-- >    case protocolVersion @pv of
-- >        SP1 -> foo
-- >        SP2 -> bar
-- >        ... -- each remaining case uses bar
--
-- This is expected to be used when specialized behaviour is required for one or a few
-- particular protocol versions, but default behaviour is available for others.
--
-- Where appropriate, it is recommended to use 'casePV' instead.
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

-- |Convenience macro for code that is uniform across protocol versions, but requires
-- a case match on the protocol version for typechecking. Typically this is due to
-- typeclass resolution.
--
-- >    $(casePV [t| pv |] [| foo |])
--
-- expands to:
--
-- >    case protocolVersion @pv of
-- >        SP1 -> foo
-- >        SP2 -> foo
-- >        ...
--
-- with a case for each constructor of 'SProtocolVersion'.
--
-- A typical use-case would be working with a type family indexed by protocol version, e.g.
--
-- > type family Foo (pv :: ProtocolVersion)
-- > type instance Foo 'P1 = Bool
-- > type instance Foo 'P2 = Int
--
-- Suppose that we want to call 'show' on a value of type @Foo pv@, where @pv@ is a type
-- variable.  The following does not work:
--
-- > showFoo :: (IsProtocolVersion pv) => Foo pv -> String
-- > showFoo = show
--
-- The reason for this is that, while there are instances @Show (Foo 'P1)@ and @Show (Foo 'P2)@,
-- there is no uniform instance @Show (Foo pv)@.  To work out which type class instance @show@
-- should refer to, the compiler needs to know the specific value of @pv@.  Hence, the following
-- solution:
--
-- > showFoo :: forall pv. (IsProtocolVersion pv) => Foo pv -> String
-- > showFoo = $(casePV [t| pv |] [| show |])
casePV :: Q Type -> Q Exp -> Q Exp
casePV pv ce = do
    pcvs <- protocolVersionConstructors
    pvt <- pv
    cee <- ce
    return (CaseE (AppTypeE (VarE 'protocolVersion) pvt) [Match (ConP c []) (NormalB cee) [] | c <- pcvs])
