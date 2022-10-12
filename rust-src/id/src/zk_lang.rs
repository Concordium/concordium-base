//! Definitions related to the language of ZK statements

/// Attribures are human-readable labels for commitments to attribute values
/// The attributes will be mapped to corresponding commitments and secret data
//  Note: not complete, will be determined later 
enum Attribute {
    Age,
    Name,
    Nationality
}

type Country = String;

/// Human-readable representation of constants 
/// Eventually mapped to elements of the BLS field
enum Constant {
    Int(u64),
    Country(String)
}

/// Term is either an attribute or a constant
enum Term{
   Var(Attribute),
   Const(Constant)
}

/// Atomic Σ-protocol statements
enum SigmaAtom {
   Eq(Term, Attribute),
   NotEq(Term, Attribute)
}

/// Atomic bulletproof statements
enum BpAtom {
   Leq(Attribute, Constant),
   Geq(Attribute, Constant),
   In(Attribute, Vec<Constant>),
   NotIn(Attribute, Vec<Constant>)
}

/// All atomic statements
enum Atom {
   SAtom(SigmaAtom),
   BPAtom(BpAtom)
 }
 
/// Composite statements
enum ZkStatement{
   Atom(Atom),
   And(Vec<Atom>)
}