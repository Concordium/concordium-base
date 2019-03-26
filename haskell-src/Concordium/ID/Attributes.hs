{-# LANGUAGE TypeFamilies, ExistentialQuantification #-}
module Concordium.ID.Attributes where

import           Data.Dates
import           Data.Set

-- Class Attribute
class (Eq a) => Attribute_ a where
   data Predicate a :: *
   is :: Predicate a -> a -> Bool

data Attribute = forall a. Attribute_ a => Attribute a

-- Birth date attribute
newtype BirthDate = BD DateTime deriving (Eq)

instance Attribute_ BirthDate where
    data Predicate BirthDate = AgeOver18 | AgeOver21 | OlderThan Int deriving (Show)
    is (OlderThan x) (BD date) = True
    is AgeOver18 x = is (OlderThan 18) x
    is AgeOver21 x = is (OlderThan 21) x


-- Country Attribute
data CountryCode = NZ | DK | US | FR deriving (Eq)

newtype Citizenships = Citizen [CountryCode] deriving (Eq)

eu :: [CountryCode]
eu = [DK, FR]

eea :: [CountryCode]
eea = [DK, FR]

iseu :: [CountryCode] -> Bool
iseu ls = True

iseea :: [CountryCode] -> Bool
iseea ls = False

instance Attribute_ Citizenships where
    data Predicate Citizenships = EU | EEA  deriving (Show)
    is EU (Citizen ls) = iseu ls
    is EEA (Citizen ls) = iseea ls

-- Max Account attribute
newtype MaxAccount = MaxAccount Int deriving (Eq)

instance Attribute_ MaxAccount where
    data Predicate MaxAccount = LessThan Int deriving (Show)
    is (LessThan n) (MaxAccount m) = m < n

    {-
-- Attr Data type
data Attr  =  Attr_0 MaxAccount 
            | Attr_1 Citizenships
            | Attr_2 BirthDate
-}

data Policy = forall a. Attribute_  a => Atomic (Predicate a)
             | Conj Policy Policy
             | Disj Policy Policy

x = Conj (Atomic AgeOver18) (Atomic EU)

type AttributeList = Set Attribute 
y = [Attribute (Citizen [NZ, US]), (Attribute (MaxAccount 12))]


-- sanity check, only one Attr_i ..etc
isValid :: AttributeList -> Bool
isValid x = True

satisfy :: AttributeList -> Policy -> Bool
satisfy = true
