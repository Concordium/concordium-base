{-# LANGUAGE TypeFamilies, FlexibleContexts, ExistentialQuantification, MultiParamTypeClasses,  DeriveGeneric, FlexibleInstances #-}

module Concordium.ID.Attributes where


import           Data.Time
import           Data.Set
import           GHC.Generics
import           Data.Serialize


class (Eq a) => Attribute_ a where
   data Predicate a :: *
   is :: Predicate a -> a -> Bool

data Attribute = forall a. Attribute_ a => Attribute a

-- Birth date attribute
newtype BirthDate = BD Day deriving (Eq)

instance Attribute_ BirthDate where
    data Predicate BirthDate = AgeOver18 | AgeOver21 | OlderThan Int deriving (Show, Generic)
    is (OlderThan x) (BD date) = True
    is AgeOver18 x = is (OlderThan 18) x
    is AgeOver21 x = is (OlderThan 21) x

instance Serialize (Predicate BirthDate) where

-- Country Attribute
data CountryCode = NZ | DK | US | FR deriving (Eq, Generic)

instance Serialize CountryCode where

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
    data Predicate Citizenships = EU | EEA  deriving (Show, Generic)
    is EU (Citizen ls) = iseu ls
    is EEA (Citizen ls) = iseea ls

instance Serialize (Predicate Citizenships) where 


-- Max Account attribute
newtype MaxAccount = MaxAccount Int deriving (Eq)

instance Attribute_ MaxAccount where
    data Predicate MaxAccount = LessThan Int deriving (Show, Generic)
    is (LessThan n) (MaxAccount m) = m < n


instance Serialize (Predicate MaxAccount) where 



data Policy = AtomicBD (Predicate BirthDate) | AtomicMaxAccount (Predicate MaxAccount) | AtomicCitizenship (Predicate Citizenships)
              | Conj Policy Policy  | Disj Policy Policy
              deriving (Generic)

instance Serialize Policy where





type AttributeList = Set Attribute 
y = [Attribute (Citizen [NZ, US]), (Attribute (MaxAccount 12))]


-- sanity check, only one Attr_i ..etc
isValid :: AttributeList -> Bool
isValid x = True

satisfy :: AttributeList -> Policy -> Bool
satisfy x y = True
