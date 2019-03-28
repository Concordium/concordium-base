{-# LANGUAGE TypeFamilies, FlexibleContexts, ExistentialQuantification, MultiParamTypeClasses,  DeriveGeneric, FlexibleInstances #-}

module Concordium.ID.Attributes where


import           Data.Time
import           Data.Set
import           GHC.Generics
import           Data.Serialize

-- Class Attribute
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
    get = getBirthDatePredicate
    put = putBirthDatePredicate

putBirthDatePredicate :: Putter (Predicate BirthDate)
putBirthDatePredicate AgeOver18 = put $ ("BD_Over18") 
putBirthDatePredicate AgeOver21 = put $ ("BD_Over21") 
putBirthDatePredicate (OlderThan x) = put $ ("BD_OlderThan"++show x) 

getBirthDatePredicate :: Get (Predicate BirthDate)
getBirthDatePredicate = do ls <- get :: (Get String) 
                           case ls of 
                             ('B':'D':'_':ls') -> case ls' of
                                                    "AgeOver18" -> return AgeOver18
                                                    "AgeOver21" -> return AgeOver21
                                                    _           -> return $ OlderThan $ read (Prelude.drop 9 ls') 
                             _                 -> error "parse error"

putMaxAccountPredicate :: Putter (Predicate MaxAccount)
putMaxAccountPredicate x = put ("MA_" ++ show x)

getMaxAccountPredicate :: Get (Predicate MaxAccount)
getMaxAccountPredicate = do ls <- get :: (Get String)
                            case ls of 
                              ('M':'A':'_': ls') -> return $ LessThan $ read ls'
                              _                  -> error "parse error"

putCitizenshipsPredicate :: Putter (Predicate Citizenships)
putCitizenshipsPredicate EU  =  put ("CT_EU")
putCitizenshipsPredicate EEA  =  put ("CT_EEA")

getCitizenshipsPredicate :: Get (Predicate Citizenships)
getCitizenshipsPredicate = do ls <- get :: (Get String) 
                              case ls of 
                                ('C':'T':'_': ls') -> case ls' of 
                                                        "EU" -> return EU
                                                        "EEA" -> return EEA
                                                        _ -> error "parse error"
                                _ -> error "parse error"


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
    get = getCitizenshipsPredicate
    put = putCitizenshipsPredicate


-- Max Account attribute
newtype MaxAccount = MaxAccount Int deriving (Eq)

instance Attribute_ MaxAccount where
    data Predicate MaxAccount = LessThan Int deriving (Show, Generic)
    is (LessThan n) (MaxAccount m) = m < n


instance Serialize (Predicate MaxAccount) where 
    put = putMaxAccountPredicate
    get  = getMaxAccountPredicate

    {-
data Policy = forall a. Attribute_  a => Atomic (Predicate a)
             | Conj Policy Policy
             | Disj Policy Policy
-}

--data Predicate_ = Atomic (Predicate BirthDate) | Atomic (Predicate Citizenship) 
    {-
instance Serialize Predicate_ where
    put (Atomic AgeOver18)= put "Over18"
    put (Atomic AgeOver21)= put "Over21"
    get = do ls <- get :: (Get String)
             case ls of 
               "AgeOver18" ->  AgeOver18
               _       -> error "ooo"
     -}          
         {-
type Policy =  [Predicate_]
instance Serialize Policy where
    put ls = put ls
    get  = mapM_ get
-}

data Policy = AtomicBD (Predicate BirthDate) | AtomicMaxAccount (Predicate MaxAccount) | AtomicCitizenship (Predicate Citizenships)
              | Conj Policy Policy  | Disj Policy Policy
              deriving (Generic)

instance Serialize Policy where



data At = forall a. (Attribute_ a) => At (Predicate a)

blink :: String -> Predicate BirthDate
blink = undefined
blank :: String -> Predicate Citizenships 
blank = undefined

bla :: String -> At
bla "" = At $ blink "s"
bla _  = At $ blank "r"

--x = Conj (Atomic AgeOver18) (Atomic EU)

type AttributeList = Set Attribute 
y = [Attribute (Citizen [NZ, US]), (Attribute (MaxAccount 12))]


-- sanity check, only one Attr_i ..etc
isValid :: AttributeList -> Bool
isValid x = True

satisfy :: AttributeList -> Policy -> Bool
satisfy x y = True
