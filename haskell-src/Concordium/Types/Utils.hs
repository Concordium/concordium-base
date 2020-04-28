module Concordium.Types.Utils where

import Data.Char

-- |Convert the first character of a string to lowercase.
-- (This is used in Template Haskell for generating JSON serialization code.)
firstLower :: String -> String
firstLower [] = []
firstLower (c:cs) = toLower c : cs
