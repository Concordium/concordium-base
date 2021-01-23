{-# LANGUAGE DerivingStrategies #-}
-- |Types to help with SQL database schemas. These cannot be directly in
-- Concordium.SQL.AccountTransactionIndex due to the staging restriction.
module Concordium.SQL.Helpers where

import Control.Arrow
import Control.Monad
import Data.ByteString
import Data.Proxy
import Data.Serialize
import Database.Persist
import Database.Persist.Postgresql
import qualified Data.Text as T

-- |Wraps a type for persistent storage via a serialization to a 'ByteString'.
newtype ByteStringSerialized a = ByteStringSerialized { unBSS :: a }
    deriving newtype (Serialize, Eq, Ord, Show)

instance Serialize a => PersistField (ByteStringSerialized a) where
  toPersistValue = toPersistValue . encode
  fromPersistValue =
    fromPersistValue >=> left (T.pack) . decode

instance Serialize a => PersistFieldSql (ByteStringSerialized a) where
  sqlType _ = sqlType (Proxy :: Proxy ByteString)
