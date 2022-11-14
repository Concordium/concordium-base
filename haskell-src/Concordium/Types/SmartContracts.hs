{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}

-- |Basic types related to smart contracts.
module Concordium.Types.SmartContracts where

import Data.Aeson
import Data.Bits
import Data.Hashable
import Data.Proxy
import qualified Data.Serialize as S
import Data.Word
import Database.Persist.Class
import Database.Persist.Sql
import GHC.Generics

newtype ContractIndex = ContractIndex {_contractIndex :: Word64}
    deriving newtype (Eq, Ord, Num, Enum, Bounded, Real, Hashable, Show, Bits, Integral, PersistField)

instance PersistFieldSql ContractIndex where
    sqlType _ = sqlType (Proxy :: Proxy Word64)

instance S.Serialize ContractIndex where
    get = ContractIndex <$> S.getWord64be
    put (ContractIndex i) = S.putWord64be i

newtype ContractSubindex = ContractSubindex {_contractSubindex :: Word64}
    deriving newtype (Eq, Ord, Num, Enum, Bounded, Real, Hashable, Show, Integral, PersistField)

instance PersistFieldSql ContractSubindex where
    sqlType _ = sqlType (Proxy :: Proxy Word64)

instance S.Serialize ContractSubindex where
    get = ContractSubindex <$> S.getWord64be
    put (ContractSubindex i) = S.putWord64be i

data ContractAddress = ContractAddress
    { contractIndex :: !ContractIndex,
      contractSubindex :: !ContractSubindex
    }
    deriving (Eq, Ord, Generic)

instance FromJSON ContractAddress where
    parseJSON = withObject "ContractAddress" $ \v -> do
        i <- v .: "index"
        j <- v .: "subindex"
        return $ ContractAddress (fromIntegral (i :: Word64)) (fromIntegral (j :: Word64))

instance ToJSON ContractAddress where
    toJSON (ContractAddress i j) =
        object ["index" .= (fromIntegral i :: Word64), "subindex" .= (fromIntegral j :: Word64)]
    toEncoding (ContractAddress i j) =
        pairs ("index" .= (fromIntegral i :: Word64) <> "subindex" .= (fromIntegral j :: Word64))

instance Hashable ContractAddress

instance Show ContractAddress where
    show (ContractAddress i v) = "<" ++ show i ++ ", " ++ show v ++ ">"

instance S.Serialize ContractAddress where
    get = ContractAddress <$> S.get <*> S.get
    put (ContractAddress i v) = S.put i <> S.put v
