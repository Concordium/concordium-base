{-# LANGUAGE GeneralizedNewtypeDeriving, RecordWildCards, OverloadedStrings, LambdaCase #-}
{-# LANGUAGE TypeFamilies, ExistentialQuantification, FlexibleContexts, DeriveGeneric, DerivingVia, DeriveDataTypeable #-}
module Concordium.Common.Version where

import Data.Word
import Data.Bits
import Data.Serialize as S
import Data.Hashable
import Data.Aeson hiding (encode, decode)
import Control.Monad



-- |Constants
__versionBlock :: Version
__versionBlock = Version 0

__versionTransaction :: Version
__versionTransaction = Version 0

__versionGenesisData :: Version
__versionGenesisData = Version 0

__versionGenesisParams :: Version
__versionGenesisParams = Version 0

__versionCredential :: Version
__versionCredential = Version 0



-- |Data structure version
newtype Version = Version Word32
    deriving (Eq, Ord, Hashable)
    deriving Show via Word32
    deriving (FromJSON, ToJSON) via Word32

instance Serialize Version where
  put (Version v) = mapM_ S.putWord8 (encode7 v)
    where
      encode7 :: Word32 -> [Word8]
      encode7 n = let (x:xs) = go n
                  in reverse (x:map (`setBit` 7) xs)
        where go x =
                if x == 0 then [0]
                else let (d, m) =  x `divMod` 128
                    in if d == 0 then [fromIntegral m]
                        else fromIntegral m : go d
  get = decode7 0 5
    where
      decode7 :: Word32 -> Integer -> Get Version
      decode7 acc left = do
          unless (left > 0) $ fail "Invalid version number"
          byte <- S.getWord8
          if testBit byte 7
            then decode7 (128 * acc + fromIntegral (clearBit byte 7)) (left-1)
            else return (Version (128 * acc + fromIntegral byte))



-- |Versioned data structure
data Versioned a = Versioned {
  -- |Version of the data
  vVersion :: Version,
  -- |The data structure
  vValue :: a
} deriving(Eq, Show)

instance (Serialize a) => Serialize (Versioned a) where
  put Versioned {..} =
    put vVersion <> put vValue
  get = Versioned <$> get <*> get

instance (ToJSON a) => ToJSON (Versioned a) where
  toJSON (Versioned {..}) = object [
    "v" .= vVersion,
    "value" .= vValue
    ]

instance FromJSON a => FromJSON (Versioned a) where
  parseJSON = withObject "Versioned" $ \obj -> do
    vVersion <- obj .: "v"
    vValue <- obj .: "value"
    return Versioned {..}