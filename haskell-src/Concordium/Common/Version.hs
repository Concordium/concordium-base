{-# LANGUAGE GeneralizedNewtypeDeriving, RecordWildCards, OverloadedStrings #-}
module Concordium.Common.Version where

import Data.Word
import Data.Bits
import qualified Data.Serialize as S
import qualified Data.Aeson as AE
import Data.Aeson ((.:), (.=))
import Data.Hashable
import Control.Monad



-- |Constants
versionBlock :: Version
versionBlock = Version 0

versionTransaction :: Version
versionTransaction = Version 0

versionGenesisData :: Version
versionGenesisData = Version 0

versionGenesisParams :: Version
versionGenesisParams = Version 0

versionCredential :: Version
versionCredential = Version 0

versionFinalizationRecord :: Version
versionFinalizationRecord = Version 0



-- |Version of a data structure. Binary coded as a variable integer represented by
-- bytes, where MSB=1 indicates more bytes follow, and the 7 lower bits in a byte
-- is Big Endian data bits for the value. A version number is bounded by u32 max.
newtype Version = Version Word32
    deriving (Eq, Ord, Hashable, Show, AE.FromJSON, AE.ToJSON)

instance S.Serialize Version where
  put (Version v) = mapM_ S.putWord8 (encode7 v)
    where
      encode7 :: Word32 -> [Word8]
      encode7 n = let (x:xs) = go n
                  in reverse (x:map (`setBit` 7) xs)
        where go x = let (d, m) =  x `quotRem` 128
                     in if d == 0 then [fromIntegral m]
                        else fromIntegral m : go d
  get = decode7 0 5
    where
      decode7 :: Word64 -> Word8 -> S.Get Version
      decode7 acc left = do
          unless (left > 0) $ fail "Version number byte overflow"
          byte <- S.getWord8
          if testBit byte 7
            then decode7 (128 * acc + fromIntegral (clearBit byte 7)) (left-1)
            else
              let
                value = 128 * acc + fromIntegral byte
              in do
                unless (value <= 4294967295) $ fail "Version number value overflow"
                return (Version (fromIntegral value))



-- |Versioned data structure
data Versioned a = Versioned {
  -- |Version of the data
  vVersion :: !Version,
  -- |The data structure
  vValue :: !a
} deriving(Eq, Show)

instance (S.Serialize a) => S.Serialize (Versioned a) where
  put Versioned {..} =
    S.put vVersion <> S.put vValue
  get = Versioned <$> S.get <*> S.get

instance (AE.ToJSON a) => AE.ToJSON (Versioned a) where
  toJSON Versioned{..} = AE.object [
    "v" .= vVersion,
    "value" .= vValue
    ]

instance AE.FromJSON a => AE.FromJSON (Versioned a) where
  parseJSON = AE.withObject "Versioned" $ \obj -> do
    vVersion <- obj .: "v"
    vValue <- obj .: "value"
    return Versioned {..}