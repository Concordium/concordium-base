{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Concordium.Common.Version where

import Control.Monad
import Data.Aeson ((.:), (.=))
import qualified Data.Aeson as AE
import Data.Bits
import Data.Hashable
import qualified Data.Serialize as S
import Data.Word

-- |Version of a data structure. Binary coded as a variable integer represented by
-- bytes, where MSB=1 indicates more bytes follow, and the 7 lower bits in a byte
-- is Big Endian data bits for the value. A version number can be at most 2^32-1.
newtype Version = Version Word32
    deriving newtype (Eq, Ord, Num, Enum, Integral, Real, Hashable, Show, AE.FromJSON, AE.ToJSON, Bounded)

instance S.Serialize Version where
    put (Version v) = mapM_ S.putWord8 (encode7 v)
      where
        encode7 :: Word32 -> [Word8]
        encode7 n =
            let (x : xs) = go n
            in  reverse (x : map (`setBit` 7) xs)
          where
            go x =
                let (d, m) = x `quotRem` 128
                in  if d == 0
                        then [fromIntegral m]
                        else fromIntegral m : go d
    get = decode7 0 5
      where
        decode7 :: Word64 -> Word8 -> S.Get Version
        decode7 acc left = do
            unless (left > 0) $ fail "Version number byte overflow"
            byte <- S.getWord8
            if testBit byte 7
                then decode7 (128 * acc + fromIntegral (clearBit byte 7)) (left - 1)
                else do
                    let value = 128 * acc + fromIntegral byte
                    unless (value <= fromIntegral (maxBound :: Version)) $ fail "Version number value overflow"
                    return $ Version (fromIntegral value)

-- |Aliases for get and put methods that fix the type. This makes them more
-- convenient to use in some cases since one does not have to provide type
-- annotations.
getVersion :: S.Get Version
getVersion = S.get

putVersion :: Version -> S.Put
putVersion = S.put

-- |Versioned data structure
data Versioned a = Versioned
    { -- |Version of the data
      vVersion :: !Version,
      -- |The data structure
      vValue :: !a
    }
    deriving (Eq, Show)

instance (S.Serialize a) => S.Serialize (Versioned a) where
    put Versioned{..} =
        S.put vVersion <> S.put vValue
    get = Versioned <$> S.get <*> S.get

instance (AE.ToJSON a) => AE.ToJSON (Versioned a) where
    toJSON Versioned{..} =
        AE.object
            [ "v" .= vVersion,
              "value" .= vValue
            ]

instance AE.FromJSON a => AE.FromJSON (Versioned a) where
    parseJSON = AE.withObject "Versioned" $ \obj -> do
        vVersion <- obj .: "v"
        vValue <- obj .: "value"
        return Versioned{..}
