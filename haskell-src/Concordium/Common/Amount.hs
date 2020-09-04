{-# LANGUAGE DerivingStrategies #-}
module Concordium.Common.Amount where

import qualified Data.Serialize as S
import Data.Word
import Data.Aeson
import Data.Hashable
import qualified Data.Text as Text
import Data.Char

import qualified Text.ParserCombinators.ReadP as RP


-- |Type representing the amount unit which is defined as the smallest
-- meaningful amount of GTU. This unit is 10^-6 GTU and denoted microGTU.
type AmountUnit = Word64
newtype Amount = Amount { _amount :: AmountUnit }
    deriving newtype (Show, Read, Eq, Ord, Enum, Bounded, Num, Integral, Real, Hashable)

instance S.Serialize Amount where
  {-# INLINE get #-}
  get = Amount <$> S.getWord64be
  {-# INLINE put #-}
  put (Amount v) = S.putWord64be v

instance FromJSON Amount where
  parseJSON = fmap Amount . withEmbeddedJSON "Amount" parseJSON

instance ToJSON Amount where
  toJSON = String . Text.pack . show . _amount

-- |Converts an amount to GTU decimal representation.
amountToString :: Amount -> String
amountToString (Amount amount) =
  let
    high = show $ amount `div` 1000000
    low = show $ amount `mod` 1000000
    pad = replicate (6 - length low) '0'
  in
    high ++ "." ++ pad ++ low

-- |Parse an amount from GTU decimal representation.
amountFromString :: String -> Maybe Amount
amountFromString s =
    if length s == 0 || length parsed /= 1
    then Nothing
    else Just $ Amount (fst (head parsed))
  where parsed = RP.readP_to_S amountParser s

-- |Parse a Word64 as a decimal number with scale 10^6
-- i.e. between 0 and 18446744073709.551615
amountParser :: RP.ReadP Word64
amountParser = decimalAmount RP.<++ noDecimalAmount
  where
    fitInWord64 v = v <= (toInteger (maxBound :: Word64))
    noDecimalAmount = do
      (_, num) <- readNumber True
      let value = num * 1000000
      if fitInWord64 value then return $ fromIntegral value
      else RP.pfail
    decimalAmount = do
      (sLen, num) <- readNumber False
      (mLen, mantissa) <- readNumber True
      if sLen > 0 && mLen > 0 && mLen <= 6 then do
        let value = num * 1000000 + (mantissa * 10 ^ (6-mLen))
        if fitInWord64 value then return $ fromIntegral value
        else RP.pfail
      else RP.pfail

-- |Reads a number by reading digits, returning (#digits,number)
readNumber :: Bool -> RP.ReadP (Int, Integer)
readNumber eof = do
    digits <- RP.manyTill readDigit terminal
    return $ (length digits, (foldl (\acc v -> (acc*10+v)) 0 digits))
  where terminal = if eof then RP.eof
                   else (RP.char '.' >> return ())
        readDigit = do
          c <- RP.get
          if isDigit c then return $ toInteger (digitToInt c)
          else RP.pfail

