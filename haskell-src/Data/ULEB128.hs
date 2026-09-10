module Data.ULEB128 (
    encode,
    decode,
) where

import Control.Monad (guard)
import Data.Bits
import qualified Data.ByteString as BS
import Data.Word

encode :: Word64 -> BS.ByteString
encode n = BS.pack (go n)
  where
    go x
        | x < 0x80 = [fromIntegral x]
        | otherwise = fromIntegral (0x80 .|. (x .&. 0x7f)) : go (shiftR x 7)

decode :: BS.ByteString -> Maybe (Word64, BS.ByteString)
decode = go 0 0
  where
    maxWord64 = toInteger (maxBound :: Word64)

    go acc bitOffset input = do
        (byte, rest) <- BS.uncons input
        let chunk = toInteger (byte .&. 0x7f)
            acc' = acc + shiftL chunk bitOffset
        guard (acc' <= maxWord64)
        if testBit byte 7
            then go acc' (bitOffset + 7) rest
            else return (fromInteger acc', rest)
