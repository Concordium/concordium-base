{-# LANGUAGE DerivingVia #-}
module Data.Base58Encoding where

import qualified Data.Vector.Storable as Vec
import qualified Concordium.Crypto.SHA256 as H
import qualified Data.ByteString as BS
import Data.Bits
import Data.Word
import Data.Maybe
import Data.Aeson
import qualified Data.Text.Encoding as Text

codeTable :: Vec.Vector Word8
codeTable = Vec.fromListN 58 (map (fromIntegral . fromEnum) "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

decodeTable :: Vec.Vector Word8
decodeTable = Vec.fromListN 256 (map (\x -> fromIntegral (fromMaybe 255 (Vec.elemIndex x codeTable))) [0..255])

-- |A bytestring wrapper that contains a valid base58 string, i.e., each byte in
-- the bytestring is a valid base58 character.
newtype Base58String = Base58String {raw :: BS.ByteString }
    deriving Show via BS.ByteString
    deriving Eq via BS.ByteString

instance FromJSON Base58String where
  parseJSON = withText "Base58 string" $ \t ->
    let bs = Text.encodeUtf8 t
    in if checkValidBase58 bs then return (Base58String bs)
       else fail "Not a valid base 58 string."

instance ToJSON Base58String where
  -- Decode here should be safe because of the invariant maintained by Base58String type.
  toJSON (Base58String bs) = String (Text.decodeUtf8 bs)

-- |Encode a non-negative integer. This function will fail if given a negative
-- integer.
encodeBytes :: BS.ByteString -> Base58String
encodeBytes input =
  if leadingzeros == BS.length input then Base58String (BS.replicate leadingzeros (Vec.unsafeIndex codeTable 0))
  else Base58String (BS.replicate leadingzeros (Vec.unsafeIndex codeTable 0) <> encodePositiveInteger' i)
  where (i, leadzero) = BS.foldl' (\(acc, nn) x ->
                                     if x == 0 then
                                       (acc `shiftL` 8, if nn >= 0 then nn+1 else nn)
                                     else (acc `shiftL` 8 + toInteger x, if nn < 0 then nn else (-nn-1))) (0, 0) input
        leadingzeros = if leadzero >= 0 then leadzero else (-leadzero - 1)

encodePositiveInteger' :: Integer -> BS.ByteString
encodePositiveInteger' i
    | i < 0 = error "Input must be positive integer."
    | otherwise = BS.pack (go i [])
      where go x acc
                | x == 0 = if null acc then [Vec.unsafeIndex codeTable 0]
                           else acc
                | otherwise =
                  let (d, m) = divMod x 58
                  in go d (Vec.unsafeIndex codeTable (fromIntegral m) : acc)

encodePositiveInteger :: Integer -> Base58String
encodePositiveInteger = Base58String . encodePositiveInteger'

decodePositiveInteger :: Base58String -> Integer
decodePositiveInteger (Base58String b) =
  case decodePositiveInteger' b of
    Nothing -> error "Precondition violated, not a valid base58 string."
    Just x -> x

decodePositiveInteger' :: BS.ByteString -> Maybe Integer
decodePositiveInteger' b = go 0 0
  where len = BS.length b
        go acc i | i == len = Just acc
                 | otherwise =
                   let r = Vec.unsafeIndex decodeTable (fromIntegral (BS.index b i))
                   in if r < 58 then go (58 * acc + toInteger r) (i+1)
                      else Nothing

decodeBytes' :: BS.ByteString -> Maybe BS.ByteString
decodeBytes' b =
  if BS.null rest then Just (BS.replicate (BS.length ones) 0)
  else 
    let start = BS.replicate (BS.length ones) 0
    in do
      restString <- decodePositiveInteger' rest
      return $! start <> BS.pack (go [] restString)

  where (ones, rest) = BS.span (== Vec.unsafeIndex codeTable 0) b
        go acc 0 = acc
        go acc n =
          let (d, m) = divMod n 256
          in go (fromIntegral m:acc) d

decodeBytes :: Base58String -> BS.ByteString
decodeBytes (Base58String b) = do
  case decodeBytes' b of
    Nothing -> error "Precondition violated, not a valid base58 string."
    Just x -> x

base58CheckEncode :: BS.ByteString -> Base58String
base58CheckEncode input = encodeBytes (input <> BS.take 4 hashedTwice)
  where hashedTwice = H.hashToByteString (H.hash (H.hashToByteString (H.hash input)))

-- |Check whether a base58 check string is valid and return the payload bytes.
base58CheckDecode :: Base58String -> Maybe BS.ByteString
base58CheckDecode input =
  let decoded = decodeBytes input
      len = BS.length decoded
  in if len < 4 then Nothing
     else let (payload, check) = BS.splitAt (len - 4) decoded
              hashedTwice = H.hashToByteString (H.hash (H.hashToByteString (H.hash payload)))
          in if check == BS.take 4 hashedTwice then Just payload
             else Nothing

checkValidBase58 :: BS.ByteString -> Bool
checkValidBase58 bs = BS.all (\x -> Vec.unsafeIndex decodeTable (fromIntegral x) < 58) bs
