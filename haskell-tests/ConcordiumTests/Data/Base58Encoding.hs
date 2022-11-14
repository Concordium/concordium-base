{-# LANGUAGE OverloadedStrings #-}

module ConcordiumTests.Data.Base58Encoding where

import Data.Aeson
import Data.Base58Encoding
import qualified Data.ByteString as BS
import Test.Hspec
import Test.QuickCheck

testEncodeInteger :: Property
testEncodeInteger = property $ ck
  where
    ck :: Integer -> Property
    ck k =
        let i = abs k
        in  case decodePositiveInteger' (raw (encodePositiveInteger i)) of
                Just j -> i === j
                Nothing -> counterexample (show i) False

testEncodeBytes :: Property
testEncodeBytes = forAll genBS ck
  where
    ck :: BS.ByteString -> Property
    ck bs = case decodeBytes' (raw (encodeBytes bs)) of
        Just bs' -> bs === bs'
        Nothing -> counterexample (show bs) False

testEncodeCheck :: Property
testEncodeCheck = forAll genBS ck
  where
    ck :: BS.ByteString -> Property
    ck bs = case base58CheckDecode (base58CheckEncode bs) of
        Just bs' -> bs === bs'
        Nothing -> counterexample (show bs) False

testJSON :: Property
testJSON = forAll genB58 ck
  where
    ck :: Base58String -> Property
    ck b58 = case decode (encode b58) of
        Nothing -> counterexample (show b58) False
        Just x -> x === b58

genBS :: Gen BS.ByteString
genBS = sized $ \n -> do
    l <- choose (0, n)
    BS.pack <$> vector l

genB58 :: Gen Base58String
genB58 = sized $ \n -> do
    l <- choose (0, n)
    encodeBytes . BS.pack <$> vector l

tests :: Spec
tests = describe "Concordium.Data.Base58Encoding" $ do
    it "integer serialization" $ withMaxSuccess 100000 $ testEncodeInteger
    it "bytes serialization" $ withMaxSuccess 100000 $ testEncodeBytes
    it "base 58 check bytes serialization" $ withMaxSuccess 100000 $ testEncodeCheck
    it "JSON encoding" $ withMaxSuccess 100000 $ testJSON
