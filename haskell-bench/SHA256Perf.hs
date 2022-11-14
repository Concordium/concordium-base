module Main where

import Data.Functor

import Criterion
import Criterion.Main
import Criterion.Types

import qualified Data.ByteString.Char8 as BS

-- import Data.ByteString.Lazy as BSL

import Concordium.Crypto.SHA256

setupCompound :: Int -> IO (BS.ByteString, BS.ByteString, BS.ByteString, BS.ByteString)
setupCompound n = do
    -- current header size (see Concordium.Types.Transactions.transactionHeaderSize)
    let header = BS.replicate 60 '0'
    let sig = BS.replicate 50 '1'
    let body = BS.replicate n '2'
    let full = header <> sig <> body
    return (header, sig, body, full)

setupSimple :: Int -> IO BS.ByteString
setupSimple n = return $ BS.replicate n '0'

-- | Benchmark hashing of n bytes.
hashSimple :: Int -> Benchmark
hashSimple n =
    env (setupSimple n) $ \testString ->
        bench ("n = " ++ show n) $ nf (\s -> hashToByteString (hash s)) testString

-- | Benchmark hashing of a transaction with n bytes payload size, 60 byte header size
-- and 50 byte signature size by first hashing each of the three parts separately and then
-- hashing the concatenated hashes.
hashCompound :: Int -> Benchmark
hashCompound n =
    env (setupCompound n) $ \ ~(header, sig, body, _full) ->
        bench "compound" $ nf (\(h, s, b) -> hashToByteString (hash (hashToByteString (hash h) <> hashToByteString (hash s) <> hashToByteString (hash b)))) (header, sig, body)

-- | Like 'hashSimple', but for a byte string with the length resulting from concatenating the three
-- parts from 'hashCompound' (payload size n). This is to be able to compare the two ways of hashing.
hashAll :: Int -> Benchmark
hashAll n =
    env (setupCompound n) $ \ ~(_header, _sig, _body, full) ->
        bench "all" $ nf (\d -> hashToByteString (hash d)) full

main :: IO ()
main = do
    let sizesSimple = [0] -- ,500..10000]
    let sizesCompound = map ((10 ^) :: Int -> Int) [2, 3, 4, 5]
    defaultMainWith (defaultConfig{timeLimit = 15}) $
        [ bgroup "hashSimple" $
            map hashSimple sizesSimple
        ]
            ++ ( sizesCompound
                    <&> \n -> bgroup ("n = " ++ show n) [hashAll n, hashCompound n]
               )
