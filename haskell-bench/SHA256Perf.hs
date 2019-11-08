module PerformanceTests.SHA256Perf where

import Criterion
import Criterion.Main
import Criterion.Types

import Data.ByteString.Char8 as BS
-- import Data.ByteString.Lazy as BSL

import Concordium.Crypto.SHA256

setup :: Int -> IO (BS.ByteString, BS.ByteString, BS.ByteString, BS.ByteString)
setup n = do
  let header = BS.replicate 100 '0'
  let sig = BS.replicate 50 '1'
  let body = BS.replicate n '2'
  let full = header <> sig <> body
  return (header, sig, body, full)

hashAll :: Int -> Benchmark
hashAll n =
  env (setup n) $ \ ~(_header, _sig, _body, full) ->
          bench "all" $ nf (\d -> hashToByteString (hash d)) full


hashCompound :: Int -> Benchmark
hashCompound n =
  env (setup n) $ \ ~(header, sig, body, _full) ->
          bench "compound" $ nf (\(h, s, b) -> hashToByteString (hash (hashToByteString (hash h) <> hashToByteString (hash s) <> hashToByteString (hash b)))) (header, sig, body)


main :: IO ()
main = defaultMainWith (defaultConfig { timeLimit = 15 }) [
  bgroup "n = 100"
  [hashAll 100
  ,hashCompound 100
  ]
  ,bgroup "n = 1000"
  [hashAll 1000
  ,hashCompound 1000
  ]
  ,bgroup "n = 10000"
  [hashAll 10000
  ,hashCompound 10000
  ]
  ,bgroup "n = 100000"
  [hashAll 100000
  ,hashCompound 100000
  ]

  ]
