module PerformanceTests.Ed25519Perf where

import Criterion
import Criterion.Main
import Criterion.Types

import qualified Data.ByteString.Char8 as BS
import Data.ByteString.Short as BSS

import Concordium.Crypto.SignatureScheme
import Concordium.Crypto.Ed25519Signature as S

-- setupEnv :: Int -> IO (SignKey, VerifyKey, ByteString)
setupSignEnv :: Int -> IO (ShortByteString, ShortByteString, BS.ByteString)
setupSignEnv n = do
  let doc = BS.replicate n '0'
  (KeyPair (SignKey sk) (VerifyKey pk)) <- newKeyPair
  return (sk, pk, doc)

setupVerifyEnv :: Int -> IO (ShortByteString, ShortByteString, BS.ByteString)
setupVerifyEnv n = do
  let doc = BS.replicate n '8'
  kp@(KeyPair _ (VerifyKey pk)) <- newKeyPair
  let Signature s = S.sign kp doc
  return (pk, s, doc)

signN :: Int -> Benchmark
signN n =
    env (setupSignEnv n) $ \ ~(sk, pk, doc) ->
          bench ("len = " ++ show n) $ nf (\x -> let Signature s = S.sign (KeyPair (SignKey sk) (VerifyKey pk)) x in s) doc


verifyN :: Int -> Benchmark
verifyN n =
  env (setupVerifyEnv n) $ \ ~(pk, s, doc) ->
          bench ("len = " ++ show n) $ nf (\d -> S.verify (VerifyKey pk) d (Signature s)) doc

main :: IO ()
main = defaultMainWith (defaultConfig { timeLimit = 15 }) [
  bgroup "sign"
  [signN 100
  ,signN 1000
  ,signN 10000
  ,signN 100000
  ],
  bgroup "verify"
  [verifyN 100
  ,verifyN 1000
  ,verifyN 10000
  ,verifyN 100000
  ]
  ]
