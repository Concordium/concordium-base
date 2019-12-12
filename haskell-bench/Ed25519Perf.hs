module Main where

import Criterion
import Criterion.Main
import Criterion.Types

import qualified Data.ByteString.Char8 as BS
-- import Data.ByteString.Short as BSS

import Concordium.Crypto.SignatureScheme
-- import Concordium.Crypto.Ed25519Signature as S

-- setupEnv :: Int -> IO (SignKey, VerifyKey, ByteString)
setupSignEnv :: Int -> IO (KeyPair, BS.ByteString)
setupSignEnv n = do
  let doc = BS.replicate n '0'
  kp <- newKeyPair Ed25519
  return (kp, doc)

setupVerifyEnv :: Int -> IO (VerifyKey, Signature, BS.ByteString)
setupVerifyEnv n = do
  let doc = BS.replicate n '8'
  kp <- newKeyPair Ed25519
  let s = sign kp doc
  return (correspondingVerifyKey kp, s, doc)

signN :: Int -> Benchmark
signN n =
    env (setupSignEnv n) $ \ ~(kp, doc) ->
          bench ("len = " ++ show n) $ nf (\x -> let Signature s = sign kp x in s) doc


verifyN :: Int -> Benchmark
verifyN n =
  env (setupVerifyEnv n) $ \ ~(vk, s, doc) ->
          bench ("len = " ++ show n) $ nf (\d -> verify vk d s) doc

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
