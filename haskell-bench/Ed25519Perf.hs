module Main where

import Criterion
import Criterion.Main
import Criterion.Types

import qualified Data.ByteString.Char8 as BS

-- import Data.ByteString.Short as BSS
import Data.Serialize

import Control.Exception

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

setupVerifyEnvSer :: Int -> IO (BS.ByteString, BS.ByteString, BS.ByteString)
setupVerifyEnvSer n = do
    (vk, s, doc) <- setupVerifyEnv n
    return (encode vk, encode s, doc)

setupDeserializeVerificationKey :: IO (BS.ByteString)
setupDeserializeVerificationKey = do
    kp <- newKeyPair Ed25519
    return (encode $ correspondingVerifyKey kp)

signN :: Int -> Benchmark
signN n =
    env (setupSignEnv n) $ \ ~(kp, doc) ->
        bench ("len = " ++ show n) $ nf (\x -> let Signature s = sign kp x in s) doc

verifyN :: Int -> Benchmark
verifyN n =
    env (setupVerifyEnv n) $ \ ~(vk, s, doc) ->
        bench ("len = " ++ show n) $ nf (\d -> assert True $ verify vk d s) doc

verifyNSer :: Int -> Benchmark
verifyNSer n =
    env (setupVerifyEnvSer n) $ \ ~(vk', s', doc) ->
        bench ("len = " ++ show n) $
            nf
                ( \(vk, s) ->
                    case (decode vk, decode s) of
                        (Right verKey, Right sig) -> assert True $ verify verKey doc sig
                        (Left err, _) -> error $ "Decode error: " ++ err
                        (_, Left err) -> error $ "Decode error: " ++ err
                )
                (vk', s')

deserializeVerificationKey :: Benchmark
deserializeVerificationKey =
    env (setupDeserializeVerificationKey) $ \encoded ->
        bench ("deserializing key") $
            nf
                ( \bytes ->
                    let VerifyKeyEd25519 k = case decode bytes of
                            Left err -> error $ "Decode error: " ++ err
                            Right key -> key
                    in  k
                )
                encoded

main :: IO ()
main =
    defaultMainWith
        (defaultConfig{timeLimit = 60})
        [ -- bgroup "sign"
          -- [signN 100
          -- ,signN 1000
          -- ,signN 10000
          -- ,signN 100000
          -- ],
          bgroup
            "deserializeVerificationKey"
            [ deserializeVerificationKey
            ],
          bgroup
            "verify"
            [ verifyN 5000
            -- ,verifyN 1000
            -- ,verifyN 10000
            -- ,verifyN 100000
            ],
          bgroup
            "verifySer"
            [ verifyNSer 5000
            -- ,verifyNSer 1000
            -- ,verifyNSer 10000
            -- ,verifyNSer 100000
            ]
        ]
