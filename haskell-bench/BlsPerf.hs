module Main where

import Control.Exception

import Criterion
import Criterion.Main
import Criterion.Types

import qualified Data.ByteString.Char8 as BS
import Data.Serialize

import qualified Concordium.Crypto.BlsSignature as Bls

-- | Generate an instance for 'checkProofOfKnowledgeSK':
-- * A challenge of the given length
-- * A BLS public key
-- * A proof of knowledge of a private key belonging to the public key.
setupProofOfKnowledgeSK :: Int -> IO (BS.ByteString, Bls.PublicKey, Bls.Proof)
setupProofOfKnowledgeSK n = do
    secKey <- Bls.generateSecretKey
    let pubKey = Bls.derivePublicKey secKey
    let challenge = BS.replicate n '0'
    proof <- Bls.proveKnowledgeOfSK challenge secKey
    return (challenge, pubKey, proof)

checkProofOfKnowledgeSK :: Int -> Benchmark
checkProofOfKnowledgeSK n =
    env (setupProofOfKnowledgeSK n) $ \ ~(c, pk, p) ->
        bench ("len = " ++ show n) $ nf (\(pubKey, proof) -> assert True $ Bls.checkProofOfKnowledgeSK c proof pubKey) (pk, p)

-- | Generate an instance for 'checkProofOfKnowledgeSKSer':
-- * A challenge of the given length
-- * A serialized BLS public key
-- * A serialized proof of knowledge of a private key belonging to the public key
setupProofOfKnowledgeSKSer :: Int -> IO (BS.ByteString, BS.ByteString, BS.ByteString)
setupProofOfKnowledgeSKSer n = do
    secKey <- Bls.generateSecretKey
    let pubKey = Bls.derivePublicKey secKey
    let challenge = BS.replicate n '0'
    proof <- Bls.proveKnowledgeOfSK challenge secKey
    return (challenge, encode pubKey, encode proof)

checkProofOfKnowledgeSKSer :: Int -> Benchmark
checkProofOfKnowledgeSKSer n =
    env (setupProofOfKnowledgeSKSer n) $ \ ~(c, pk', p') ->
        -- NOTE: We include the decoding in the benchmark because this is usually needed when proofs are checked.
        -- It is a major part of execution time.
        bench ("len = " ++ show n) $
            nf
                ( \(pk, p) ->
                    case (decode pk, decode p) of
                        (Right pubKey, Right proof) -> assert True $ Bls.checkProofOfKnowledgeSK c proof pubKey
                        (Left err, _) -> error $ "Decode error: " ++ err
                        (_, Left err) -> error $ "Decode error: " ++ err
                )
                (pk', p')

main :: IO ()
main =
    defaultMainWith
        (defaultConfig{timeLimit = 15})
        [ bgroup
            "checkProofOfKnowledgeSK"
            [ checkProofOfKnowledgeSK 200
            -- , checkProofOfKnowledgeSK 1000
            -- , checkProofOfKnowledgeSK 10000
            -- , checkProofOfKnowledgeSK 100000
            -- , checkProofOfKnowledgeSK 1000000
            ],
          bgroup
            "checkProofOfKnowledgeSKSer"
            [ checkProofOfKnowledgeSKSer 200
            -- , checkProofOfKnowledgeSKSer 1000
            -- , checkProofOfKnowledgeSKSer 10000
            -- , checkProofOfKnowledgeSKSer 100000
            -- , checkProofOfKnowledgeSKSer 1000000
            ]
        ]
