module Main where

import Control.Exception
import Data.Maybe

import Criterion
import Criterion.Main
import Criterion.Types

import qualified Data.ByteString.Char8 as BS
import Data.Serialize

import qualified Concordium.Crypto.Proofs as Proofs
import qualified Concordium.Crypto.VRF as VRF

-- * Ed25519 Dlog proof checks

-- $note
-- NOTE:
-- 'Proof.checkDlog25519ProofVRF', 'Proof.checkDlog25519ProofBlock' and 'Proof.checkDlog25519ProofSig' are
-- essentially the same and thus benchmarking the first serves as a representation of all three.

-- | Generate an instance for 'checkProofVRF':
-- * A challenge of the given length
-- * A VRF public key
-- * The proof of the challenge
setupProofVRF :: Int -> IO (BS.ByteString, VRF.PublicKey, Proofs.Dlog25519Proof)
setupProofVRF n = do
    kp <- VRF.newKeyPair
    let challenge = BS.replicate n '0'
    proof <- fromJust <$> Proofs.proveDlog25519VRF challenge kp
    return (challenge, VRF.publicKey kp, proof)

checkProofVRF :: Int -> Benchmark
checkProofVRF n =
    env (setupProofVRF n) $ \ ~(c, pk, p) ->
        bench ("len = " ++ show n) $ nf (\(pubKey, proof) -> assert True $ Proofs.checkDlog25519ProofVRF c pubKey proof) (pk, p)

-- | Generate an instance for 'checkProofVRFSer':
-- * A challenge of the given length
-- * A serialized VRF public key
-- * The serialized proof of the challenge
setupProofVRFSer :: Int -> IO (BS.ByteString, BS.ByteString, BS.ByteString)
setupProofVRFSer n = do
    kp <- VRF.newKeyPair
    let challenge = BS.replicate n '0'
    proof <- fromJust <$> Proofs.proveDlog25519VRF challenge kp
    return (challenge, encode $ VRF.publicKey kp, encode proof)

checkProofVRFSer :: Int -> Benchmark
checkProofVRFSer n =
    env (setupProofVRFSer n) $ \ ~(c, pk', p') ->
        -- NOTE: We include the decoding in the benchmark because this is usually needed when proofs are checked.
        -- It should not result in a big difference of execution time.
        bench ("len = " ++ show n) $
            nf
                ( \(pk, p) ->
                    case (decode pk, decode p) of
                        (Right pubKey, Right proof) -> assert True $ Proofs.checkDlog25519ProofVRF c pubKey proof
                        (Left err, _) -> error $ "Decode error: " ++ err
                        (_, Left err) -> error $ "Decode error: " ++ err
                )
                (pk', p')

main :: IO ()
main =
    defaultMainWith
        (defaultConfig{timeLimit = 15})
        [ bgroup
            "checkProofVRF"
            [ checkProofVRF 100,
              checkProofVRF 1000,
              checkProofVRF 10000,
              checkProofVRF 100000,
              checkProofVRF 1000000
            ],
          bgroup
            "checkProofVRFSer"
            [ checkProofVRFSer 100,
              checkProofVRFSer 1000,
              checkProofVRFSer 10000,
              checkProofVRFSer 100000,
              checkProofVRFSer 1000000
            ]
        ]
