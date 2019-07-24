{-# LANGUAGE ScopedTypeVariables #-}
module PerformanceTests.VerifyCredentialPerf where

import Criterion
import Criterion.Main
import Criterion.Types

import qualified Data.ByteString.Char8 as BS

import Concordium.Crypto.FFIDataTypes
import Concordium.ID.Types
import Concordium.ID.Account

import Data.Serialize

filePath :: FilePath
filePath = "testdata/cdi-example.bin"

type Keys = (ElgamalGen, PedersenKey, ElgamalGen, AnonymityRevokerPublicKey, IdentityProviderPublicKey)

getData :: Get Keys
getData = do
  dlogBase <- get
  cmmKey <- get
  arGen <- get
  arPubKey <- get
  ipVerifyKey <- get
  return (dlogBase, cmmKey, arGen, arPubKey, ipVerifyKey)

readData :: BS.ByteString -> Either String (Keys, BS.ByteString)
readData bs = loop (runGetPartial getData bs)
  where loop (Fail err _ ) = Left err
        loop (Partial k) = loop (k BS.empty)
        loop (Done r rest) = Right (r, rest)

testVerify ::
  Keys
  -> CredentialDeploymentInformationBytes
  -> Bool
testVerify (a, b, c, d, e) bs = verifyCredential a b e c d bs

test :: BS.ByteString -> Either String Bool
test bs = case readData bs of
            Left err -> Left err
            Right (tuple, rest) -> Right (testVerify tuple rest)

setup :: IO (Keys, BS.ByteString)
setup = do
  bs <- BS.readFile filePath
  case readData bs of
    Left err -> error err
    Right d -> return d

verify :: Benchmark
verify =
    env setup $ \ ~(keys, cdi) ->
          bench "Verify bench" $ nf (\c -> testVerify keys c) cdi

main :: IO ()
main = defaultMainWith (defaultConfig { timeLimit = 15 }) [
  verify
  ]
