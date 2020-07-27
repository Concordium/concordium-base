{-# LANGUAGE ScopedTypeVariables #-}
module Main where

import Criterion
import Criterion.Main
import Criterion.Types

import qualified Data.ByteString.Char8 as BS

import Concordium.ID.Account
import Concordium.ID.Parameters
import Concordium.ID.IdentityProvider
import Concordium.ID.AnonymityRevoker

import Data.Serialize


filePath :: FilePath
filePath = "testdata/testdata.bin"

type Data = (GlobalContext, IpInfo, [ArInfo], CredentialDeploymentInformationBytes)

readData :: BS.ByteString -> Either String Data
readData bs = flip runGet bs $ do
  gc <- get
  ipInfo <- get
  arInfos <- get
  l1 <- getWord32be
  cdi1 <- getByteString (fromIntegral l1)
  return (gc, ipInfo, arInfos, cdi1)

setup :: IO Data
setup = do
  bs <- BS.readFile filePath
  case readData bs of
    Left err -> error err
    Right d -> return d


verify :: Benchmark
verify =
    env setup $ \ ~(gc, ipInfo, arInfos, cdi1) -> 
          bench "Verify credential success" $ nf (verifyCredential gc ipInfo arInfos Nothing) cdi1

main :: IO ()
main = defaultMainWith (defaultConfig { timeLimit = 15 }) [
  verify
  ]
