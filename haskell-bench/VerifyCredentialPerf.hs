{-# LANGUAGE ScopedTypeVariables #-}
module Main where

import Criterion
import Criterion.Main
import Criterion.Types

import qualified Data.ByteString.Char8 as BS

import Concordium.ID.Account
import Concordium.ID.Parameters
import Concordium.ID.IdentityProvider

import Data.Serialize


filePath :: FilePath
filePath = "testdata/testdata.bin"

getData :: Get (GlobalContext, IpInfo)
getData = getTwoOf get get

type Data = (GlobalContext, IpInfo, CredentialDeploymentInformationBytes)

readData :: BS.ByteString -> Either String Data
readData bs = flip runGet bs $ do
  gc <- get
  ipInfo <- get
  l1 <- getWord32be
  cdi1 <- getByteString (fromIntegral l1)
  return (gc, ipInfo, cdi1)

testVerify :: (GlobalContext, IpInfo) -> CredentialDeploymentInformationBytes -> Bool
testVerify (gc, ipInfo) = verifyCredential gc ipInfo Nothing

setup :: IO Data
setup = do
  bs <- BS.readFile filePath
  case readData bs of
    Left err -> error err
    Right d -> return d


verify :: Benchmark
verify =
    env setup $ \ ~(gc, ipInfo, cdi1) -> 
          bench "Verify credential success" $ nf (verifyCredential gc ipInfo Nothing) cdi1

main :: IO ()
main = defaultMainWith (defaultConfig { timeLimit = 15 }) [
  verify
  ]
