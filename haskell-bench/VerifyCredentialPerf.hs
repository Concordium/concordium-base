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
filePath = "testdata/cdi-example.bin"

getData :: Get (GlobalContext, IpInfo)
getData = getTwoOf get get

readData :: BS.ByteString -> Either String ((GlobalContext, IpInfo), BS.ByteString)
readData bs = loop (runGetPartial getData bs)
  where loop (Fail err _ ) = Left err
        loop (Partial k) = loop (k BS.empty)
        loop (Done r rest) = Right (r, rest)

testVerify :: (GlobalContext, IpInfo) -> CredentialDeploymentInformationBytes -> Bool
testVerify = uncurry verifyCredential

setup :: IO ((GlobalContext, IpInfo), BS.ByteString)
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
