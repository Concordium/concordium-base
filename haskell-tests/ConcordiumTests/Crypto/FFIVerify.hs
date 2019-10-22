{-# LANGUAGE ScopedTypeVariables #-}
module ConcordiumTests.Crypto.FFIVerify where

import Concordium.ID.Account
import Concordium.ID.Parameters
import Concordium.ID.IdentityProvider

import qualified Data.ByteString as BS
import Data.Serialize

import Test.Hspec

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

test :: BS.ByteString -> Either String Bool
test bs = case readData bs of
            Left err -> Left err
            Right (tuple, rest) -> Right (testVerify tuple rest)

tests :: Spec
tests = do
  bs <- runIO (BS.readFile filePath)
  describe "Basic FFI verification test" $
      specify ("Using " ++ filePath) $ shouldSatisfy (test bs) (== Right True)
