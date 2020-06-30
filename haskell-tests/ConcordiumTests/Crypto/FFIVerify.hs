{-# LANGUAGE ScopedTypeVariables #-}
module ConcordiumTests.Crypto.FFIVerify where

import Concordium.ID.Account
import Concordium.ID.Parameters
import Concordium.ID.IdentityProvider

import qualified Data.ByteString as BS
import Data.Serialize
import Control.Monad.Except

import Test.Hspec

filePath :: FilePath
filePath = "testdata/testdata.bin"


getData :: Get (GlobalContext, IpInfo)
getData = getTwoOf get get

readData :: BS.ByteString -> Either String ((GlobalContext, IpInfo), BS.ByteString)
readData bs = loop (runGetPartial getData bs)
  where loop (Fail err _ ) = Left err
        loop (Partial k) = loop (k BS.empty)
        loop (Done r rest) = Right (r, rest)

testVerify :: (GlobalContext, IpInfo) -> CredentialDeploymentInformationBytes -> Bool
testVerify (gc, ipInfo) = verifyCredential gc ipInfo Nothing

test :: BS.ByteString -> Either String Bool
test bs = do
  ((gc, ipInfo), rest) <- readData bs
  (cdi1, accKeys, cdi2, accKeys') <- flip runGet rest $ do
    l1 <- getWord32be
    c1 <- getByteString (fromIntegral l1)
    k <- get
    l2 <- getWord32be
    c2 <- getByteString (fromIntegral l2)
    k3 <- get
    return (c1, k, c2, k3)
  unless (verifyCredential gc ipInfo Nothing cdi1) $ throwError "Verification of the first credential failed."
  unless (verifyCredential gc ipInfo (Just accKeys) cdi2) $ throwError "Verification of the second credential failed."
  when (verifyCredential gc ipInfo (Just accKeys') cdi2) $ throwError "Verification of with wrong keys should fail."
  return True

tests :: Spec
tests = do
  bs <- runIO (BS.readFile filePath)
  describe "Basic FFI verification test" $
      specify ("Using " ++ filePath) $ shouldSatisfy (test bs) (== Right True)
