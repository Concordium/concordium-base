{-# LANGUAGE ScopedTypeVariables #-}
module ConcordiumTests.Crypto.FFIVerify where

import Concordium.Crypto.FFIDataTypes
import Concordium.ID.Types
import Concordium.ID.Account

import qualified Data.ByteString as BS
import Data.Serialize

import Test.Hspec

filePath :: FilePath
filePath = "testdata/cdi-example.bin"

getData :: Get (ElgamalGen, PedersenKey, ElgamalGen, AnonymityRevokerPublicKey, IdentityProviderPublicKey)
getData = do
  dlogBase <- get
  cmmKey <- get
  arGen <- get
  arPubKey <- get
  ipVerifyKey <- get
  return (dlogBase, cmmKey, arGen, arPubKey, ipVerifyKey)

readData :: BS.ByteString -> Either String ((ElgamalGen, PedersenKey, ElgamalGen, AnonymityRevokerPublicKey, IdentityProviderPublicKey), BS.ByteString)
readData bs = loop (runGetPartial getData bs)
  where loop (Fail err _ ) = Left err
        loop (Partial k) = loop (k BS.empty)
        loop (Done r rest) = Right (r, rest)

testVerify ::
  (ElgamalGen, PedersenKey, ElgamalGen, AnonymityRevokerPublicKey, IdentityProviderPublicKey)
  -> CredentialDeploymentInformationBytes
  -> Bool
testVerify (a, b, c, d, e) bs = verifyCredential a b e c d bs

test :: BS.ByteString -> Either String Bool
test bs = case readData bs of
            Left err -> Left err
            Right (tuple, rest) -> Right (testVerify tuple rest)

tests :: Spec
tests = do
  bs <- runIO (BS.readFile filePath)
  describe "Basic FFI verification test" $
      specify ("Using " ++ filePath) $ shouldSatisfy (test bs) (== Right True)
