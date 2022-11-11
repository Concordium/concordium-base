{-# LANGUAGE ScopedTypeVariables #-}

module ConcordiumTests.Crypto.FFIVerify where

import Concordium.ID.Account
import Concordium.ID.AnonymityRevoker
import Concordium.ID.IdentityProvider
import Concordium.ID.Parameters
import Concordium.Types

import Control.Monad.Except
import qualified Data.ByteString as BS
import Data.Serialize

import Test.Hspec

filePath :: FilePath
filePath = "testdata/testdata.bin"

getData :: Get (GlobalContext, IpInfo, [ArInfo])
getData = get

readData :: BS.ByteString -> Either String ((GlobalContext, IpInfo, [ArInfo]), BS.ByteString)
readData bs = loop (runGetPartial getData bs)
  where
    loop (Fail err _) = Left err
    loop (Partial k) = loop (k BS.empty)
    loop (Done r rest) = Right (r, rest)

-- This should match with the EXPIRY constant in generate_testdata.
maxExpiry :: TransactionTime
maxExpiry = TransactionTime maxBound

test :: BS.ByteString -> Either String Bool
test bs = do
    ((gc, ipInfo, arInfos), rest) <- readData bs
    (cdi1, addr, cdi2, addr', icdi) <- flip runGet rest $ do
        l1 <- getWord32be
        c1 <- getByteString (fromIntegral l1)
        k <- get
        l2 <- getWord32be
        c2 <- getByteString (fromIntegral l2)
        k3 <- get
        l3 <- getWord32be
        c3 <- getByteString (fromIntegral l3)
        return (c1, k, c2, k3, c3)
    unless (verifyCredential gc ipInfo arInfos cdi1 (Left maxExpiry)) $ throwError "Verification of the first credential failed."
    when (verifyCredential gc ipInfo arInfos cdi1 (Left 0)) $ throwError "Verification of the first credential succeeded with incorrect expiry."
    when (verifyCredential gc ipInfo arInfos cdi1 (Right addr)) $ throwError "Verification of the first credential succeeded with addr instead of expiry."
    unless (verifyCredential gc ipInfo arInfos cdi2 (Right addr)) $ throwError "Verification with correct address failed."
    when (verifyCredential gc ipInfo arInfos cdi2 (Right addr')) $ throwError "Verification with wrong address should fail."
    unless (verifyInitialAccountCreation ipInfo maxExpiry icdi) $ throwError "Verification of initial credential deployment failed"
    when (verifyInitialAccountCreation ipInfo 0 icdi) $ throwError "Verification of initial credential with incorrect expiry succeeded."
    return True

tests :: Spec
tests = do
    bs <- runIO (BS.readFile filePath)
    describe "Basic FFI verification test" $
        specify ("Using " ++ filePath) $
            shouldSatisfy (test bs) (== Right True)
