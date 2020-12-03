{-# LANGUAGE RecordWildCards, TemplateHaskell #-}
{-# OPTIONS_GHC -Wno-deprecations #-}
module Concordium.ID.DummyData where

import Concordium.Common.Version
import qualified Data.Map.Strict as OrdMap
import qualified Data.Hashable as IntHash
import qualified Data.ByteString.Lazy as BSL
import Concordium.ID.Types as ID
import Concordium.ID.Parameters
import Concordium.Crypto.FFIDataTypes
import qualified Data.Aeson as AE
import qualified Concordium.Crypto.SignatureScheme as SigScheme

-- Derive a dummy registration id from an account address. This hashes the
-- account address derived from the verification key, and uses it as a seed of a
-- random number generator.
{-# WARNING dummyRegId "Invalid credential Registration ID, only for testing." #-}
dummyRegId :: AccountAddress -> ID.CredentialRegistrationID
dummyRegId addr = ID.RegIdCred (generateGroupElementFromSeed dummyGlobalContext (fromIntegral (IntHash.hash addr)))

-- Derive a dummy encryption secret key corresponding to the dummyRegId above.
{-# WARNING dummyEncryptionSecretKey "Only use for testing, do not use in production." #-}
dummyEncryptionSecretKey :: AccountAddress -> ElgamalSecretKey
dummyEncryptionSecretKey addr = generateElgamalSecretKeyFromSeed dummyGlobalContext (fromIntegral (IntHash.hash addr))

{-# NOINLINE globalContext #-}
{-# WARNING globalContext "Do not use in production." #-}
globalContext :: GlobalContext
globalContext = dummyGlobalContext

-- This credential value is invalid and does not satisfy the invariants normally expected of credentials.
-- Should only be used when only the existence of a credential is needed in testing, but the credential
-- will neither be serialized, nor inspected.
{-# WARNING dummyCredential "Invalid credential, only for testing." #-}
dummyCredential :: AccountAddress -> SigScheme.VerifyKey -> ID.CredentialValidTo -> ID.CredentialCreatedAt -> ID.AccountCredential
dummyCredential addr key pValidTo pCreatedAt = ID.NormalAC $ ID.CredentialDeploymentValues
    {
      cdvAccount = ID.NewAccount [key] 1,
      cdvRegId = dummyRegId addr,
      cdvIpId = ID.IP_ID 0,
      cdvThreshold = ID.Threshold 2,
      cdvArData = OrdMap.empty,
      cdvPolicy = ID.Policy {
        pItems = OrdMap.empty,
        ..
        },
      ..
    }

{-# WARNING dummyMaxValidTo "Invalid validTo, only for testing." #-}
dummyMaxValidTo :: ID.YearMonth
dummyMaxValidTo = YearMonth 9999 12

{-# WARNING dummyLowValidTo "Invalid validTo, only for testing." #-}
dummyLowValidTo :: ID.YearMonth
dummyLowValidTo = YearMonth 1000 1

{-# WARNING dummyCreatedAt "Invalid creation time, only for testing." #-}
dummyCreatedAt :: ID.YearMonth
dummyCreatedAt = YearMonth 2020 3

{-# WARNING readCredential "Do not use in production." #-}
readCredential :: BSL.ByteString -> ID.CredentialDeploymentInformation
readCredential bs = 
  case AE.eitherDecode bs of
    Left err -> error $ "Cannot read credential because " ++ err
    Right d -> if vVersion d == 0 then vValue d else error "Incorrect credential version."

{-# WARNING readInitialCredential "Do not use in production." #-}
readInitialCredential :: BSL.ByteString -> ID.InitialCredentialDeploymentInfo
readInitialCredential bs =
  case AE.eitherDecode bs of
    Left err -> error $ "Cannot read credential because " ++ err
    Right d -> if vVersion d == 0 then vValue d else error "Incorrect credential version."
