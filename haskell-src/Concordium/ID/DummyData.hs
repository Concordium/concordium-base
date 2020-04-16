{-# LANGUAGE RecordWildCards #-}
-- |

module Concordium.ID.DummyData where

import qualified Data.Map.Strict as OrdMap
import qualified Data.Hashable as IntHash
import qualified Data.FixedByteString as FBS
import qualified Data.ByteString.Lazy as BSL
import System.Random
import Concordium.ID.Types as ID
import Concordium.ID.IdentityProvider as IP
import qualified Data.Aeson as AE

-- Derive a dummy registration id from an account address. This hashes the
-- account address derived from the verification key, and uses it as a seed of a
-- random number generator.
{-# WARNING dummyRegId "Invalid credential Registration ID, only for testing." #-}
dummyRegId :: AccountAddress -> ID.CredentialRegistrationID
dummyRegId addr = ID.RegIdCred . FBS.pack $ bytes
  where bytes = take (FBS.fixedLength (undefined :: ID.RegIdSize)) . randoms . mkStdGen $ IntHash.hash addr

-- This credential value is invalid and does not satisfy the invariants normally expected of credentials.
-- Should only be used when only the existence of a credential is needed in testing, but the credential
-- will neither be serialized, nor inspected.
{-# WARNING dummyCredential "Invalid credential, only for testing." #-}
dummyCredential :: ID.AccountAddress -> ID.CredentialValidTo -> ID.CredentialCreatedAt -> ID.CredentialDeploymentValues
dummyCredential address pValidTo pCreatedAt = ID.CredentialDeploymentValues
    {
      cdvAccount = ID.ExistingAccount address,
      cdvRegId = dummyRegId address,
      cdvIpId = ID.IP_ID 0,
      cdvThreshold = ID.Threshold 2,
      cdvArData = [],
      cdvPolicy = ID.Policy {
        pItems = OrdMap.empty,
        ..
        },
      ..
    }

{-# WARNING dummyMaxValidTo "Invalid validTo, only for testing." #-}
dummyMaxValidTo :: ID.YearMonth
dummyMaxValidTo = YearMonth 2199 12

{-# WARNING dummyLowValidTo "Invalid validTo, only for testing." #-}
dummyLowValidTo :: ID.YearMonth
dummyLowValidTo = YearMonth 1900 1

{-# WARNING dummyCreatedAt "Invalid creation time, only for testing." #-}
dummyCreatedAt :: ID.YearMonth
dummyCreatedAt = YearMonth 2020 3

{-# WARNING dummyEmptyIdentityProviders "Invalid identity providers, only for testing." #-}
dummyEmptyIdentityProviders :: [IP.IpInfo]
dummyEmptyIdentityProviders = []

{-# WARNING readCredential "Do not use in production." #-}
readCredential :: FilePath -> IO ID.CredentialDeploymentInformation
readCredential fp = do
  bs <- BSL.readFile fp
  case AE.eitherDecode bs of
    Left err -> fail $ "Cannot read credential from file " ++ fp ++ " because " ++ err
    Right d -> return d
