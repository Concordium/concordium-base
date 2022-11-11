{-# OPTIONS_GHC -Wno-deprecations #-}

module Concordium.ID.DummyData where

import Concordium.Common.Time
import Concordium.Common.Version
import Concordium.Crypto.FFIDataTypes
import qualified Concordium.Crypto.SignatureScheme as SigScheme
import Concordium.ID.Parameters
import Concordium.ID.Types
import qualified Data.Aeson as AE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.FixedByteString as FBS
import qualified Data.Hashable as IntHash
import qualified Data.Map.Strict as OrdMap

-- Derive a dummy registration id from an account address. This hashes the
-- account address derived from the verification key, and uses it as a seed of a
-- random number generator.
{-# WARNING dummyRegId "Invalid credential Registration ID, only for testing." #-}
dummyRegId :: GlobalContext -> AccountAddress -> CredentialRegistrationID
dummyRegId gc addr = RegIdCred (generateGroupElementFromSeed gc (fromIntegral (IntHash.hash addr)))

-- Derive a dummy encryption secret key corresponding to the dummyRegId above.
{-# WARNING dummyEncryptionSecretKey "Only use for testing, do not use in production." #-}
dummyEncryptionSecretKey :: GlobalContext -> AccountAddress -> ElgamalSecretKey
dummyEncryptionSecretKey gc addr = generateElgamalSecretKeyFromSeed gc (fromIntegral (IntHash.hash addr))

{-# NOINLINE globalContext #-}
{-# WARNING globalContext "Do not use in production." #-}
globalContext :: GlobalContext
globalContext = dummyGlobalContext

-- This credential value is invalid and does not satisfy the invariants normally expected of credentials.
-- Should only be used when only the existence of a credential is needed in testing, but the credential
-- will neither be serialized, nor inspected.
{-# WARNING dummyCredential "Invalid credential, only for testing." #-}
dummyCredential :: GlobalContext -> AccountAddress -> SigScheme.VerifyKey -> CredentialValidTo -> CredentialCreatedAt -> AccountCredential
dummyCredential gc addr key pValidTo pCreatedAt =
    NormalAC
        ( CredentialDeploymentValues
            { cdvPublicKeys = makeCredentialPublicKeys [key] 1,
              cdvCredId = dummyRegId gc addr,
              cdvIpId = IP_ID 0,
              cdvThreshold = Threshold 2,
              cdvArData = OrdMap.empty,
              cdvPolicy =
                Policy
                    { pItems = OrdMap.empty,
                      ..
                    },
              ..
            }
        )
        $ CredentialDeploymentCommitments
            { cmmPrf = dummyCommitment,
              cmmCredCounter = dummyCommitment,
              cmmMaxAccounts = dummyCommitment,
              cmmAttributes = OrdMap.empty,
              cmmIdCredSecSharingCoeff = []
            }

{-# WARNING dummyCommitment "Commitment with 0 inside, only for testing." #-}

-- | This is a commitment to 0 with randomness 0.
dummyCommitment :: Commitment
dummyCommitment = Commitment (FBS.fromByteString (BS.pack [192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))

{-# WARNING dummyMaxValidTo "Invalid validTo, only for testing." #-}
dummyMaxValidTo :: YearMonth
dummyMaxValidTo = YearMonth 9999 12

{-# WARNING dummyLowValidTo "Invalid validTo, only for testing." #-}
dummyLowValidTo :: YearMonth
dummyLowValidTo = YearMonth 1000 1

{-# WARNING dummyCreatedAt "Invalid creation time, only for testing." #-}
dummyCreatedAt :: YearMonth
dummyCreatedAt = YearMonth 2020 3

{-# WARNING readCredential "Do not use in production." #-}
readCredential :: BSL.ByteString -> CredentialDeploymentInformation
readCredential bs =
    case AE.eitherDecode bs of
        Left err -> error $ "Cannot read credential because " ++ err
        Right d -> if vVersion d == 0 then vValue d else error "Incorrect credential version."

{-# WARNING readInitialCredential "Do not use in production." #-}
readInitialCredential :: BSL.ByteString -> InitialCredentialDeploymentInfo
readInitialCredential bs =
    case AE.eitherDecode bs of
        Left err -> error $ "Cannot read credential because " ++ err
        Right d -> if vVersion d == 0 then vValue d else error "Incorrect credential version."
