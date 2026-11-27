{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- | Deterministic initial-genesis examples for serialization tests.
module Examples.Genesis (p8GenesisExample, p9GenesisExample, p10GenesisExample, p11GenesisExample) where

import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Ratio ((%))
import qualified Data.Serialize as S
import qualified Data.Set as Set
import qualified Data.Vector as Vec

import Concordium.Common.Time (YearMonth (..))
import qualified Concordium.Crypto.BlsSignature as Bls
import qualified Concordium.Crypto.Ed25519Signature as Ed25519
import Concordium.Crypto.FFIDataTypes (generateGroupElementFromSeed)
import qualified Concordium.Crypto.SHA256 as Hash
import qualified Concordium.Crypto.SignatureScheme as Sig
import qualified Concordium.Crypto.VRF as VRF
import Concordium.Genesis.Account
import Concordium.Genesis.Data.Base (GenesisState (..))
import Concordium.Genesis.Data.BaseV1 (CoreGenesisParametersV1 (..))
import qualified Concordium.Genesis.Data.P10 as P10
import qualified Concordium.Genesis.Data.P11 as P11
import qualified Concordium.Genesis.Data.P8 as P8
import qualified Concordium.Genesis.Data.P9 as P9
import Concordium.ID.Parameters (dummyGlobalContext)
import Concordium.ID.Types
import Concordium.Types
import Concordium.Types.AnonymityRevokers (emptyAnonymityRevokers)
import Concordium.Types.IdentityProviders (emptyIdentityProviders)
import Concordium.Types.Parameters
import Concordium.Types.Updates

import Examples.ChainParameters

-- | One key authorizes each update. The protocol selects the available access structures.
updateKeysExample :: forall auv. (IsAuthorizationsVersion auv) => Sig.VerifyKey -> UpdateKeysCollection auv
updateKeysExample key =
    UpdateKeysCollection
        { rootKeys = HigherLevelKeys (Vec.singleton key) 1,
          level1Keys = HigherLevelKeys (Vec.singleton key) 1,
          level2Keys =
            Authorizations
                { asKeys = Vec.singleton key,
                  asEmergency = access,
                  asProtocol = access,
                  asParamConsensusParameters = access,
                  asParamEuroPerEnergy = access,
                  asParamMicroGTUPerEuro = access,
                  asParamFoundationAccount = access,
                  asParamMintDistribution = access,
                  asParamTransactionFeeDistribution = access,
                  asParamGASRewards = access,
                  asPoolParameters = access,
                  asAddAnonymityRevoker = access,
                  asAddIdentityProvider = access,
                  asCooldownParameters = conditionally (sSupportsCooldownParametersAccessStructure version) access,
                  asTimeParameters = conditionally (sSupportsTimeParameters version) access,
                  asCreatePLT = conditionally (sSupportsCreatePLT version) access,
                  asTokenParameters = conditionally (sSupportsTokenParameters version) access
                }
        }
  where
    access = AccessStructure (Set.singleton 0) 1
    version = authorizationsVersion @auv

-- | Use one foundation account with a credential and a baker after the chain parameters.
genesisStateExample :: (IsAuthorizationsVersion (AuthorizationsVersionFor pv)) => ChainParameters pv -> Either String (GenesisState pv)
genesisStateExample parameters = do
    signingKey <- S.decode (BS.replicate 32 1)
    electionKey <- S.decode (BS.replicate 32 2)
    aggregationKey <- S.decode (BS.replicate 32 3)
    let verifyKey = Sig.VerifyKeyEd25519 (Ed25519.deriveVerifyKey signingKey)
        credential =
            InitialCredentialDeploymentValues
                { icdvAccount = makeCredentialPublicKeys [verifyKey] 1,
                  icdvRegId = RegIdCred (generateGroupElementFromSeed dummyGlobalContext 0),
                  icdvIpId = IP_ID 0,
                  icdvPolicy = Policy (YearMonth 2030 1) (YearMonth 2020 1) Map.empty
                }
        account =
            GenesisAccount
                { gaAddress = initialCredentialAccountAddress credential,
                  gaThreshold = 1,
                  gaBalance = 1000000000000,
                  gaCredentials = Map.singleton initialCredentialIndex (InitialAC credential),
                  gaBaker =
                    Just
                        GenesisBaker
                            { gbElectionVerifyKey = VRF.pubKey electionKey,
                              gbSignatureVerifyKey = Ed25519.deriveVerifyKey signingKey,
                              gbAggregationVerifyKey = Bls.derivePublicKey aggregationKey,
                              gbStake = 300000000000,
                              gbRestakeEarnings = True,
                              gbBakerId = 0
                            }
                }
    return
        GenesisState
            { genesisCryptographicParameters = dummyGlobalContext,
              genesisIdentityProviders = emptyIdentityProviders,
              genesisAnonymityRevokers = emptyAnonymityRevokers,
              genesisUpdateKeys = updateKeysExample verifyKey,
              genesisChainParameters = parameters,
              genesisLeadershipElectionNonce = Hash.hash "genesis-example-nonce",
              genesisAccounts = Vec.singleton account
            }

-- | Fixed consensus timing shared by the examples.
coreExample :: CoreGenesisParametersV1
coreExample = CoreGenesisParametersV1 1794993140589 3600000 (2 % 3)

-- | P8 genesis with CPV3 and authorization version 1.
p8GenesisExample :: Either String P8.GenesisDataP8
p8GenesisExample = P8.GDP8Initial coreExample <$> genesisStateExample @'P8 p8ChainParametersExample

-- | P9 genesis with CPV3 and authorization version 2.
p9GenesisExample :: Either String P9.GenesisDataP9
p9GenesisExample = P9.GDP9Initial coreExample <$> genesisStateExample @'P9 p8ChainParametersExample

-- | P10 genesis with CPV3 and authorization version 2.
p10GenesisExample :: Either String P10.GenesisDataP10
p10GenesisExample = P10.GDP10Initial coreExample <$> genesisStateExample @'P10 p8ChainParametersExample

-- | P11 genesis with CPV4 and authorization version 3.
p11GenesisExample :: Either String P11.GenesisDataP11
p11GenesisExample = P11.GDP11Initial coreExample <$> genesisStateExample @'P11 p11ChainParametersExample
