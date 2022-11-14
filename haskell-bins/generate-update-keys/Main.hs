{-# LANGUAGE OverloadedStrings #-}

-- |A tool for generating update keys and authorizations for
--    chain updates.  The generated authorizations can be used
--    in genesis data, or used to update the authorizations on
--    chain.
module Main where

import Control.Monad
import qualified Data.Aeson.Encode.Pretty as AE
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Set as Set
import qualified Data.Vector as Vec
import Data.Word
import Options.Applicative
import System.Exit
import System.FilePath

import Concordium.Crypto.SignatureScheme
import Concordium.Types.ProtocolVersion.JustForCPV1
import Concordium.Types.Updates

data AuthDetails = AuthDetails
    { adThreshold :: Word16,
      adKeys :: [Word16]
    }
    deriving (Show)

-- Reads "x:y,z,u" as AuthDetails x [y,z,u]
readAuthDetails :: ReadM AuthDetails
readAuthDetails = maybeReader $ \s -> case reads s of
    [(adThreshold, ':' : r)] -> case reads ("[" ++ r ++ "]") of
        [(adKeys, "")] -> Just AuthDetails{..}
        _ -> Nothing
    _ -> Nothing

data HigherAuthDetails = HigherAuthDetails
    { hadThreshold :: Word16,
      hadNumKeys :: Word16
    }
    deriving (Show)

-- reads "x:y" as HigherLevelKeys x y
readHigherAuthDetails :: ReadM HigherAuthDetails
readHigherAuthDetails = maybeReader $ \s -> case reads s of
    [(hadThreshold, ':' : r)] -> case reads r of
        [(hadNumKeys, "")] -> Just HigherAuthDetails{..}
        _ -> Nothing
    _ -> Nothing

-- |Common parameters for generating update keys across all protocol versions.
data CommonUpdateKeys = CommonUpdateKeys
    { -- |Number of keys to generate
      cukKeyCount :: Word16,
      -- |Name of authorization file to generate
      cukAuthorizationFile :: FilePath,
      -- |Directory to generate key files
      cukKeyPath :: FilePath,
      -- |Threshold and number of root keys to generate
      cukRootKeys :: HigherAuthDetails,
      -- |Threshold and number of level 1 keys to generate
      cukLevel1Keys :: HigherAuthDetails,
      -- |Key indices (and thresholds) to use for each update type
      cukEmergency :: AuthDetails,
      cukProtocol :: AuthDetails,
      cukElectionDifficulty :: AuthDetails,
      cukEuroEnergy :: AuthDetails,
      cukGTUEuro :: AuthDetails,
      cukFoundationAccount :: AuthDetails,
      cukMintDistribution :: AuthDetails,
      cukTransactionFeeDistribution :: AuthDetails,
      cukGASRewards :: AuthDetails,
      cukPoolParameters :: AuthDetails,
      cukAddAnonymityRevoker :: AuthDetails,
      cukAddIdentityProvider :: AuthDetails
    }
    deriving (Show)

-- |Parameters for generating chain parameter update keys.
data GenerateUpdateKeys
    = GenerateUpdateKeysCPV0
        { -- |Common across chain parameters versions
          gukCommon :: CommonUpdateKeys
        }
    | GenerateUpdateKeysCPV1
        { -- |Common across chain parameters versions
          gukCommon :: CommonUpdateKeys,
          -- |Key indices (and thresholds) to use for cooldown and time parameters
          gukCooldownParameters :: AuthDetails,
          gukTimeParameters :: AuthDetails
        }
    deriving (Show)

readKeyList :: ReadM [Word16]
readKeyList = maybeReader $ \s -> case reads ("[" ++ s ++ "]") of
    ((l, "") : _) -> Just l
    _ -> Nothing

commonParameters :: Parser CommonUpdateKeys
commonParameters =
    CommonUpdateKeys
        <$> argument auto (metavar "NUM" <> help "Number of level 2 keys to generate")
        <*> strOption (metavar "FILE" <> long "keys-outfile" <> help "File name for generated authorization" <> value "update-keys.json" <> showDefault)
        <*> strOption (metavar "PATH" <> long "keys-outdir" <> help "Path to output generated keys" <> value "." <> showDefault)
        <*> option readHigherAuthDetails (metavar "HACSTR" <> long "root-keys" <> help "Threshold and number of root keys to generate")
        <*> option readHigherAuthDetails (metavar "HACSTR" <> long "level1-keys" <> help "Threshold and number of level 1 keys to generate")
        <*> option readAuthDetails (metavar "ACSTR" <> long "emergency" <> help "Emergency update access structure")
        <*> option readAuthDetails (metavar "ACSTR" <> long "protocol" <> help "Protocol update access structure")
        <*> option readAuthDetails (metavar "ACSTR" <> long "election" <> help "Election difficulty update access structure")
        <*> option readAuthDetails (metavar "ACSTR" <> long "euro-energy" <> help "Euro:energy rate update access structure")
        <*> option readAuthDetails (metavar "ACSTR" <> long "gtu-euro" <> help "GTU:Euro rate update access structure")
        <*> option readAuthDetails (metavar "ACSTR" <> long "foundation-account" <> help "Foundation account update access structure")
        <*> option readAuthDetails (metavar "ACSTR" <> long "mint-distribution" <> help "Mint distribution update access structure")
        <*> option readAuthDetails (metavar "ACSTR" <> long "fee-distribution" <> help "Transaction fee distribution update access structure")
        <*> option readAuthDetails (metavar "ACSTR" <> long "gas-rewards" <> help "GAS rewards update access structure")
        <*> option readAuthDetails (metavar "ACSTR" <> long "pool-parameters" <> help "Pool parameters access structure")
        <*> option readAuthDetails (metavar "ACSTR" <> long "add-anonymity-revoker" <> help "Add anonymity revoker access structure")
        <*> option readAuthDetails (metavar "ACSTR" <> long "add-identity-provider" <> help "Add identity provider access structure")

parameters :: Parser GenerateUpdateKeys
parameters =
    GenerateUpdateKeysCPV1
        <$> commonParameters
        <*> option readAuthDetails (metavar "ACSTR" <> long "cooldown" <> help "Cooldown update access structure")
        <*> option readAuthDetails (metavar "ACSTR" <> long "time" <> help "Time update access structure")

main :: IO ()
main = customExecParser p opts >>= generateKeys
  where
    opts =
        info (parameters <**> helper) $
            header "Generate keys for updates on the Concordium block chain."
                <> progDesc
                    "Generate a set of keypairs and an authorization structure for chain updates. \
                    \An authorization structure determines which keys are required for performing \
                    \each kind of chain update. An authorization structure is required at genesis \
                    \and may subsequently be replaced in an authorization update."
                <> footer
                    "HACSTR for root and level 1 keys should be entered in the form: THRESHOLD:NUMBER-OF-KEYS. ACSTR for level 2 keys should be \
                    \entered in the form: THRESHOLD:KEY1,KEY2,...,KEYn. THRESHOLD is \
                    \the minimum number of keys that are required to authorize the update (and must \
                    \be at most n). The level 2 keys are specified by 0-based index, and so must be less than \
                    \NUM (the total number of keys being generated). Root and level 1 keys will be generated separatedly from \
                    \ the level 2 keys, thus not being counted in the total number of generated keys."
    p = prefs showHelpOnEmpty

-- |Generate chain update keys.
generateKeys :: GenerateUpdateKeys -> IO ()
generateKeys guk = do
    when (cukKeyCount == 0) $ die "At least one level 2 key is required."
    asEmergency <- makeAS cukEmergency "Emergency update access structure"
    asProtocol <- makeAS cukProtocol "Protocol update access structure"
    asParamElectionDifficulty <- makeAS cukElectionDifficulty "Election difficulty update access structure"
    asParamEuroPerEnergy <- makeAS cukEuroEnergy "Euro-energy rate update access structure"
    asParamMicroGTUPerEuro <- makeAS cukGTUEuro "GTU-Euro rate update access structure"
    asParamFoundationAccount <- makeAS cukFoundationAccount "Foundation account update access structure"
    asParamMintDistribution <- makeAS cukMintDistribution "Mint distribution update access structure"
    asParamTransactionFeeDistribution <- makeAS cukTransactionFeeDistribution "Transaction fee distribution update access structure"
    asParamGASRewards <- makeAS cukGASRewards "GAS rewards update access structure"
    asPoolParameters <- makeAS cukPoolParameters "Baker minimum threshold access structure"
    asAddAnonymityRevoker <- makeAS cukAddAnonymityRevoker "Add anonymity revoker access structure"
    asAddIdentityProvider <- makeAS cukAddIdentityProvider "Add identity provider access structure"
    let asKeys = Vec.empty -- Placeholder; replaced in doGenerateKeys
    case guk of
        GenerateUpdateKeysCPV0{} ->
            doGenerateKeys
                Authorizations
                    { asCooldownParameters = NothingForCPV1,
                      asTimeParameters = NothingForCPV1,
                      ..
                    }
        GenerateUpdateKeysCPV1{..} -> do
            asCooldownParameters <-
                JustForCPV1
                    <$> makeAS gukCooldownParameters "Add identity provider access structure"
            asTimeParameters <-
                JustForCPV1
                    <$> makeAS gukCooldownParameters "Add identity provider access structure"
            doGenerateKeys Authorizations{..}
  where
    CommonUpdateKeys{..} = gukCommon guk
    doGenerateKeys level2KeysPre = do
        putStrLn "Generating keys..."
        asKeys <- Vec.fromList <$> sequence [makeKey k "level2-key" | k <- [0 .. cukKeyCount - 1]]
        let level2Keys = level2KeysPre{asKeys = asKeys}
        rootKeys <- makeHAS cukRootKeys "root-key" "Root key structure"
        level1Keys <- makeHAS cukLevel1Keys "level1-key" "Level 1 key structure"
        let keyCollection = UpdateKeysCollection{..}
        LBS.writeFile cukAuthorizationFile (AE.encodePretty' AE.defConfig{AE.confCompare = keyComp} keyCollection)
    keyComp =
        AE.keyOrder ["keys", "emergency", "protocol", "electionDifficulty", "euroPerEnergy", "microGTUPerEuro", "schemeId"]
            <> compare
    makeAS AuthDetails{..} desc = do
        let accessPublicKeys = Set.fromList adKeys
            nKeys = Set.size accessPublicKeys
            -- maxKey should only be evaluated after determining accessPublicKeys to have at least one
            -- element
            maxKey = Set.findMax accessPublicKeys
        when (adThreshold < 1) $ die (desc ++ ": threshold must be at least 1")
        when (nKeys < 1) $ die (desc ++ ": number of keys provided must be at least 1")
        when (fromIntegral adThreshold > nKeys) $ die (desc ++ ": threshold (" ++ show adThreshold ++ ") cannot exceed number of keys (" ++ show nKeys ++ ")")
        when (maxKey >= cukKeyCount) $ die (desc ++ ": key index " ++ show maxKey ++ " is out of bounds. Maximal index is " ++ show (cukKeyCount - 1))
        return AccessStructure{accessThreshold = UpdateKeysThreshold adThreshold, ..}
    makeHAS HigherAuthDetails{..} name desc = do
        when (hadThreshold > hadNumKeys) $ die (desc ++ ": threshold (" ++ show hadThreshold ++ ") cannot exceed number of keys (" ++ show hadNumKeys ++ ")")
        hlkKeys <- Vec.fromList <$> sequence [makeKey k name | k <- [0 .. hadNumKeys - 1]]
        return HigherLevelKeys{hlkThreshold = UpdateKeysThreshold hadThreshold, ..}
    makeKey k desc = do
        kp <- newKeyPair Ed25519
        LBS.writeFile (cukKeyPath </> (desc ++ "-" ++ show k ++ ".json")) (AE.encodePretty' AE.defConfig{AE.confCompare = keyComp} kp)
        return (correspondingVerifyKey kp)
