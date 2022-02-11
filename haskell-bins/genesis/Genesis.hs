{-# OPTIONS_GHC -fno-cse #-}
{-# LANGUAGE DeriveDataTypeable, OverloadedStrings, ScopedTypeVariables, GADTs, TypeApplications #-}
module Main where

import System.Exit
import System.Console.CmdArgs
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy.Char8 as LBS8
import qualified Data.Map.Strict as OrdMap
import Data.Aeson
import Data.Aeson.Encode.Pretty
import qualified Data.Serialize as S
import Control.Monad
import Text.Printf
import Data.Time.Format
import Lens.Micro.Platform
import qualified Data.Vector as Vec
import Data.Foldable
import Data.Maybe
import Data.Ratio
import System.FilePath

import Data.Text(Text)
import qualified Data.HashMap.Strict as Map
import Concordium.Common.Version
import Concordium.Types.Parameters
import Concordium.Genesis.Parameters
import Concordium.Genesis.Data
import qualified Concordium.Genesis.Data.P1 as P1
import qualified Concordium.Genesis.Data.P2 as P2
import qualified Concordium.Genesis.Data.P3 as P3
import qualified Concordium.Genesis.Data.P4 as P4
import qualified Concordium.Genesis.Data.Base as GDBase
import Concordium.Types.IdentityProviders
import Concordium.Types.AnonymityRevokers
import Concordium.Types
import Concordium.Types.Updates

data Genesis
    = GenerateGenesisData {gdSource :: FilePath,
                           gdOutput :: FilePath,
                           gdIdentity :: Maybe FilePath,
                           gdArs :: Maybe FilePath,
                           gdCryptoParams :: Maybe FilePath,
                           gdAccounts :: Maybe FilePath,
                           gdUpdateKeys :: Maybe FilePath,
                           gdVersion :: Integer
                           }
      | PrintGenesisData { gdSource :: FilePath }
    deriving (Typeable, Data)


generateGenesisData :: Genesis
generateGenesisData = GenerateGenesisData {
    gdSource = def &= typ "INFILE" &= argPos 0,
    gdOutput = def &= typ "OUTFILE" &= argPos 1,
    gdIdentity = def &=
                 explicit &=
                 name "identity-providers" &=
                 opt (Nothing :: Maybe FilePath) &=
                 typFile &=
                 help "JSON file with identity providers.",
    gdArs = def &=
            explicit &=
            name "anonymity-revokers" &=
            opt (Nothing :: Maybe FilePath) &=
            typFile &=
            help "JSON file with anonymity revokers.",
    gdCryptoParams = def &=
                     explicit &=
                     name "crypto-params" &=
                     opt (Nothing :: Maybe FilePath) &=
                     typFile &=
                     help "JSON file with cryptographic parameters for the chain.",
    gdAccounts = def &=
                           explicit &=
                           name "accounts" &=
                           opt (Nothing :: Maybe FilePath) &=
                           typFile &=
                           help "JSON file with initial accounts, whether they are bakers or not.",
    gdUpdateKeys = def &=
                        explicit &=
                        name "update-keys" &=
                        opt (Nothing :: Maybe FilePath) &=
                        typFile &=
                        help "JSON file with update keys.",
    gdVersion = 3 &=
        explicit &=
        name "gdver" &=
        typ "VER" &=
        help "Genesis data format version."
 } &= help "Parse JSON genesis parameters from INFILE and write serialized genesis data to OUTFILE"
  &= explicit &= name "make-genesis"

printGenesisBlock :: Genesis
printGenesisBlock = PrintGenesisData {
    gdSource = def &= typ "INFILE" &= argPos 0
 } &= help "Parse genesis data from INFILE and print it to stdout."
  &= explicit &= name "print-genesis"

mode :: Mode (CmdArgs Genesis)
mode = cmdArgsMode $ modes [generateGenesisData, printGenesisBlock]
    &= summary "Concordium genesis v1"
    &= help "Generate genesis data or display the genesis block."

modifyValueWith :: Text -> Value -> Value -> Maybe Value
modifyValueWith key val (Object obj) = Just (Object (Map.insert key val obj))
modifyValueWith _ _ _ = Nothing

maybeModifyValue :: Maybe FilePath -> Text -> Value -> IO Value
maybeModifyValue Nothing _ obj = return obj
maybeModifyValue (Just source) key obj = do
  inBS <- LBS.readFile source
  case eitherDecode inBS of
    Left e -> do
      die $ "Could not decode JSON: " ++ e
    Right v' ->
      case modifyValueWith key v' obj of
        Nothing -> do
          putStrLn "Base value not an object."
          exitFailure
        Just v -> return v


maybeModifyValueVersioned :: Version -> Maybe FilePath -> Text -> Value -> IO Value
maybeModifyValueVersioned _ Nothing _ obj = return obj
maybeModifyValueVersioned ver (Just source) key obj = do
  inBS <- LBS.readFile source
  case eitherDecode inBS of
    Left e -> do
      die $ "Could not decode JSON: " ++ e
    Right v' -> do
      if vVersion v' /= ver then do
        die $ "Invalid version in JSON file, expected " ++ show ver ++ ", got " ++ show (vVersion v')
      else do
        let value = vValue v'
        case modifyValueWith key value obj of
          Nothing -> do
            die $ "Base value '" ++ show key ++ "' not an object."
          Just v -> return v

unwrapVersionedGenesisParameters :: Version -> Versioned Value -> IO Value
unwrapVersionedGenesisParameters ver v =
  if vVersion v /= ver then die $ "Unsupported genesis parameters version " ++ show (vVersion v)
  else return (vValue v)

expectedIpInfosVersion, expectedArInfosVersion, expectedGenesisParametersVersion, expectedCryptoParamsVersion :: Version
expectedArInfosVersion = 0
expectedIpInfosVersion = 0
expectedGenesisParametersVersion = genesisParametersVersion
expectedCryptoParamsVersion = 0

main :: IO ()
main = cmdArgsRun mode >>=
    \case
        GenerateGenesisData{..} -> do
            inBS <- LBS.readFile gdSource
            case eitherDecode inBS of
                Left e -> do
                    putStrLn e
                    exitFailure
                Right v -> do
                  g <- unwrapVersionedGenesisParameters expectedGenesisParametersVersion v
                  vId <- maybeModifyValueVersioned expectedIpInfosVersion gdIdentity "identityProviders" g
                  vAr <- maybeModifyValueVersioned expectedArInfosVersion gdArs "anonymityRevokers" vId
                  vCP <- maybeModifyValueVersioned expectedCryptoParamsVersion gdCryptoParams "cryptographicParameters" vAr
                  vAdditionalAccs <- maybeModifyValue gdAccounts "initialAccounts" vCP
                  value <- maybeModifyValue gdUpdateKeys "updateKeys" vAdditionalAccs
                  case fromJSON value of
                    Error err -> do
                      die $ "Could not decode genesis parameters: " ++ show err
                    Success params -> do
                      -- P1 and P2 initial genesis are really the same format, so we combine them into
                      -- the same PVGenesisData type when generating, and then output it.
                      pvGD <- case gdVersion of
                               3 -> return $ PVGenesisData . GDP1 $ P1.parametersToGenesisData params
                               -- see documentation of 'putVersionedGenesisData'
                               -- for why we assign these versions to P1 and P2 genesis
                               4 -> return $ PVGenesisData . GDP2 $ P2.parametersToGenesisData params
                               5 -> return $ PVGenesisData . GDP3 $ P3.parametersToGenesisData params
                               6 -> return $ PVGenesisData . GDP4 $ P4.parametersToGenesisData params
                               n -> do
                                 putStrLn $ "Unsupported genesis data version: " ++ show n
                                 exitFailure
                      putStrLn $ "Generated genesis data for protocol version " ++ show (pvProtocolVersion pvGD)
                      LBS.writeFile gdOutput (S.runPutLazy $ putPVGenesisData pvGD)
                      putStrLn $ "Wrote genesis data to file " ++ gdOutput
                      let hashFile = takeDirectory gdOutput </> "genesis_hash"
                      LBS.writeFile hashFile (encode [pvGenesisBlockHash pvGD])
                      putStrLn $ "Wrote genesis hash list to file " ++ hashFile
                      exitSuccess
        PrintGenesisData{..} -> do
          source <- LBS.readFile gdSource
          case S.runGetLazy getPVGenesisData source of
            Left err -> putStrLn $ "Cannot parse genesis data:" ++ err
            Right (PVGenesisData (gdata :: GenesisData pv)) ->
              case protocolVersion @pv of
                SP1 -> case gdata of
                  GDP1 P1.GDP1Regenesis{..} -> printRegenesis P1 genesisRegenesis
                  gd@(GDP1 P1.GDP1Initial{..}) -> printInitial P1 (genesisBlockHash gd) genesisCore genesisInitialState
                SP2 -> case gdata of
                  GDP2 P2.GDP2Regenesis{..} -> printRegenesis P2 genesisRegenesis
                  gd@(GDP2 P2.GDP2Initial{..}) -> printInitial P2 (genesisBlockHash gd) genesisCore genesisInitialState
                SP3 -> case gdata of
                  GDP3 P3.GDP3Regenesis{..} -> printRegenesis P3 genesisRegenesis
                  gd@(GDP3 P3.GDP3Initial{..}) -> printInitial P3 (genesisBlockHash gd) genesisCore genesisInitialState
                SP4 -> case gdata of
                  GDP4 P4.GDP4Regenesis{..} -> printRegenesis P3 genesisRegenesis
                  gd@(GDP4 P4.GDP4Initial{..}) -> printInitial P4 (genesisBlockHash gd) genesisCore genesisInitialState

printRegenesis :: ProtocolVersion -> RegenesisData -> IO ()
printRegenesis pv RegenesisData{genesisCore=CoreGenesisParameters{..},..} = do
    putStrLn $ "Re-genesis data for protocol version " ++ show pv
    putStrLn $ "Genesis time is set to: " ++ showTime genesisTime
    putStrLn $ "Slot duration: " ++ show (durationToNominalDiffTime genesisSlotDuration)
    putStrLn $ "Epoch length in slots: " ++ show genesisEpochLength

    putStrLn ""
    putStrLn "Finalization parameters: "
    let FinalizationParameters{..} = genesisFinalizationParameters
    putStrLn $ "  - minimum skip: " ++ show finalizationMinimumSkip
    putStrLn $ "  - committee max size: " ++ show finalizationCommitteeMaxSize
    putStrLn $ "  - waiting time: " ++ show (durationToNominalDiffTime finalizationWaitingTime)
    putStrLn $ "  - skip shrink factor: " ++ showRatio finalizationSkipShrinkFactor
    putStrLn $ "  - skip grow factor: " ++ showRatio finalizationSkipGrowFactor
    putStrLn $ "  - delay shrink factor: " ++ showRatio finalizationDelayShrinkFactor
    putStrLn $ "  - delay grow factor: " ++ showRatio finalizationDelayGrowFactor
    putStrLn $ "  - allow zero delay: " ++ show finalizationAllowZeroDelay

    putStrLn ""
    putStrLn $ "First genesis block: " ++ show genesisFirstGenesis
    putStrLn $ "Previous (re)genesis block: " ++ show genesisPreviousGenesis
    putStrLn $ "Terminal block of previous chain: " ++ show genesisTerminalBlock
    putStrLn $ "State hash: " ++ show genesisStateHash

printInitial :: ProtocolVersion -> BlockHash -> CoreGenesisParameters -> GDBase.GenesisState -> IO ()
printInitial pv gh CoreGenesisParameters{..} GDBase.GenesisState{..} = do
    putStrLn $ "Genesis data for genesis block with hash " ++ show gh
    putStrLn $ "Protocol version " ++ show pv
    putStrLn $ "Genesis time is set to: " ++ showTime genesisTime
    putStrLn $ "Slot duration: " ++ show (durationToNominalDiffTime genesisSlotDuration)
    putStrLn $ "Leadership election nonce: " ++ show genesisLeadershipElectionNonce
    putStrLn $ "Epoch length in slots: " ++ show genesisEpochLength

    let totalGTU = sum (gaBalance <$> genesisAccounts)

    putStrLn ""
    putStrLn $ "Genesis total GTU: " ++ amountToString totalGTU
    putStrLn $ "Maximum block energy: " ++ show genesisMaxBlockEnergy

    putStrLn ""
    putStrLn "Finalization parameters: "
    let FinalizationParameters{..} = genesisFinalizationParameters
    putStrLn $ "  - minimum skip: " ++ show finalizationMinimumSkip
    putStrLn $ "  - committee max size: " ++ show finalizationCommitteeMaxSize
    putStrLn $ "  - waiting time: " ++ show (durationToNominalDiffTime finalizationWaitingTime)
    putStrLn $ "  - skip shrink factor: " ++ showRatio finalizationSkipShrinkFactor
    putStrLn $ "  - skip grow factor: " ++ showRatio finalizationSkipGrowFactor
    putStrLn $ "  - delay shrink factor: " ++ showRatio finalizationDelayShrinkFactor
    putStrLn $ "  - delay grow factor: " ++ showRatio finalizationDelayGrowFactor
    putStrLn $ "  - allow zero delay: " ++ show finalizationAllowZeroDelay

    let ChainParameters{..} = genesisChainParameters
    putStrLn ""
    putStrLn "Chain parameters: "
    putStrLn $ "  - election difficulty: " ++ show _cpElectionDifficulty
    putStrLn $ "  - Euro per Energy rate: " ++ showExchangeRate _cpEuroPerEnergy
    putStrLn $ "  - microGTU per Euro rate: " ++ showExchangeRate _cpMicroGTUPerEuro
    putStrLn $ "  - baker extra cooldown epochs: " ++ show _cpBakerExtraCooldownEpochs
    putStrLn $ "  - maximum credential deployments per block: " ++ show _cpAccountCreationLimit
    putStrLn $ "  - minimum stake to become a baker: " ++ showBalance totalGTU _cpBakerStakeThreshold
    putStrLn "  - reward parameters:"
    putStrLn "    + mint distribution:"
    putStrLn $ "      * mint rate per slot: " ++ show (_cpRewardParameters ^. mdMintPerSlot)
    putStrLn $ "      * baking reward: " ++ show (_cpRewardParameters ^. mdBakingReward)
    putStrLn $ "      * finalization reward: " ++ show (_cpRewardParameters ^. mdFinalizationReward)
    putStrLn "    + transaction fee distribution:"
    putStrLn $ "      * baker: " ++ show (_cpRewardParameters ^. tfdBaker)
    putStrLn $ "      * GAS account: " ++ show (_cpRewardParameters ^. tfdGASAccount)
    putStrLn "    + GAS rewards:"
    putStrLn $ "      * baking a block: " ++ show (_cpRewardParameters ^. gasBaker)
    putStrLn $ "      * adding a finalization proof: " ++ show (_cpRewardParameters ^. gasFinalizationProof)
    putStrLn $ "      * adding a credential deployment: " ++ show (_cpRewardParameters ^. gasAccountCreation)
    putStrLn $ "      * adding a chain update: " ++ show (_cpRewardParameters ^. gasChainUpdate)

    let foundAcc = case genesisAccounts ^? ix (fromIntegral _cpFoundationAccount) of
          Nothing -> "INVALID (" ++ show _cpFoundationAccount ++ ")"
          Just acc -> show (gaAddress acc) ++ " (index " ++ show _cpFoundationAccount ++ ")"
    putStrLn $ "  - foundation account: " ++ foundAcc

    putStrLn ""
    putStrLn $ "Cryptographic parameters: "
    putStrLn $ "  - " ++ showAsJSON 3 genesisCryptographicParameters

    putStrLn ""
    putStrLn "Identity providers: "
    forM_ (OrdMap.toAscList (idProviders genesisIdentityProviders)) $ \(ipId, ipData) ->
      putStrLn $ "  - " ++ show ipId ++ ": " ++ showAsJSON (6 + length (show ipId)) ipData

    putStrLn ""
    putStrLn "Anonymity revokers: "
    forM_ (OrdMap.toAscList (arRevokers genesisAnonymityRevokers)) $ \(arId, arData) ->
      putStrLn $ "  - " ++ show arId ++ ": " ++ showAsJSON (6 + length (show arId)) arData

    putStrLn ""
    let bkrs = catMaybes (gaBaker <$> toList genesisAccounts)
    let bkrTotalStake = foldl' (+) 0 (gbStake <$> bkrs)
    putStrLn $ "\nThere are " ++ show (length bkrs) ++ " bakers with total stake: " ++ showBalance totalGTU bkrTotalStake

    putStrLn ""
    putStrLn "Genesis accounts:"
    forM_ genesisAccounts (showAccount bkrTotalStake totalGTU)

    let UpdateKeysCollection{level2Keys = Authorizations{..}, ..} = genesisUpdateKeys
    putStrLn ""
    putStrLn "Root level update authorizations:"
    putStrLn $ " - "  ++ show (hlkThreshold rootKeys) ++ " of:"
    Vec.mapM_ (\k -> putStrLn $ "    " ++ show k) (hlkKeys rootKeys)
    putStrLn ""
    putStrLn "Level 1 update authorizations:"
    putStrLn $ " - "  ++ show (hlkThreshold level1Keys) ++ " of:"
    Vec.mapM_ (\k -> putStrLn $ "    " ++ show k) (hlkKeys level1Keys)
    putStrLn ""
    putStrLn "Level 2 update authorizations:"
    putStrLn "  - public keys:"
    Vec.imapM_ (\i k -> putStrLn $ "    " ++ show i ++ ": " ++ show k) asKeys
    printAccessStructure "emergency" asEmergency
    printAccessStructure "protocol" asProtocol
    printAccessStructure "election difficulty" asParamElectionDifficulty
    printAccessStructure "euro per energy" asParamEuroPerEnergy
    printAccessStructure "microGTU per euro" asParamMicroGTUPerEuro
    printAccessStructure "foundation account" asParamFoundationAccount
    printAccessStructure "mint distribution" asParamMintDistribution
    printAccessStructure "transaction fee distribution" asParamTransactionFeeDistribution
    printAccessStructure "gas reward parameters" asParamGASRewards
    printAccessStructure "baker stake threshold" asBakerStakeThreshold
    printAccessStructure "add anonymity revokers" asAddAnonymityRevoker
    printAccessStructure "add identity providers" asAddIdentityProvider

  where showBalance totalGTU balance =
            printf "%s (= %.4f%%)" (amountToString balance) (100 * (fromIntegral balance / fromIntegral totalGTU) :: Double)
        showAccount bkrTotalStake totalGTU GenesisAccount{..} = do
          putStrLn $ "  - " ++ show gaAddress
          putStrLn $ "     * balance: " ++ showBalance totalGTU gaBalance
          putStrLn $ "     * threshold: " ++ show (gaThreshold)
          putStrLn $ "     * credentials: "
          forM_ (OrdMap.toAscList gaCredentials) $ \(idx, k) ->
            putStrLn $ "       - " ++ show idx ++ ": " ++ showAsJSON (11 + length (show idx)) k
          forM_ gaBaker $ \GenesisBaker{..} -> do
            putStrLn $ "     * baker:"
            putStrLn $ "       + id: " ++ show gbBakerId
            putStrLn $ "       + stake: " ++ showBalance bkrTotalStake gbStake
            putStrLn $ "       + election key: " ++ show gbElectionVerifyKey
            putStrLn $ "       + signature key: " ++ show gbSignatureVerifyKey
            putStrLn $ "       + aggregation key: " ++ show gbAggregationVerifyKey
            putStrLn $ "       + earnings are " ++ (if gbRestakeEarnings then "" else "not ") ++ "restaked"
        -- Use the JSON instance and pretty print it, indenting everything but the first line by the stated amount.
        showAsJSON :: ToJSON a => Int -> a -> String
        showAsJSON indent v =
          let bs = encodePretty v
              offset = replicate indent ' '
              indentLine :: Int -> LBS8.ByteString -> LBS8.ByteString
              indentLine idx line = if idx > 0 then LBS8.pack offset <> line else line
          in LBS8.unpack . LBS8.unlines . zipWith indentLine [0..] $ (LBS8.lines bs)
        printAccessStructure n AccessStructure{..} = putStrLn $ "  - " ++ n ++ " update: " ++ show accessThreshold ++ " of " ++ show (toList accessPublicKeys)

        showExchangeRate (ExchangeRate r) = showRatio r

showTime :: Timestamp -> String
showTime t = formatTime defaultTimeLocale rfc822DateFormat (timestampToUTCTime t)

showRatio :: (Show a, Integral a) => Ratio a -> String
showRatio r =
  let num = numerator r
      den = denominator r
  in show num ++ " / " ++ show den ++ " (approx " ++ show (realToFrac r :: Double) ++ ")"

